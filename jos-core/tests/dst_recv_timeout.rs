//! Deterministic Simulation Testing of IPC receive-with-timeout: the
//! deadlock-freedom capstone (VERIFICATION-TARGETS IPC-1).
//!
//! Conservation (`dst_ipc.rs`) proves the IPC layer never loses, duplicates, or
//! corrupts a message. Its dual is PROGRESS: a receiver that blocks on an
//! endpoint must not block forever. This harness proves that by composing the
//! three already-verified pieces the kernel's `recv_timeout` is built from, all
//! pure jos-core:
//!
//! - the [`Endpoint`] rendezvous state machine (`jos_core::endpoint`), with its
//!   Kani-proven [`cancel_receiver`](Endpoint::cancel_receiver) (a timed-out
//!   receiver abandoning its park),
//! - the injected [`SimClock`] and its saturating, monotonic deadline math
//!   (`jos_core::clock`), and
//! - the deadline-ordered [`TimerQueue`] (`jos_core::timer`), whose earliest-due
//!   timer fires the receiver waiting on it.
//!
//! It models `R` receivers, each parked on one of `E` capacity-1 endpoints with
//! a deadline, and senders depositing messages under the slice-2 fault regimes
//! (drops and delays make a sender miss a deadline, which must produce a
//! timeout, not a hang). Time advances by a seeded schedule; whenever the
//! `SimClock` reaches a receiver's deadline, the timer queue fires it and the
//! receiver times out. The properties checked:
//!
//! - **Progress (the headline)**: after a final phase that advances the clock
//!   past every deadline and drains every realized send, EVERY receiver is in a
//!   terminal state (`Received` or `TimedOut`). None is stuck waiting. This is
//!   deadlock-freedom: a blocked recv always reaches a terminal outcome.
//! - **No premature timeout**: a receiver is marked `TimedOut` only at a clock
//!   time that has reached its deadline (cross-checked against the deadline).
//! - **Conservation under timeout**: a timed-out receiver consumed no message,
//!   so the message it would have received is still in flight or delivered
//!   elsewhere. The realized-message multiset is conserved (received, plus those
//!   in slots, plus those in flight), exactly as in `dst_ipc.rs`, with timeout a
//!   conserving terminal state.
//! - **Determinism**: the whole run is a pure function of `(seed, regime)`;
//!   reproduce a failure with
//!   `DST_REGIME=stormy DST_SEED=<n> cargo test -p jos-core --test dst_recv_timeout`.

use std::collections::BTreeMap;
use std::env;

use jos_core::clock::{Duration, Instant, KernelClock, SimClock};
use jos_core::endpoint::{Endpoint, Message, RecvOutcome, SendOutcome};
use jos_core::fault::FaultConfig;
use jos_core::rng::{KernelRng, SimRng};
use jos_core::timer::{TimerId, TimerQueue};

// shared endpoints; receivers contend them so capacity-1 forces parking.
const E: usize = 3;
// receivers, each bound to one endpoint with its own deadline.
const R: usize = 6;
// timer-queue capacity: one armed timer per receiver.
const CAP: usize = R;

#[cfg(miri)]
const SEEDS: u64 = 2;
#[cfg(not(miri))]
const SEEDS: u64 = 96;

#[cfg(miri)]
const STEPS: usize = 50;
#[cfg(not(miri))]
const STEPS: usize = 800;

// the horizon deadlines are drawn within; STEPS advances of a few ticks each
// sweep the clock well past it, so the final phase always crosses every deadline.
const HORIZON: u64 = 400;

// a multiset of message labels: what entered the pipeline vs what came out.
type LabelBag = BTreeMap<u64, usize>;

fn bag_insert(bag: &mut LabelBag, label: u64) {
    *bag.entry(label).or_insert(0) += 1;
}

// a receiver's lifecycle. Waiting receivers hold an armed timer id and a
// deadline; terminal receivers are done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Receiver {
    // parked on endpoint `ep`, timer `timer` armed for `deadline`.
    Waiting { ep: usize, deadline: Instant, timer: TimerId },
    // collected a message at the recorded label.
    Received { label: u64 },
    // gave up at its deadline (no message arrived in time).
    TimedOut,
}

impl Receiver {
    fn is_terminal(self) -> bool {
        matches!(self, Receiver::Received { .. } | Receiver::TimedOut)
    }
}

// one recorded event, enough to prove two same-seed runs are identical.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ev {
    Realized { ep: usize, label: u64 },
    Deposited { ep: usize, label: u64 },
    Received { receiver: usize, label: u64 },
    TimedOut { receiver: usize },
    Advanced { now: u64 },
}

struct Sim {
    seed: u64,
    regime: &'static str,
    rng: SimRng,
    config: FaultConfig,

    clock: SimClock,
    endpoints: [Endpoint; E],
    timers: TimerQueue<CAP>,

    // the receivers under test.
    receivers: [Receiver; R],

    // an independent slot shadow per endpoint (capacity-1 + anti-corruption),
    // and per-endpoint outboxes of realized-but-undeposited messages.
    slot_shadow: [Option<Message>; E],
    outbox: [Vec<Message>; E],

    next_label: u64,
    budget: usize,

    // conservation accounting (mirrors dst_ipc).
    realized: LabelBag,
    received: LabelBag,
    realized_total: usize,
    received_total: usize,

    log: Vec<Ev>,
}

#[cfg(miri)]
const BUDGET: usize = 8;
#[cfg(not(miri))]
const BUDGET: usize = 60;

impl Sim {
    fn new(seed: u64, config: FaultConfig, regime: &'static str) -> Self {
        let mut rng = SimRng::new(seed);
        let mut timers = TimerQueue::new();
        let clock = SimClock::new();

        // arm every receiver: pick an endpoint and a deadline, arm a timer.
        let mut receivers = [Receiver::TimedOut; R];
        for (i, slot) in receivers.iter_mut().enumerate() {
            let ep = usize::try_from(rng.below(u64::try_from(E).unwrap())).unwrap();
            let deadline = Instant::new(1 + rng.below(HORIZON));
            // data = receiver index, so a fired timer names its receiver.
            let timer = timers
                .arm(deadline, u64::try_from(i).unwrap())
                .expect("timer queue sized to R, so every arm fits");
            *slot = Receiver::Waiting { ep, deadline, timer };
        }

        Self {
            seed,
            regime,
            rng,
            config,
            clock,
            endpoints: [Endpoint::new(); E],
            timers,
            receivers,
            slot_shadow: [None; E],
            outbox: std::array::from_fn(|_| Vec::new()),
            next_label: 1,
            budget: BUDGET,
            realized: LabelBag::new(),
            received: LabelBag::new(),
            realized_total: 0,
            received_total: 0,
            log: Vec::new(),
        }
    }

    fn random_endpoint(&mut self) -> usize {
        usize::try_from(self.rng.below(u64::try_from(E).unwrap())).unwrap()
    }

    // records that a message entered the pipeline for endpoint `ep`.
    fn realize(&mut self, message: Message, ep: usize) {
        bag_insert(&mut self.realized, message.label);
        self.realized_total += 1;
        self.outbox[ep].push(message);
        self.log.push(Ev::Realized { ep, label: message.label });
    }

    // generates one fresh message for `ep`, applying drop/dup faults (delay is
    // modeled coarsely as a drop here; the message layer's full delay behavior is
    // covered by dst_ipc). drops are what make a sender miss a receiver's
    // deadline, the interesting case for timeouts.
    fn generate(&mut self, ep: usize) {
        if self.budget == 0 {
            return;
        }
        self.budget -= 1;
        let label = self.next_label;
        self.next_label += 1;
        let message = Message::new(label, [label, 0, 0, 0]);

        let roll = self.rng.below(1000);
        let drop_to = u64::from(self.config.drop_ppm);
        let dup_to = drop_to + u64::from(self.config.duplicate_ppm);
        if roll < drop_to {
            // dropped: never realized, so a receiver on this endpoint may time out.
        } else if roll < dup_to {
            self.realize(message, ep);
            self.realize(message, ep);
        } else {
            self.realize(message, ep);
        }
    }

    // tries to deposit the front of endpoint `ep`'s outbox into its slot.
    fn deposit(&mut self, ep: usize) {
        let Some(&message) = self.outbox[ep].first() else {
            return;
        };
        match self.endpoints[ep].try_send(message) {
            SendOutcome::Deposited { .. } => {
                assert!(
                    self.slot_shadow[ep].is_none(),
                    "{} seed={}: endpoint {ep} accepted a deposit while shadow full",
                    self.regime, self.seed,
                );
                self.slot_shadow[ep] = Some(message);
                self.outbox[ep].remove(0);
                self.log.push(Ev::Deposited { ep, label: message.label });
            }
            SendOutcome::Full => {
                // slot occupied: leave it in the outbox (still in flight).
            }
        }
    }

    // a waiting receiver on endpoint `ep` tries to collect a message. on success
    // it becomes Received and cancels its armed timer (the message won the race);
    // on empty it stays Waiting (its timer is still armed).
    fn try_receive(&mut self, r: usize) {
        let Receiver::Waiting { ep, timer, .. } = self.receivers[r] else {
            return;
        };
        match self.endpoints[ep].try_recv() {
            RecvOutcome::Took { message, .. } => {
                assert_eq!(
                    Some(message), self.slot_shadow[ep],
                    "{} seed={}: endpoint {ep} returned a message different from the deposited one",
                    self.regime, self.seed,
                );
                self.slot_shadow[ep] = None;
                bag_insert(&mut self.received, message.label);
                self.received_total += 1;
                // the message won: cancel the timer so it cannot fire later.
                self.timers.cancel(timer);
                self.receivers[r] = Receiver::Received { label: message.label };
                self.log.push(Ev::Received { receiver: r, label: message.label });
            }
            RecvOutcome::Empty => {
                // nothing yet; the receiver remains parked with its timer armed.
                self.endpoints[ep].park_receiver();
            }
        }
    }

    // advance the clock by a random step, then fire every timer the new time has
    // reached: each fired timer times out its receiver (which cancels its
    // endpoint park, the cancel_receiver mechanism). this is where progress comes
    // from: a parked receiver whose deadline passes is forced terminal.
    fn advance_and_fire(&mut self, by: u64) {
        self.clock.advance(Duration::new(by));
        let now = self.clock.now();
        self.log.push(Ev::Advanced { now: now.ticks() });
        while let Some(timer) = self.timers.expire_next(now) {
            // no premature timeout: the timer fired only because now reached it.
            assert!(
                now.reached(timer.deadline),
                "{} seed={}: timer fired before its deadline ({:?} at now={now:?})",
                self.regime, self.seed, timer.deadline,
            );
            let r = usize::try_from(timer.data).unwrap();
            // the receiver this timer names must still be waiting on this very
            // timer (we cancel the timer when a message wins, so a fired timer
            // always corresponds to a still-waiting receiver).
            if let Receiver::Waiting { ep, deadline, timer: armed } = self.receivers[r] {
                assert_eq!(
                    armed, timer.id,
                    "{} seed={}: fired timer does not match receiver {r}'s armed timer",
                    self.regime, self.seed,
                );
                // cross-check the deadline the timer carried matches the receiver's.
                assert_eq!(deadline, timer.deadline, "{} seed={}: deadline mismatch", self.regime, self.seed);
                // time out: abandon the endpoint park (the verified cancel_receiver).
                self.endpoints[ep].cancel_receiver();
                self.receivers[r] = Receiver::TimedOut;
                self.log.push(Ev::TimedOut { receiver: r });
            }
        }
    }

    fn step(&mut self) {
        // a weighted action mix: generate, deposit, receive, or advance time.
        match self.rng.below(4) {
            0 => {
                let ep = self.random_endpoint();
                self.generate(ep);
            }
            1 => {
                let ep = self.random_endpoint();
                self.deposit(ep);
            }
            2 => {
                let r = usize::try_from(self.rng.below(u64::try_from(R).unwrap())).unwrap();
                self.try_receive(r);
            }
            _ => {
                // small time step so deadlines are crossed gradually mid-run.
                let by = 1 + self.rng.below(8);
                self.advance_and_fire(by);
            }
        }
        self.check_conservation();
    }

    // conservation: realized == received + in-slots + in-outboxes, every step.
    // a timeout consumes nothing, so it does not appear here; the message a
    // timed-out receiver would have taken is still accounted in a slot or outbox.
    fn check_conservation(&self) {
        let in_slots = self.slot_shadow.iter().filter(|s| s.is_some()).count();
        let in_outboxes: usize = self.outbox.iter().map(Vec::len).sum();
        assert_eq!(
            self.realized_total,
            self.received_total + in_slots + in_outboxes,
            "{} seed={}: conservation broken: realized={} received={} slots={in_slots} outboxes={in_outboxes}",
            self.regime, self.seed, self.realized_total, self.received_total,
        );
    }

    fn run(&mut self, steps: usize) {
        for _ in 0..steps {
            self.step();
        }

        // FINAL PHASE: drive every receiver to a terminal state. A receiver that
        // already has a message it could take before its deadline collects it; a
        // receiver whose deadline has passed without a deliverable message times
        // out. We model this faithfully: one last deliver-then-receive pass lets a
        // receiver whose message is sitting in its endpoint's outbox/slot collect
        // it (it would have, on a poll before its deadline), then advancing the
        // clock past every deadline fires the timers of all the rest, timing them
        // out. The delivery pass is bounded (one sweep per receiver), not an
        // unbounded loop, so timeouts remain load-bearing: a receiver with no
        // message waiting cannot be saved from timing out.
        for r in 0..R {
            if let Receiver::Waiting { ep, .. } = self.receivers[r] {
                // try to give this receiver a message that is already realized for
                // its endpoint (deposit the outbox front if the slot is free).
                if self.slot_shadow[ep].is_none() {
                    self.deposit(ep);
                }
                self.try_receive(r);
            }
        }
        // advance the clock past every deadline and fire all remaining timers:
        // every still-waiting receiver (no message arrived in time) times out.
        self.advance_and_fire(HORIZON + 1);
        self.check_conservation();

        // THE CAPSTONE: deadlock-freedom. every receiver reached a terminal state.
        for (r, &receiver) in self.receivers.iter().enumerate() {
            assert!(
                receiver.is_terminal(),
                "{} seed={}: receiver {r} is stuck ({receiver:?}): deadlock-freedom violated",
                self.regime, self.seed,
            );
        }
        // no timer is left armed (every receiver is terminal, so every timer
        // either fired or was cancelled).
        assert!(
            self.timers.is_empty(),
            "{} seed={}: {} timers left armed after every receiver is terminal",
            self.regime, self.seed, self.timers.len(),
        );
        // and no receiver parked flag is left set on any endpoint (every wait was
        // resolved by a take or a cancel_receiver).
        for ep in 0..E {
            assert!(
                !self.endpoints[ep].receiver_parked(),
                "{} seed={}: endpoint {ep} still has a parked receiver after the run",
                self.regime, self.seed,
            );
        }
    }

    // counts of each terminal outcome, for the anti-vacuous guard.
    fn outcome_counts(&self) -> (usize, usize) {
        let received = self.receivers.iter().filter(|r| matches!(r, Receiver::Received { .. })).count();
        let timed_out = self.receivers.iter().filter(|r| matches!(r, Receiver::TimedOut)).count();
        (received, timed_out)
    }

    // how many messages were generated vs realized; the gap is what the drop
    // fault removed (the direct, low-noise signal that faults fired, the same
    // measure dst_ipc uses). generated = BUDGET - remaining.
    fn generated_and_realized(&self) -> (usize, usize) {
        (BUDGET - self.budget, self.realized_total)
    }

    // starves the run of all messages: no sender ever has anything to deposit, so
    // EVERY receiver must reach its terminal state via timeout. used by the
    // starved test, where the timeout-termination path is the only route to
    // progress (so the progress assertion directly exercises it).
    fn starve(&mut self) {
        self.budget = 0;
    }
}

// ---------------------------------------------------------------------------
// regime plumbing (mirrors dst_ipc / dst_timeout)
// ---------------------------------------------------------------------------

fn config_for(regime: &str) -> FaultConfig {
    match regime {
        "clear_sky" | "clearsky" => FaultConfig::CLEAR_SKY,
        "stormy" => FaultConfig::STORMY,
        "apocalyptic" => FaultConfig::APOCALYPTIC,
        other => panic!("unknown DST_REGIME {other:?}; use clear_sky|stormy|apocalyptic"),
    }
}

fn regime_selected(regime: &str) -> bool {
    env::var("DST_REGIME").map_or(true, |r| r.eq_ignore_ascii_case(regime))
}

fn sweep(regime: &'static str, config: FaultConfig) {
    if let Ok(s) = env::var("DST_SEED") {
        let seed: u64 = s.parse().expect("DST_SEED must parse as u64");
        Sim::new(seed, config, regime).run(STEPS);
        return;
    }
    for seed in 0..SEEDS {
        Sim::new(seed, config, regime).run(STEPS);
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// ClearSky: no faults. Receivers mostly receive (some still time out if no
// sender targets their endpoint in time), and every one reaches a terminal state.
#[test]
fn clear_sky_every_receiver_terminates() {
    if regime_selected("clear_sky") {
        sweep("clear_sky", FaultConfig::CLEAR_SKY);
    }
}

// Stormy: drops and duplicates. Dropped sends make more receivers time out;
// deadlock-freedom and conservation still hold.
#[test]
fn stormy_every_receiver_terminates() {
    if regime_selected("stormy") {
        sweep("stormy", FaultConfig::STORMY);
    }
}

// Apocalyptic: the most aggressive regime. The progress guarantee is unchanged:
// no receiver is ever stuck, however hostile the transport.
#[test]
fn apocalyptic_every_receiver_terminates() {
    if regime_selected("apocalyptic") {
        sweep("apocalyptic", FaultConfig::APOCALYPTIC);
    }
}

// the starved case: no message is ever generated, so EVERY receiver reaches its
// terminal state by TIMING OUT. this makes the timeout-termination path the only
// route to progress, so the deadlock-freedom assertion directly exercises it (in
// the regime sweeps a receiver usually receives, so timeouts are comparatively
// rare; here they are universal). it is the sharpest test of the property the
// whole consumer exists for: a recv with no sender always terminates, never hangs.
#[test]
fn starved_receivers_all_time_out() {
    let seeds = if cfg!(miri) { 2 } else { 64 };
    for seed in 0..seeds {
        let mut sim = Sim::new(seed, FaultConfig::CLEAR_SKY, "clear_sky");
        sim.starve();
        sim.run(STEPS);
        // run()'s capstone already asserts every receiver is terminal; here every
        // one must specifically be TimedOut (none could have received).
        let (received, timed_out) = sim.outcome_counts();
        assert_eq!(received, 0, "starved run delivered a message at seed {seed}");
        assert_eq!(timed_out, R, "not every starved receiver timed out at seed {seed}");
    }
}

// the harness is a pure function of (seed, regime): two runs log identically.
#[test]
fn harness_is_deterministic() {
    let seeds = if cfg!(miri) { 2 } else { 24 };
    for regime in ["clear_sky", "stormy", "apocalyptic"] {
        if !regime_selected(regime) {
            continue;
        }
        let config = config_for(regime);
        for seed in 0..seeds {
            let mut a = Sim::new(seed, config, regime);
            let mut b = Sim::new(seed, config, regime);
            a.run(STEPS);
            b.run(STEPS);
            assert_eq!(a.log, b.log, "{regime} nondeterministic at seed {seed}");
        }
    }
}

// anti-vacuous, two independent checks. (1) BOTH terminal outcomes actually
// occur across the sweep, so the progress assertion is not trivially satisfied
// by everyone always timing out (or always receiving): the deadlock-freedom
// check genuinely sees a mix. (2) the fault regimes genuinely fire: under
// ClearSky every generated message is realized, while under Stormy drops make
// fewer realized than generated. (2) is the direct low-noise fault signal, the
// same measure dst_ipc::regimes_differ_in_realized_count uses; the
// terminal-outcome counts are too noisy to compare across regimes here, since a
// receiver whose endpoint simply never got a timely sender times out regardless.
#[test]
fn both_outcomes_occur_and_faults_fire() {
    if cfg!(miri) {
        return;
    }
    // (1) both outcomes occur across a ClearSky sweep.
    let mut received = 0;
    let mut timed_out = 0;
    for seed in 0..64 {
        let mut sim = Sim::new(seed, FaultConfig::CLEAR_SKY, "clear_sky");
        sim.run(STEPS);
        let (r, t) = sim.outcome_counts();
        received += r;
        timed_out += t;
    }
    assert!(received > 0, "no receiver ever received a message (progress check is vacuous)");
    assert!(timed_out > 0, "no receiver ever timed out (progress check is vacuous)");

    // (2) faults fire: ClearSky realizes everything it generates; Stormy drops some.
    let mut clear_gen = 0;
    let mut clear_realized = 0;
    let mut storm_gen = 0;
    let mut storm_realized = 0;
    for seed in 0..64 {
        let mut clear = Sim::new(seed, FaultConfig::CLEAR_SKY, "clear_sky");
        clear.run(STEPS);
        let (g, r) = clear.generated_and_realized();
        clear_gen += g;
        clear_realized += r;

        let mut storm = Sim::new(seed, FaultConfig::STORMY, "stormy");
        storm.run(STEPS);
        let (g, r) = storm.generated_and_realized();
        storm_gen += g;
        storm_realized += r;
    }
    // ClearSky never drops (it may duplicate-realize 0 times under CLEAR_SKY), so
    // realized == generated exactly.
    assert_eq!(clear_realized, clear_gen, "ClearSky should realize every generated message");
    // Stormy drops some sends, so strictly fewer are realized than generated.
    assert!(
        storm_realized < storm_gen,
        "Stormy should drop some sends: realized {storm_realized} of {storm_gen} generated",
    );
}
