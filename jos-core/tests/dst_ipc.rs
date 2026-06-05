//! Deterministic Simulation Testing of IPC message conservation.
//!
//! This drives the verified endpoint state machine (`jos_core::endpoint`) with
//! many concurrent senders and receivers contending capacity-1 endpoints under
//! a seeded schedule, and proves the property that matters for an IPC layer:
//! conservation. No message is ever lost, duplicated, or corrupted by the
//! endpoint. Every message that enters the send pipeline ends up received, in
//! an endpoint slot, or waiting in a sender's outbox, and nowhere else.
//!
//! It reuses the slice-2 fault regimes (`jos_core::fault::FaultConfig`) at the
//! message layer: under `Stormy` and `Apocalyptic`, sends are dropped, delayed,
//! duplicated, and corrupted before they reach an endpoint. The conservation
//! invariant is anchored on the *realized* stream (what actually entered the
//! pipeline after faults), exactly as the capability harness anchors its
//! differential oracle on the realized op stream: a dropped message is simply
//! never realized, a duplicate is realized twice, and a corrupted message is
//! realized in its corrupted form. So the endpoint must faithfully transport
//! whatever it is handed, which is precisely what conservation tests.
//!
//! An independent per-endpoint slot shadow cross-checks every deposit and take
//! (capacity-1 honored; a taken message equals the one deposited), and an
//! exhaustive end-of-run drain proves everything realized is eventually
//! received. The whole run is a pure function of `(seed, regime)`; reproduce a
//! failure with `DST_REGIME=stormy DST_SEED=<n> cargo test -p jos-core --test dst_ipc`.

use std::collections::BTreeMap;
use std::env;

use jos_core::endpoint::{Endpoint, Message, RecvOutcome, SendOutcome};
use jos_core::fault::FaultConfig;
use jos_core::rng::{KernelRng, SimRng};

// number of shared endpoints. small, so senders and receivers genuinely
// contend each one (capacity-1 forces parking and interleaving).
const E: usize = 3;

#[cfg(miri)]
const SEEDS: u64 = 2;
#[cfg(not(miri))]
const SEEDS: u64 = 96;

#[cfg(miri)]
const STEPS: usize = 40;
#[cfg(not(miri))]
const STEPS: usize = 600;

// how many fresh messages a run may generate before senders only drain.
#[cfg(miri)]
const BUDGET: usize = 12;
#[cfg(not(miri))]
const BUDGET: usize = 200;

// a multiset of message labels, used to compare what entered the pipeline
// against what came out.
type LabelBag = BTreeMap<u64, usize>;

fn bag_insert(bag: &mut LabelBag, label: u64) {
    *bag.entry(label).or_insert(0) += 1;
}

// a message awaiting delayed release: its target endpoint and steps remaining.
struct Delayed {
    message: Message,
    target: usize,
    remaining: u8,
}

// one recorded pipeline event, enough to prove two same-seed runs are identical.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ev {
    Realized { target: usize, label: u64 },
    Deposited { endpoint: usize, label: u64 },
    Received { endpoint: usize, label: u64 },
}

struct IpcSim {
    seed: u64,
    regime: &'static str,
    rng: SimRng,
    config: FaultConfig,

    // the systems under test: E verified endpoints.
    endpoints: [Endpoint; E],
    // an INDEPENDENT shadow of each endpoint's slot: what the harness believes
    // is parked there. cross-checked against every outcome (capacity-1 and
    // anti-corruption), and the source of the "in slots" conservation bucket.
    slot_shadow: [Option<Message>; E],
    // per-endpoint outbox: realized messages awaiting deposit (the "in flight at
    // a sender" bucket; a message lands here when a deposit returns Full).
    outbox: [Vec<Message>; E],
    // messages held back by the delay fault, not yet realized.
    delay_buf: Vec<Delayed>,

    next_label: u64,
    budget: usize,

    // conservation accounting. realized = entered the pipeline; received = came
    // out. the multisets prove per-label conservation; the scalars are an O(1)
    // per-step cross-check.
    realized: LabelBag,
    received: LabelBag,
    realized_total: usize,
    received_total: usize,

    log: Vec<Ev>,
}

impl IpcSim {
    fn new(seed: u64, config: FaultConfig, regime: &'static str) -> Self {
        Self {
            seed,
            regime,
            rng: SimRng::new(seed),
            config,
            endpoints: [Endpoint::new(); E],
            slot_shadow: [None; E],
            outbox: std::array::from_fn(|_| Vec::new()),
            delay_buf: Vec::new(),
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

    // records that `message` has entered the pipeline bound for endpoint
    // `target`: it joins the realized multiset and that endpoint's outbox. the
    // single place realized is incremented, so the accounting cannot drift.
    fn realize(&mut self, message: Message, target: usize) {
        bag_insert(&mut self.realized, message.label);
        self.realized_total += 1;
        self.outbox[target].push(message);
        self.log.push(Ev::Realized { target, label: message.label });
    }

    // matures the delay buffer by one step, realizing any message whose
    // countdown reached zero. called at the start of every step so a delayed
    // message is realized exactly when released, never lost.
    fn mature_delays(&mut self) {
        let mut due = Vec::new();
        let mut i = 0;
        while i < self.delay_buf.len() {
            self.delay_buf[i].remaining -= 1;
            if self.delay_buf[i].remaining == 0 {
                let d = self.delay_buf.swap_remove(i);
                due.push((d.message, d.target));
            } else {
                i += 1;
            }
        }
        for (message, target) in due {
            self.realize(message, target);
        }
    }

    // generates one fresh message for `target` and applies the message-layer
    // faults drawn from the regime config: drop (never realized), delay
    // (realized later), duplicate (realized twice), corrupt (realized mangled),
    // or normal (realized once).
    fn generate(&mut self, target: usize) {
        if self.budget == 0 {
            return;
        }
        self.budget -= 1;
        let label = self.next_label;
        self.next_label += 1;
        let message = Message::new(label, [label, label ^ 0xAAAA, label.wrapping_mul(3), 0]);

        let roll = self.rng.below(1000);
        let cfg = &self.config;
        let drop_to = u64::from(cfg.drop_ppm);
        let delay_to = drop_to + u64::from(cfg.delay_ppm);
        let dup_to = delay_to + u64::from(cfg.duplicate_ppm);
        let corrupt_to = dup_to + u64::from(cfg.corrupt_op_ppm);

        if roll < drop_to {
            // dropped: never enters the pipeline, so never realized.
        } else if roll < delay_to {
            let max = u64::from(cfg.max_delay_steps.max(1));
            #[allow(clippy::cast_possible_truncation)]
            let remaining = (1 + self.rng.below(max)) as u8;
            self.delay_buf.push(Delayed { message, target, remaining });
        } else if roll < dup_to {
            self.realize(message, target);
            self.realize(message, target);
        } else if roll < corrupt_to {
            let mangled = corrupt(message, &mut self.rng);
            self.realize(mangled, target);
        } else {
            self.realize(message, target);
        }
    }

    // tries to deposit the front of endpoint `e`'s outbox. on success the
    // message moves outbox -> slot; on Full it stays in the outbox (in flight)
    // and the sender parks. cross-checks the slot shadow against the endpoint.
    fn deposit(&mut self, e: usize) {
        let Some(&message) = self.outbox[e].first() else {
            return;
        };
        match self.endpoints[e].try_send(message) {
            SendOutcome::Deposited { .. } => {
                assert!(
                    self.slot_shadow[e].is_none(),
                    "{} seed={}: endpoint {e} accepted a deposit while the shadow slot was full",
                    self.regime, self.seed,
                );
                self.slot_shadow[e] = Some(message);
                self.outbox[e].remove(0);
                self.log.push(Ev::Deposited { endpoint: e, label: message.label });
            }
            SendOutcome::Full => {
                // the endpoint and the shadow must agree the slot is occupied.
                assert!(
                    self.slot_shadow[e].is_some(),
                    "{} seed={}: endpoint {e} refused a deposit while the shadow slot was empty",
                    self.regime, self.seed,
                );
                // a blocked sender parks; this never makes both peers parked.
                self.endpoints[e].park_sender();
            }
        }
        self.assert_endpoint_invariant(e);
    }

    // tries to take a message from endpoint `e`. on success it joins the
    // received multiset; the taken message must equal what the shadow says was
    // deposited (the anti-corruption / anti-fabrication check at the endpoint).
    fn recv(&mut self, e: usize) {
        match self.endpoints[e].try_recv() {
            RecvOutcome::Took { message, .. } => {
                assert_eq!(
                    Some(message), self.slot_shadow[e],
                    "{} seed={}: endpoint {e} returned a message different from the one deposited",
                    self.regime, self.seed,
                );
                self.slot_shadow[e] = None;
                bag_insert(&mut self.received, message.label);
                self.received_total += 1;
                self.log.push(Ev::Received { endpoint: e, label: message.label });
            }
            RecvOutcome::Empty => {
                assert!(
                    self.slot_shadow[e].is_none(),
                    "{} seed={}: endpoint {e} reported empty while the shadow slot was full",
                    self.regime, self.seed,
                );
                self.endpoints[e].park_receiver();
            }
        }
        self.assert_endpoint_invariant(e);
    }

    fn assert_endpoint_invariant(&self, e: usize) {
        let ep = &self.endpoints[e];
        assert!(
            !(ep.sender_parked() && ep.receiver_parked()),
            "{} seed={}: endpoint {e} has both a sender and a receiver parked",
            self.regime, self.seed,
        );
        // the slot shadow agrees with the endpoint's own loaded state.
        assert_eq!(
            ep.is_loaded(), self.slot_shadow[e].is_some(),
            "{} seed={}: endpoint {e} loaded state disagrees with the shadow",
            self.regime, self.seed,
        );
    }

    fn step(&mut self) {
        self.mature_delays();
        let e = self.random_endpoint();
        match self.rng.below(3) {
            0 => self.generate(e),
            1 => self.deposit(e),
            _ => self.recv(e),
        }
        self.check_conservation();
    }

    // the conservation invariant, checked after every step: the multiset of
    // realized labels equals received, plus those still in endpoint slots, plus
    // those waiting in outboxes. nothing is lost, duplicated, or corrupted.
    fn check_conservation(&self) {
        // scalar cross-check (O(1)): totals must balance.
        let in_slots = self.slot_shadow.iter().filter(|s| s.is_some()).count();
        let in_outboxes: usize = self.outbox.iter().map(Vec::len).sum();
        assert_eq!(
            self.realized_total,
            self.received_total + in_slots + in_outboxes,
            "{} seed={}: scalar conservation broken: realized={} received={} slots={in_slots} outboxes={in_outboxes}",
            self.regime, self.seed, self.realized_total, self.received_total,
        );

        // per-label multiset check: realized == received + slots + outboxes.
        let mut accounted = self.received.clone();
        for slot in self.slot_shadow.iter().flatten() {
            bag_insert(&mut accounted, slot.label);
        }
        for ob in &self.outbox {
            for m in ob {
                bag_insert(&mut accounted, m.label);
            }
        }
        assert_eq!(
            self.realized, accounted,
            "{} seed={}: per-label conservation broken",
            self.regime, self.seed,
        );
    }

    // drains every realized message to a receiver: force-mature all delays, then
    // alternately recv and deposit each endpoint until nothing moves. because
    // this is exhaustive and deterministic, afterwards EVERYTHING realized has
    // been received, the strongest conservation statement.
    fn drain(&mut self) {
        // force every delayed message into the pipeline.
        let pending: Vec<Delayed> = self.delay_buf.drain(..).collect();
        for d in pending {
            self.realize(d.message, d.target);
        }
        loop {
            let mut progress = false;
            for e in 0..E {
                if self.slot_shadow[e].is_some() {
                    self.recv(e);
                    progress = true;
                }
                if !self.outbox[e].is_empty() {
                    self.deposit(e);
                    progress = true;
                }
            }
            if !progress {
                break;
            }
        }
    }

    fn run(&mut self, steps: usize) {
        for _ in 0..steps {
            self.step();
        }
        self.drain();
        // capstone: a fully drained pipeline has delivered every realized
        // message exactly once, with nothing stuck in a slot or an outbox.
        self.check_conservation();
        assert_eq!(
            self.received_total, self.realized_total,
            "{} seed={}: {} of {} realized messages were never received after draining",
            self.regime, self.seed, self.received_total, self.realized_total,
        );
        assert_eq!(
            self.received, self.realized,
            "{} seed={}: the received multiset differs from the realized multiset after draining",
            self.regime, self.seed,
        );
        assert!(
            self.slot_shadow.iter().all(Option::is_none),
            "{} seed={}: a message was left in an endpoint slot after draining",
            self.regime, self.seed,
        );
    }
}

// mangles a message: flips label bits and perturbs the words. the corrupted
// message is what gets realized, so the harness expects the endpoint to
// transport it verbatim (corruption happens before the endpoint sees it).
fn corrupt(m: Message, rng: &mut impl KernelRng) -> Message {
    let label = m.label ^ (rng.next_u64() | 1); // | 1 guarantees a change
    Message::new(label, [m.words[0], m.words[1] ^ rng.next_u64(), m.words[2], m.words[3]])
}

// ---------------------------------------------------------------------------
// regime plumbing
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
        IpcSim::new(seed, config, regime).run(STEPS);
        return;
    }
    for seed in 0..SEEDS {
        IpcSim::new(seed, config, regime).run(STEPS);
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// ClearSky: no faults. Every generated message is realized exactly once, so
// after draining the received multiset equals the generated one.
#[test]
fn clear_sky_conserves_every_message() {
    if regime_selected("clear_sky") {
        sweep("clear_sky", FaultConfig::CLEAR_SKY);
    }
}

// Stormy: drops, delays, reorders, duplicates. Conservation holds on the
// realized stream (drops are never realized; duplicates are realized twice).
#[test]
fn stormy_conserves_the_realized_stream() {
    if regime_selected("stormy") {
        sweep("stormy", FaultConfig::STORMY);
    }
}

// Apocalyptic: adds corruption. The endpoint must transport each realized
// (possibly corrupted) message verbatim; a taken message always equals the
// deposited one, and the realized multiset is conserved.
#[test]
fn apocalyptic_conserves_under_corruption() {
    if regime_selected("apocalyptic") {
        sweep("apocalyptic", FaultConfig::APOCALYPTIC);
    }
}

// the harness is a pure function of (seed, regime): two runs log the identical
// pipeline. guards against accidental nondeterminism (e.g. iteration order).
#[test]
fn ipc_harness_is_deterministic() {
    let seeds = if cfg!(miri) { 2 } else { 24 };
    for regime in ["clear_sky", "stormy", "apocalyptic"] {
        if !regime_selected(regime) {
            continue;
        }
        let config = config_for(regime);
        for seed in 0..seeds {
            let mut a = IpcSim::new(seed, config, regime);
            let mut b = IpcSim::new(seed, config, regime);
            a.run(STEPS);
            b.run(STEPS);
            assert_eq!(a.log, b.log, "{regime} nondeterministic at seed {seed}");
        }
    }
}

// sanity: the regimes actually behave differently. under ClearSky every
// generated message is realized (no drops), so realized_total equals the number
// generated; under Stormy drops and delays make the realized count diverge from
// a fault-free run. guards against a vacuous (no-op) fault application.
#[test]
fn regimes_differ_in_realized_count() {
    if cfg!(miri) {
        return;
    }
    let mut clear = IpcSim::new(1, FaultConfig::CLEAR_SKY, "clear_sky");
    clear.run(STEPS);
    // ClearSky never drops, so everything generated is realized and received.
    let generated_clear = BUDGET - clear.budget;
    assert_eq!(
        clear.realized_total, generated_clear,
        "ClearSky realized count should equal the number generated",
    );

    let mut stormy = IpcSim::new(1, FaultConfig::STORMY, "stormy");
    stormy.run(STEPS);
    let generated_stormy = BUDGET - stormy.budget;
    // Stormy drops some sends, so fewer are realized than generated.
    assert!(
        stormy.realized_total < generated_stormy,
        "Stormy should drop some sends: realized {} of {} generated",
        stormy.realized_total, generated_stormy,
    );
}
