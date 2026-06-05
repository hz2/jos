//! Deterministic Simulation Testing for deadline-ordered wakeups.
//!
//! This drives the verified [`TimerQueue`] (`jos_core::timer`) under a seeded
//! schedule of arms, cancels, and clock advances, and checks it every step
//! against an *independently implemented* shadow model. It is the spec-as-oracle
//! pattern of [`dst_capspace`](../tests/dst_capspace.rs), now over time: the
//! shadow is a `BTreeMap<TimerId, (Instant, u64)>`, a different shape from the
//! queue's packed array (a sorted map with no swap-remove and no linear scan),
//! so a bug in the array implementation is unlikely to be mirrored by an
//! identical bug in the map, and a divergence between them is a real defect.
//!
//! The injected [`SimClock`] is what makes this a *time-driven* DST, the first
//! consumer of the clock seam: the harness owns the timeline and advances it by
//! hand, so every expiry is a pure function of the schedule. The properties
//! checked, per step and at end of run:
//!
//! - **Conservation**: every armed timer is eventually either cancelled or
//!   fired, exactly once; none is lost, duplicated, or fired without being due.
//! - **No early fire**: a timer fires only at a clock time that has reached its
//!   deadline (cross-checked against the shadow's own deadline).
//! - **Earliest-first / non-decreasing**: draining yields timers in
//!   non-decreasing deadline order, and the fired timer is the one the shadow
//!   independently computes as earliest (ties broken identically by id).
//! - **Liveness**: after the clock advances to or past a deadline, draining
//!   fires every due timer, so nothing due is ever left behind.
//!
//! It reuses the fault-regime idea at the schedule layer via two presets (`Calm`
//! and `Turbulent`) that vary how aggressively timers are armed, cancelled, and
//! how far the clock jumps, so the queue is exercised both lightly loaded and at
//! capacity with heavy churn. The whole run is a pure function of `(seed,
//! regime)`; reproduce a failure with
//! `DST_REGIME=turbulent DST_SEED=<n> cargo test -p jos-core --test dst_timeout`.

use std::collections::BTreeMap;
use std::env;

use jos_core::clock::{Duration, Instant, KernelClock, SimClock};
use jos_core::rng::{KernelRng, SimRng};
use jos_core::timer::{TimerId, TimerQueue};

// capacity of the simulated queue. small, so the full / churn paths are hit
// often, but large enough that several timers coexist and contend the
// earliest-first ordering.
const CAP: usize = 8;

#[cfg(miri)]
const SEEDS: u64 = 2;
#[cfg(not(miri))]
const SEEDS: u64 = 96;

#[cfg(miri)]
const STEPS: usize = 40;
#[cfg(not(miri))]
const STEPS: usize = 600;

// how many timers a run may arm before arming stops and the run only drains.
// larger than CAP * a few so the queue fills and churns many times over.
#[cfg(miri)]
const BUDGET: usize = 12;
#[cfg(not(miri))]
const BUDGET: usize = 240;

// deadlines are drawn as an offset in [0, MAX_AHEAD) from the current time, so
// some are already due when armed (offset 0) and some are well in the future.
const MAX_AHEAD: u64 = 200;

// the schedule regime: how the workload is shaped. the queue is the same
// verified code under both; the regime only changes the seeded action mix.
#[derive(Clone, Copy)]
struct Regime {
    name: &'static str,
    // per-1000 weight of each action; the remainder is "advance the clock".
    arm_ppm: u64,
    cancel_ppm: u64,
    // the largest single clock advance, in ticks. bigger jumps fire more timers
    // per drain (and stress liveness); smaller jumps fire them gradually.
    max_step: u64,
}

impl Regime {
    // light load: arming dominates over cancel, the clock creeps forward in
    // small steps, so timers fire gradually and the queue rarely fills.
    const CALM: Self = Self {
        name: "calm",
        arm_ppm: 500,
        cancel_ppm: 100,
        max_step: 8,
    };

    // heavy churn: frequent arms AND cancels, and large clock jumps that fire
    // many timers at once, so the queue repeatedly fills, churns, and drains in
    // bursts. exercises swap-remove, capacity refusal, and burst liveness.
    const TURBULENT: Self = Self {
        name: "turbulent",
        arm_ppm: 550,
        cancel_ppm: 300,
        max_step: 80,
    };
}

// one recorded event, enough to prove two same-seed runs are identical.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ev {
    Armed { id: u64, deadline: u64, data: u64 },
    ArmRefused { deadline: u64 },
    Cancelled { id: u64 },
    CancelMissed { id: u64 },
    Advanced { now: u64 },
    Fired { id: u64, deadline: u64, data: u64 },
}

struct TimeoutSim {
    seed: u64,
    regime: Regime,
    rng: SimRng,

    // the system under test and the injected clock that drives it.
    queue: TimerQueue<CAP>,
    clock: SimClock,

    // the INDEPENDENT shadow: a sorted map of live timers by id, carrying each
    // timer's deadline and payload. different shape from the packed array, so a
    // divergence is a real bug. the source of the earliest-first cross-check and
    // the conservation buckets.
    shadow: BTreeMap<u64, (Instant, u64)>,

    // conservation accounting, keyed by the payload (unique per armed timer).
    // armed = entered; fired + cancelled + still-live must equal armed, always.
    armed_total: usize,
    fired_total: usize,
    cancelled_total: usize,

    // the deadline of the most recently fired timer, to assert the global drain
    // order is non-decreasing across the whole run, not just within one drain.
    last_fired_deadline: Option<Instant>,

    budget: usize,
    // a monotone payload tag, so every armed timer is uniquely identifiable in
    // the conservation accounting regardless of id reuse semantics.
    next_data: u64,

    log: Vec<Ev>,
}

impl TimeoutSim {
    fn new(seed: u64, regime: Regime) -> Self {
        Self {
            seed,
            regime,
            rng: SimRng::new(seed),
            queue: TimerQueue::new(),
            clock: SimClock::new(),
            shadow: BTreeMap::new(),
            armed_total: 0,
            fired_total: 0,
            cancelled_total: 0,
            last_fired_deadline: None,
            budget: BUDGET,
            next_data: 1,
            log: Vec::new(),
        }
    }

    // the independent earliest computation: the live timer with the smallest
    // (deadline, id), the same total order the queue uses. None when empty.
    fn shadow_earliest(&self) -> Option<(u64, Instant, u64)> {
        self.shadow
            .iter()
            .map(|(&id, &(deadline, data))| (deadline, id, data))
            .min()
            .map(|(deadline, id, data)| (id, deadline, data))
    }

    fn arm(&mut self) {
        if self.budget == 0 {
            return;
        }
        let ahead = self.rng.below(MAX_AHEAD);
        let deadline = self.clock.now().saturating_add(Duration::new(ahead));
        let data = self.next_data;

        match self.queue.arm(deadline, data) {
            Some(id) => {
                self.budget -= 1;
                self.next_data += 1;
                self.armed_total += 1;
                // the shadow must not already know this id (ids are unique).
                assert!(
                    self.shadow.insert(id.0, (deadline, data)).is_none(),
                    "{} seed={}: queue reissued a live TimerId {}",
                    self.regime.name, self.seed, id.0,
                );
                self.log.push(Ev::Armed { id: id.0, deadline: deadline.ticks(), data });
            }
            None => {
                // a refusal must mean the queue is genuinely full, and the shadow
                // agrees on fullness. no budget or data is consumed.
                assert!(
                    self.queue.is_full() && self.shadow.len() == CAP,
                    "{} seed={}: arm refused but queue not full (len {} shadow {})",
                    self.regime.name, self.seed, self.queue.len(), self.shadow.len(),
                );
                self.log.push(Ev::ArmRefused { deadline: deadline.ticks() });
            }
        }
        self.check_consistency();
    }

    fn cancel(&mut self) {
        // pick a target id: usually a live one (so cancels mostly hit), but
        // sometimes a likely-absent one (so the no-op path is exercised too).
        let target = self.pick_cancel_target();
        let removed = self.queue.cancel(TimerId(target));
        let in_shadow = self.shadow.remove(&target).is_some();
        // the queue and the independent shadow must agree on whether the id was
        // present: a divergence is a real bug.
        assert_eq!(
            removed, in_shadow,
            "{} seed={}: cancel({target}) queue={removed} shadow={in_shadow} disagree",
            self.regime.name, self.seed,
        );
        if removed {
            self.cancelled_total += 1;
            self.log.push(Ev::Cancelled { id: target });
        } else {
            self.log.push(Ev::CancelMissed { id: target });
        }
        self.check_consistency();
    }

    fn pick_cancel_target(&mut self) -> u64 {
        // 3/4 of the time aim at a live id (drawn from the shadow by index); the
        // rest aim at an arbitrary id, usually absent.
        if !self.shadow.is_empty() && self.rng.below(4) != 0 {
            let n = u64::try_from(self.shadow.len()).unwrap();
            let pick = usize::try_from(self.rng.below(n)).unwrap();
            *self.shadow.keys().nth(pick).expect("pick < shadow.len()")
        } else {
            self.rng.below(self.next_data + 4)
        }
    }

    fn advance(&mut self) {
        let by = self.rng.below(self.regime.max_step);
        self.clock.advance(Duration::new(by));
        self.log.push(Ev::Advanced { now: self.clock.now().ticks() });
        self.drain_due();
        self.check_consistency();
    }

    // fire every timer that is due at the current time, checking each fire
    // against the shadow. this is the liveness step: after it, NO due timer
    // remains (asserted by liveness_holds).
    fn drain_due(&mut self) {
        let now = self.clock.now();
        while let Some(fired) = self.queue.expire_next(now) {
            // no early fire: the clock has reached the fired deadline.
            assert!(
                now.reached(fired.deadline),
                "{} seed={}: fired a timer (deadline {:?}) before it was due at now={now:?}",
                self.regime.name, self.seed, fired.deadline,
            );

            // earliest-first: the shadow independently names the same timer as
            // the earliest live one (id, deadline, and payload all agree).
            let (eid, edl, edata) = self.shadow_earliest().unwrap_or_else(|| {
                panic!(
                    "{} seed={}: queue fired id {} but the shadow is empty",
                    self.regime.name, self.seed, fired.id.0,
                )
            });
            assert_eq!(
                (fired.id.0, fired.deadline, fired.data),
                (eid, edl, edata),
                "{} seed={}: fired timer disagrees with the shadow's earliest",
                self.regime.name, self.seed,
            );

            // global non-decreasing drain order across the whole run.
            if let Some(prev) = self.last_fired_deadline {
                assert!(
                    fired.deadline >= prev,
                    "{} seed={}: drain order regressed: {:?} after {:?}",
                    self.regime.name, self.seed, fired.deadline, prev,
                );
            }
            self.last_fired_deadline = Some(fired.deadline);

            // the payload round-trips uncorrupted (the shadow stored it at arm).
            self.shadow.remove(&fired.id.0);
            self.fired_total += 1;
            self.log.push(Ev::Fired {
                id: fired.id.0,
                deadline: fired.deadline.ticks(),
                data: fired.data,
            });
        }
        self.liveness_holds(now);
    }

    // after a drain, nothing due remains: the queue's earliest (if any) is
    // strictly in the future. this is the liveness property, the converse of
    // no-early-fire.
    fn liveness_holds(&self, now: Instant) {
        if let Some(next) = self.queue.next_deadline() {
            assert!(
                !now.reached(next),
                "{} seed={}: a due timer (deadline {next:?}) survived the drain at now={now:?}",
                self.regime.name, self.seed,
            );
        }
    }

    // per-step structural agreement between the queue and the shadow, plus the
    // running conservation identity.
    fn check_consistency(&self) {
        // same population.
        assert_eq!(
            self.queue.len(), self.shadow.len(),
            "{} seed={}: queue len {} != shadow len {}",
            self.regime.name, self.seed, self.queue.len(), self.shadow.len(),
        );
        // the queue's live set equals the shadow's, timer for timer (id ->
        // deadline+payload). catches a dropped, duplicated, or mutated entry.
        for t in self.queue.iter() {
            let &(deadline, data) = self.shadow.get(&t.id.0).unwrap_or_else(|| {
                panic!(
                    "{} seed={}: queue holds id {} the shadow does not",
                    self.regime.name, self.seed, t.id.0,
                )
            });
            assert_eq!(
                (t.deadline, t.data), (deadline, data),
                "{} seed={}: queue/shadow disagree on timer {}",
                self.regime.name, self.seed, t.id.0,
            );
        }
        // the queue's idea of the next deadline matches the shadow's earliest.
        assert_eq!(
            self.queue.next_deadline(),
            self.shadow_earliest().map(|(_, dl, _)| dl),
            "{} seed={}: next_deadline disagrees with the shadow earliest",
            self.regime.name, self.seed,
        );
        // conservation: armed == fired + cancelled + still live, every step.
        assert_eq!(
            self.armed_total,
            self.fired_total + self.cancelled_total + self.queue.len(),
            "{} seed={}: conservation broken: armed={} fired={} cancelled={} live={}",
            self.regime.name, self.seed,
            self.armed_total, self.fired_total, self.cancelled_total, self.queue.len(),
        );
    }

    fn step(&mut self) {
        let roll = self.rng.below(1000);
        if roll < self.regime.arm_ppm {
            self.arm();
        } else if roll < self.regime.arm_ppm + self.regime.cancel_ppm {
            self.cancel();
        } else {
            self.advance();
        }
    }

    // drives the schedule, then jumps the clock to the end of time and drains:
    // afterwards every armed timer has been fired or cancelled, the strongest
    // conservation statement.
    fn run(&mut self, steps: usize) {
        for _ in 0..steps {
            self.step();
        }
        // jump past every possible deadline and drain everything left.
        self.clock.set(Instant::new(u64::MAX));
        self.drain_due();

        // capstone: the queue is empty and fully accounted for.
        assert!(
            self.queue.is_empty() && self.shadow.is_empty(),
            "{} seed={}: {} timers left after final drain",
            self.regime.name, self.seed, self.queue.len(),
        );
        assert_eq!(
            self.armed_total,
            self.fired_total + self.cancelled_total,
            "{} seed={}: {} armed != {} fired + {} cancelled after draining",
            self.regime.name, self.seed,
            self.armed_total, self.fired_total, self.cancelled_total,
        );
    }
}

// ---------------------------------------------------------------------------
// regime plumbing
// ---------------------------------------------------------------------------

fn regime_for(name: &str) -> Regime {
    match name {
        "calm" => Regime::CALM,
        "turbulent" => Regime::TURBULENT,
        other => panic!("unknown DST_REGIME {other:?}; use calm|turbulent"),
    }
}

fn regime_selected(name: &str) -> bool {
    env::var("DST_REGIME").map_or(true, |r| r.eq_ignore_ascii_case(name))
}

fn sweep(regime: Regime) {
    if let Ok(s) = env::var("DST_SEED") {
        let seed: u64 = s.parse().expect("DST_SEED must parse as u64");
        // when replaying a single seed, honor an explicit DST_REGIME name so the
        // failing (seed, regime) pair reproduces exactly; otherwise replay the
        // regime of the test that called in.
        let replay = env::var("DST_REGIME").map_or(regime, |r| regime_for(&r));
        TimeoutSim::new(seed, replay).run(STEPS);
        return;
    }
    for seed in 0..SEEDS {
        TimeoutSim::new(seed, regime).run(STEPS);
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// Calm: light load, small clock steps. Timers fire gradually; conservation,
// ordering, and liveness hold across the sweep.
#[test]
fn calm_conserves_and_orders() {
    if regime_selected("calm") {
        sweep(Regime::CALM);
    }
}

// Turbulent: heavy arm/cancel churn and large clock jumps, so the queue
// repeatedly fills and drains in bursts. The same invariants must hold.
#[test]
fn turbulent_conserves_and_orders() {
    if regime_selected("turbulent") {
        sweep(Regime::TURBULENT);
    }
}

// the harness is a pure function of (seed, regime): two runs log the identical
// timeline. guards against accidental nondeterminism (e.g. relying on the
// queue's storage order, which swap-remove scrambles).
#[test]
fn timeout_harness_is_deterministic() {
    let seeds = if cfg!(miri) { 2 } else { 24 };
    for regime in [Regime::CALM, Regime::TURBULENT] {
        if !regime_selected(regime.name) {
            continue;
        }
        for seed in 0..seeds {
            let mut a = TimeoutSim::new(seed, regime);
            let mut b = TimeoutSim::new(seed, regime);
            a.run(STEPS);
            b.run(STEPS);
            assert_eq!(a.log, b.log, "{} nondeterministic at seed {seed}", regime.name);
        }
    }
}

// anti-vacuous guard: the schedule genuinely fills the queue to capacity (so the
// arm-refusal path fires), genuinely fires timers, and genuinely cancels some.
// without this, a queue that silently dropped every arm would pass the
// conservation identity vacuously (armed stays 0).
#[test]
fn the_schedule_exercises_every_path() {
    if cfg!(miri) {
        return;
    }
    let mut total_fired = 0usize;
    let mut total_cancelled = 0usize;
    let mut total_armed = 0usize;
    let mut saw_full = false;
    for seed in 0..64 {
        // instrument a turbulent run: it churns hardest, so it should hit
        // capacity and exercise every action.
        let mut sim = TimeoutSim::new(seed, Regime::TURBULENT);
        for _ in 0..STEPS {
            sim.step();
            if sim.queue.is_full() {
                saw_full = true;
            }
        }
        sim.clock.set(Instant::new(u64::MAX));
        sim.drain_due();
        total_fired += sim.fired_total;
        total_cancelled += sim.cancelled_total;
        total_armed += sim.armed_total;
    }
    assert!(total_armed > 0, "no timer was ever armed across the sweep");
    assert!(total_fired > 0, "no timer ever fired across the sweep");
    assert!(total_cancelled > 0, "no timer was ever cancelled across the sweep");
    assert!(saw_full, "the queue never reached capacity, so arm-refusal was never tested");
}
