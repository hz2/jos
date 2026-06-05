//! Deterministic Simulation Testing for the injected clock (Phase 3 seam).
//!
//! This is the determinism guard for [`jos_core::clock`], the time twin of the
//! `rng` seam: it proves the injected clock already enables time-driven
//! simulation before any consumer is built on it. Under a seeded schedule it
//! advances a [`SimClock`] by random steps (and occasionally jumps it with
//! `set`, including backward jumps that must be clamped), tracking a fixed set
//! of armed deadlines. The properties it checks each step are the ones a timeout
//! subsystem will rely on:
//!
//! - **Monotonicity**: `now` never decreases, however advances and sets are
//!   interleaved (a backward `set` is absorbed by the clock's monotonic guard).
//! - **Threshold correctness**: `now.reached(deadline)` agrees with an
//!   independent recomputation from the public tick counts at every step,
//!   including exactly at the boundary tick.
//! - **Flip exactly once iff crossed**: each deadline transitions from
//!   not-reached to reached at most once, only in the not-reached -> reached
//!   direction, and a deadline flips during the run precisely when the timeline
//!   started below it and ended at or past it.
//!
//! The whole run is a pure function of its seed, so any failure reproduces
//! exactly: re-run with `DST_SEED=<n> cargo test -p jos-core --test dst_clock`.
//! Counts shrink under Miri (which interprets every operation) so the UB-check
//! run stays tractable; the native run is a wider seed sweep.

use std::env;

use jos_core::clock::{Duration, Instant, KernelClock, SimClock};
use jos_core::rng::{KernelRng, SimRng};

// run sizes. Miri interprets every instruction, so it gets a tiny sweep; the
// native run is wide. STEPS is large enough that the timeline crosses most armed
// deadlines within a run.
#[cfg(miri)]
const SEEDS: u64 = 2;
#[cfg(not(miri))]
const SEEDS: u64 = 128;

#[cfg(miri)]
const STEPS: usize = 40;
#[cfg(not(miri))]
const STEPS: usize = 600;

// number of deadlines armed at the start of a run and tracked throughout. fixed
// across the run so the "flips exactly once" property is unambiguous.
const D: usize = 8;

// the largest single advance step, in ticks. the average advance is half this,
// so STEPS advances sweep the timeline across a range comfortably larger than
// HORIZON, ensuring most armed deadlines are crossed.
const MAX_STEP: u64 = 64;

// deadlines and set-targets are drawn from `[0, HORIZON)`. chosen so the native
// run (~600 steps * ~24 ticks each, minus the occasional set) reaches close to
// HORIZON: most deadlines fall within reach and flip, while a few near the top
// may not be crossed, so both the flip path and the never-crossed path are hit.
const HORIZON: u64 = 12_000;

// one recorded event, enough to prove two same-seed runs are identical.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ev {
    // the clock was advanced; `now` is the resulting time.
    Advanced { now: u64 },
    // a set was requested to `requested`; `now` is the resulting time (equal to
    // `requested` if it took effect, the prior time if it was clamped backward).
    Set { requested: u64, now: u64 },
    // a deadline crossed from not-reached to reached at time `at`.
    Flip { deadline: usize, at: u64 },
}

struct ClockSim {
    seed: u64,
    rng: SimRng,

    // the system under test.
    clock: SimClock,

    // armed deadlines, fixed for the run.
    deadlines: [Instant; D],
    // last-observed reached state of each deadline, the flip tracker.
    reached: [bool; D],
    // how many times each deadline flipped (must end 0 or 1).
    flips: [u32; D],

    // the time the clock started at, and the time at the previous step. used to
    // state the "flipped exactly when crossed" property precisely.
    start_now: Instant,
    prev_now: Instant,

    log: Vec<Ev>,
}

impl ClockSim {
    fn new(seed: u64) -> Self {
        let mut rng = SimRng::new(seed);
        // start at a small random offset so some deadlines fall below the start
        // (already reached at tick 0 of the run), exercising the init path as
        // well as the flip path.
        let start = rng.below(256);
        let clock = SimClock::at(start);
        let now = clock.now();

        // arm D deadlines scattered across the horizon.
        let mut deadlines = [Instant::ZERO; D];
        for slot in &mut deadlines {
            *slot = Instant::new(rng.below(HORIZON));
        }
        // a deadline at or below the start is already reached; seed the tracker
        // from the true starting relation so a never-crossed-because-already-met
        // deadline is not miscounted as a flip.
        let mut reached = [false; D];
        for (r, &dl) in reached.iter_mut().zip(deadlines.iter()) {
            *r = now.reached(dl);
        }

        Self {
            seed,
            rng,
            clock,
            deadlines,
            reached,
            flips: [0; D],
            start_now: now,
            prev_now: now,
            log: Vec::new(),
        }
    }

    fn step(&mut self) {
        // a quarter of steps jump the clock with `set` (often backward, so the
        // monotonic guard is exercised); the rest advance it forward.
        if self.rng.below(4) == 0 {
            let requested = self.rng.below(HORIZON);
            self.clock.set(Instant::new(requested));
            self.log.push(Ev::Set {
                requested,
                now: self.clock.now().ticks(),
            });
        } else {
            let by = self.rng.below(MAX_STEP);
            self.clock.advance(Duration::new(by));
            self.log.push(Ev::Advanced {
                now: self.clock.now().ticks(),
            });
        }
        self.check();
    }

    // the per-step invariant battery.
    fn check(&mut self) {
        let now = self.clock.now();

        // monotonicity: time never runs backward, however the op was sequenced.
        assert!(
            now >= self.prev_now,
            "seed={}: time went backward: {:?} -> {:?}",
            self.seed, self.prev_now, now,
        );

        for i in 0..D {
            let dl = self.deadlines[i];
            let is_reached = now.reached(dl);

            // threshold correctness: `reached` agrees with an independent
            // recomputation from the public tick counts, at and around the
            // boundary. catches a `>` / `>=` confusion or a reversed comparison.
            assert_eq!(
                is_reached,
                now.ticks() >= dl.ticks(),
                "seed={}: reached() disagrees with the tick comparison at now={:?} deadline={:?}",
                self.seed, now, dl,
            );

            if is_reached != self.reached[i] {
                // the only legal transition is not-reached -> reached.
                assert!(
                    is_reached,
                    "seed={}: deadline {i} ({dl:?}) became un-reached at now={now:?}",
                    self.seed,
                );
                // it flipped on the first step the timeline crossed it: the prior
                // time was strictly below the deadline, this time is at or past.
                assert!(
                    self.prev_now.ticks() < dl.ticks(),
                    "seed={}: deadline {i} flipped late: prev={:?} deadline={dl:?}",
                    self.seed, self.prev_now,
                );
                self.flips[i] += 1;
                self.log.push(Ev::Flip { deadline: i, at: now.ticks() });
                self.reached[i] = is_reached;
            }
        }

        self.prev_now = now;
    }

    fn run(&mut self, steps: usize) {
        for _ in 0..steps {
            self.step();
        }
        self.finish();
    }

    // the end-of-run capstone: every deadline flipped at most once, the tracked
    // reached state matches the final time, and a deadline flipped during the
    // run precisely when the timeline started below it and ended at or past it.
    fn finish(&self) {
        let now = self.clock.now();
        for i in 0..D {
            let dl = self.deadlines[i];

            assert!(
                self.flips[i] <= 1,
                "seed={}: deadline {i} flipped {} times (expected at most once)",
                self.seed, self.flips[i],
            );

            // the tracker matches reality at the end.
            assert_eq!(
                self.reached[i],
                now.ticks() >= dl.ticks(),
                "seed={}: final reached tracker for deadline {i} disagrees with the clock",
                self.seed,
            );

            // the precise statement of "flips exactly once iff crossed": a
            // deadline flips during the run iff it sat strictly above the start
            // and at or below the final time.
            let crossed = self.start_now.ticks() < dl.ticks() && dl.ticks() <= now.ticks();
            assert_eq!(
                self.flips[i] == 1,
                crossed,
                "seed={}: deadline {i} ({dl:?}) flip/cross mismatch: flips={} start={:?} now={now:?}",
                self.seed, self.flips[i], self.start_now,
            );
        }
    }

    // total flips across all deadlines this run (used by the anti-vacuous test).
    fn total_flips(&self) -> u32 {
        self.flips.iter().sum()
    }
}

// ---------------------------------------------------------------------------
// replay plumbing
// ---------------------------------------------------------------------------

fn sweep() {
    if let Ok(s) = env::var("DST_SEED") {
        let seed: u64 = s.parse().expect("DST_SEED must parse as u64");
        ClockSim::new(seed).run(STEPS);
        return;
    }
    for seed in 0..SEEDS {
        ClockSim::new(seed).run(STEPS);
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// the main sweep: monotonicity, threshold correctness, and flip-exactly-once
// hold for every seed.
#[test]
fn clock_invariants_hold_across_the_sweep() {
    sweep();
}

// the harness is a pure function of its seed: two runs log the identical
// timeline. guards against accidental nondeterminism.
#[test]
fn clock_harness_is_deterministic() {
    let seeds = if cfg!(miri) { 2 } else { 32 };
    for seed in 0..seeds {
        let mut a = ClockSim::new(seed);
        let mut b = ClockSim::new(seed);
        a.run(STEPS);
        b.run(STEPS);
        assert_eq!(a.log, b.log, "clock harness nondeterministic at seed {seed}");
    }
}

// anti-vacuous guard: the schedule actually moves the clock and actually crosses
// deadlines, so the flip-tracking path is genuinely exercised. without this, a
// clock that never advanced (a real bug) would satisfy every per-step assertion
// vacuously, since nothing would ever flip and monotonicity would hold trivially.
#[test]
fn the_schedule_crosses_some_deadlines() {
    let mut total_flips = 0u64;
    let mut max_now = 0u64;
    let seeds = if cfg!(miri) { 2 } else { 64 };
    for seed in 0..seeds {
        let mut sim = ClockSim::new(seed);
        sim.run(STEPS);
        total_flips += u64::from(sim.total_flips());
        max_now = max_now.max(sim.clock.now().ticks());
    }
    assert!(
        total_flips > 0,
        "no deadline ever flipped across {seeds} seeds: the schedule never crossed one (clock stuck?)",
    );
    assert!(
        max_now > 0,
        "the clock never advanced across {seeds} seeds",
    );
}

// a deadline guaranteed to be within reach always flips: a focused,
// schedule-independent check that the flip machinery fires (complements the
// statistical guard above). advancing well past a small deadline must reach it.
#[test]
fn a_reachable_deadline_always_flips() {
    let deadline = Instant::new(100);
    let mut clock = SimClock::new();
    assert!(!clock.now().reached(deadline), "reached before any time passed");
    // advance in steps that together pass the deadline.
    for _ in 0..20 {
        clock.advance(Duration::new(10));
    }
    assert!(
        clock.now().reached(deadline),
        "a deadline well within reach was not reached after advancing past it",
    );
}
