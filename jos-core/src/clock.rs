//! Monotonic time behind a HAL trait, with verifiable deadline arithmetic.
//!
//! This is the injected-time seam the VISION's deterministic-simulation pillar
//! requires (north star 5: a deterministic core with all time, randomness, and
//! I/O injected behind traits). It is the twin of [`crate::rng`]: where that
//! injects randomness, this injects time. The kernel core never reads a real
//! clock; it takes a [`KernelClock`] and is handed either a real hardware clock
//! (a later kernel-side impl over the timer IRQ or the TSC) or the deterministic
//! [`SimClock`] the simulation drives by hand, the same shape as Tokio's
//! `time::pause()` plus `advance()`. Same schedule, same timeline, every run, so
//! a timing-dependent failure found under simulation reproduces exactly.
//!
//! # Invariant
//!
//! - A [`SimClock`]'s time is monotonic non-decreasing: [`advance`](SimClock::advance)
//!   saturates rather than wrapping, and [`set`](SimClock::set) clamps a backward
//!   move, so [`now`](KernelClock::now) never returns a smaller [`Instant`] than a
//!   previous call (`advance_is_monotone`, `set_is_monotone`).
//! - A deadline is never computed in the past: for any base instant and span,
//!   [`Instant::saturating_add`] yields an instant at or after the base, so a
//!   deadline never wraps around to fire immediately (`deadline_never_in_the_past`).
//! - [`Instant::reached`] is the threshold "at or after", and it is monotone in
//!   the current time: once an instant has reached a deadline, every later
//!   instant has too (`reached_is_monotone_in_now`).
//!
//! These obligations are discharged by the `#[cfg(kani)]` harnesses at the
//! bottom of this file. The deadline arithmetic ([`Instant::saturating_add`] and
//! [`Instant::reached`]) is factored as pure `const fn`s, the same way
//! [`crate::rng::map_below`] is, so the proofs are over straight-line integer
//! add and compare with no clock state involved. There is deliberately no
//! tautological "the simulated clock is deterministic" proof: a hand-advanced
//! counter is deterministic by language guarantee, exactly as
//! [`crate::rng::SimRng`]'s stream is, so determinism is covered by the
//! `dst_clock` harness rather than a vacuous proof.

// ---------------------------------------------------------------------------
// Instant and Duration
// ---------------------------------------------------------------------------

/// A monotonic point in time, in abstract ticks.
///
/// What a tick is (TSC cycles, a timer-interrupt count, nanoseconds) is the real
/// clock's choice; the core only needs monotonicity and comparison, so an
/// `Instant` is an opaque `u64` counter. It derives `Ord`, so instants compare
/// directly, and [`reached`](Self::reached) names the "at or after" test the
/// deadline logic reads on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);

impl Instant {
    /// The earliest representable instant, tick `0`. A fresh [`SimClock`] starts
    /// here.
    pub const ZERO: Self = Self(0);

    /// Creates an instant at `ticks`.
    #[inline]
    #[must_use]
    pub const fn new(ticks: u64) -> Self {
        Self(ticks)
    }

    /// Returns this instant's raw tick count.
    #[inline]
    #[must_use]
    pub const fn ticks(self) -> u64 {
        self.0
    }

    /// Returns the instant `d` ticks after this one, saturating at the maximum.
    ///
    /// Saturating is the load-bearing choice: a deadline computed as `now + d`
    /// must never wrap around `u64::MAX` back to a small value, because a wrapped
    /// deadline would lie in the past and fire immediately, a real timeout-bug
    /// class. With saturation the worst case is a deadline pinned at the end of
    /// time, which simply never fires, the safe direction. (jos builds with
    /// `overflow-checks = true`, so a plain `+` here would panic on overflow
    /// rather than wrap; saturation is both panic-free and correct.)
    #[inline]
    #[must_use]
    pub const fn saturating_add(self, d: Duration) -> Instant {
        Instant(self.0.saturating_add(d.0))
    }

    /// Returns `true` once this instant is at or after `deadline`.
    ///
    /// Read as "has the current time reached the deadline?": `now.reached(dl)`.
    /// It is exactly `self >= deadline` on the tick counts, the threshold a
    /// timeout fires on.
    #[inline]
    #[must_use]
    pub const fn reached(self, deadline: Instant) -> bool {
        self.0 >= deadline.0
    }
}

/// A span of time, in the same abstract ticks as [`Instant`].
///
/// A `Duration` is added to an [`Instant`] to compute a deadline (see
/// [`Instant::saturating_add`]) and is how much a [`SimClock`] moves under
/// [`advance`](SimClock::advance).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration(u64);

impl Duration {
    /// A zero-length span; advancing by it leaves the clock unchanged.
    pub const ZERO: Self = Self(0);

    /// Creates a span of `ticks` ticks.
    #[inline]
    #[must_use]
    pub const fn new(ticks: u64) -> Self {
        Self(ticks)
    }

    /// Returns this span's raw tick count.
    #[inline]
    #[must_use]
    pub const fn ticks(self) -> u64 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// KernelClock trait
// ---------------------------------------------------------------------------

/// A source of monotonic time.
///
/// The one required method is [`now`](KernelClock::now). This is the HAL
/// boundary for time: hardware-backed in production (a timer-interrupt count or
/// the TSC, a later kernel-side impl), [`SimClock`] under deterministic
/// simulation. It is deliberately not sealed, so a real clock can implement it
/// later without changing this crate, mirroring [`crate::rng::KernelRng`].
pub trait KernelClock {
    /// Returns the current time.
    ///
    /// Must be monotonic non-decreasing across calls: a later call never returns
    /// a smaller [`Instant`] than an earlier one. [`SimClock`] upholds this by
    /// construction (see the module invariant); a hardware impl must choose a
    /// monotonic source (the TSC on modern parts, or a free-running tick count).
    #[must_use]
    fn now(&self) -> Instant;
}

// ---------------------------------------------------------------------------
// SimClock
// ---------------------------------------------------------------------------

/// A deterministic simulated clock: time advances only when told to.
///
/// This is the simulated counterpart to a future hardware clock behind the same
/// [`KernelClock`] trait, exactly as [`SimRng`](crate::rng::SimRng) is the
/// simulated counterpart to a hardware RNG. The simulation holds one and drives
/// the timeline by hand with [`advance`](Self::advance) and [`set`](Self::set),
/// so every timeout and deadline in a run is a pure function of the schedule the
/// harness chose.
///
/// Not `Copy`: a clock is the single source of truth for the current time, and
/// an accidental copy (advancing the copy while the original lags) would
/// silently desynchronize the timeline. Clone it explicitly when a snapshot of
/// the current time is genuinely intended.
#[derive(Clone, Debug)]
pub struct SimClock {
    now: Instant,
}

impl SimClock {
    /// Creates a clock started at [`Instant::ZERO`].
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self { now: Instant::ZERO }
    }

    /// Creates a clock started at tick `start`.
    #[inline]
    #[must_use]
    pub const fn at(start: u64) -> Self {
        Self {
            now: Instant::new(start),
        }
    }

    /// Advances the clock by `by`, saturating at the maximum instant.
    ///
    /// Saturating (via [`Instant::saturating_add`]) keeps time monotonic even at
    /// the end of the representable range: advancing past `u64::MAX` pins the
    /// clock at the maximum rather than wrapping back to zero.
    #[inline]
    pub fn advance(&mut self, by: Duration) {
        self.now = self.now.saturating_add(by);
    }

    /// Sets the clock to `t`, but never backward.
    ///
    /// A `t` at or before the current time is ignored (the clock is clamped to
    /// its current value), so `now` never decreases however the caller sequences
    /// its calls. This is the monotonic guard the module invariant rests on; a
    /// hardware clock would uphold the same property by reading a monotonic
    /// counter.
    #[inline]
    pub fn set(&mut self, t: Instant) {
        if t > self.now {
            self.now = t;
        }
    }
}

impl Default for SimClock {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelClock for SimClock {
    #[inline]
    fn now(&self) -> Instant {
        self.now
    }
}

// ---------------------------------------------------------------------------
// unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{Duration, Instant, KernelClock, SimClock};

    #[test]
    fn fresh_clock_starts_at_zero() {
        let clock = SimClock::new();
        assert_eq!(clock.now(), Instant::ZERO);
        assert_eq!(clock.now().ticks(), 0);
    }

    #[test]
    fn at_starts_at_the_given_tick() {
        let clock = SimClock::at(1000);
        assert_eq!(clock.now(), Instant::new(1000));
    }

    #[test]
    fn advance_accumulates() {
        let mut clock = SimClock::new();
        clock.advance(Duration::new(10));
        clock.advance(Duration::new(5));
        clock.advance(Duration::new(100));
        // the three spans sum: a clock advanced repeatedly tracks the total.
        assert_eq!(clock.now(), Instant::new(115));
    }

    #[test]
    fn advance_by_zero_is_a_noop() {
        let mut clock = SimClock::at(42);
        clock.advance(Duration::ZERO);
        assert_eq!(clock.now(), Instant::new(42));
    }

    #[test]
    fn advance_saturates_at_the_maximum() {
        // advancing past the end of time pins the clock at the maximum rather
        // than wrapping back to a small value (which would be time travel, and
        // under overflow-checks would instead panic).
        let mut clock = SimClock::at(u64::MAX - 3);
        clock.advance(Duration::new(100));
        assert_eq!(clock.now(), Instant::new(u64::MAX));
    }

    #[test]
    fn set_moves_the_clock_forward() {
        let mut clock = SimClock::new();
        clock.set(Instant::new(500));
        assert_eq!(clock.now(), Instant::new(500));
    }

    #[test]
    fn set_backward_is_clamped() {
        // a set into the past is refused: the clock holds its current time, so
        // time never runs backward.
        let mut clock = SimClock::at(500);
        clock.set(Instant::new(100));
        assert_eq!(clock.now(), Instant::new(500), "a backward set must be ignored");
    }

    #[test]
    fn set_to_the_current_time_is_a_noop() {
        let mut clock = SimClock::at(500);
        clock.set(Instant::new(500));
        assert_eq!(clock.now(), Instant::new(500));
    }

    #[test]
    fn reached_is_a_correct_threshold() {
        let deadline = Instant::new(100);
        // strictly before the deadline: not reached.
        assert!(!Instant::new(99).reached(deadline));
        // exactly at the deadline: reached (the boundary is inclusive).
        assert!(Instant::new(100).reached(deadline));
        // after the deadline: reached.
        assert!(Instant::new(101).reached(deadline));
    }

    #[test]
    fn saturating_add_does_not_wrap_near_the_maximum() {
        // a deadline computed near the end of time saturates instead of wrapping
        // to a small (past) value, so it stays in the future.
        let base = Instant::new(u64::MAX - 2);
        let deadline = base.saturating_add(Duration::new(1000));
        assert_eq!(deadline, Instant::new(u64::MAX));
        // and the base has NOT reached a saturated future deadline.
        assert!(!base.reached(deadline));
        // only the maximum instant reaches it.
        assert!(Instant::new(u64::MAX).reached(deadline));
    }

    #[test]
    fn a_fresh_deadline_is_never_in_the_past() {
        // the property the kernel relies on: now + d is always >= now, so a
        // freshly armed timeout never fires before any time has passed.
        for base in [0u64, 1, 1000, u64::MAX - 1, u64::MAX] {
            for span in [0u64, 1, 7, u64::MAX] {
                let now = Instant::new(base);
                let deadline = now.saturating_add(Duration::new(span));
                assert!(deadline.reached(now), "deadline {deadline:?} fell before {now:?}");
            }
        }
    }

    #[test]
    fn now_never_decreases_across_a_mixed_schedule() {
        // drive a hand-built interleaving of advance and set (including a
        // backward set) and assert monotonicity after every step, the SimClock
        // analogue of the endpoint's never-both-parked sequence test.
        let mut clock = SimClock::new();
        let steps: &[fn(&mut SimClock)] = &[
            |c| c.advance(Duration::new(10)),
            |c| c.set(Instant::new(100)),
            |c| c.set(Instant::new(50)), // backward: must be clamped
            |c| c.advance(Duration::new(0)),
            |c| c.advance(Duration::new(25)),
            |c| c.set(Instant::new(125)), // equal to current: no-op
        ];
        let mut previous = clock.now();
        for step in steps {
            step(&mut clock);
            let current = clock.now();
            assert!(current >= previous, "time went backward: {previous:?} -> {current:?}");
            previous = current;
        }
        // the backward set to 50 and equal set to 125 were both absorbed: the
        // final time is the running maximum (100 then +25).
        assert_eq!(clock.now(), Instant::new(125));
    }

    #[test]
    fn deadline_flips_exactly_once_when_crossed() {
        // a unit-scale version of the DST property: walk time forward one tick at
        // a time and confirm a deadline is not-reached strictly before it and
        // reached at and after it, flipping exactly once.
        let deadline = Instant::new(5);
        let mut clock = SimClock::new();
        let mut flips = 0;
        let mut was_reached = clock.now().reached(deadline);
        assert!(!was_reached, "deadline reached before any time passed");
        for _ in 0..10 {
            clock.advance(Duration::new(1));
            let is_reached = clock.now().reached(deadline);
            if is_reached != was_reached {
                flips += 1;
                // the only legal transition is not-reached -> reached.
                assert!(is_reached, "a reached deadline became un-reached");
                assert_eq!(clock.now(), deadline, "flipped at the wrong tick");
            }
            was_reached = is_reached;
        }
        assert_eq!(flips, 1, "the deadline should flip exactly once");
    }

    #[test]
    fn durations_and_instants_order_naturally() {
        // the derived Ord is the natural numeric order, which the harness relies
        // on to compare deadlines.
        assert!(Instant::new(1) < Instant::new(2));
        assert!(Duration::new(10) > Duration::new(9));
        assert_eq!(Instant::ZERO, Instant::new(0));
        assert_eq!(Duration::ZERO, Duration::new(0));
    }
}

// ---------------------------------------------------------------------------
// bounded proofs
// ---------------------------------------------------------------------------
//
// these prove the load-bearing arithmetic of the deadline logic and the
// monotonic guard of the simulated clock. all of it is integer add and compare,
// with no 64-bit multiply, so CBMC discharges it without the bit-blasting hang
// the rng and run_queue proofs document (see rng.rs and
// memory/dst-and-tracing.md); and there are no loops, so no #[kani::unwind]
// bound is needed. determinism is deliberately NOT proved here: a hand-advanced
// counter is deterministic by language guarantee (the same reasoning that
// dropped SimRng's determinism proof), so the dst_clock harness covers it.
#[cfg(kani)]
mod kani_proofs {
    use super::{Duration, Instant, KernelClock, SimClock};

    // a freshly computed deadline is never in the past: for any base instant and
    // any span, now + d is at or after now. this is what lets the kernel arm a
    // timeout without separately checking it did not wrap to the past.
    #[kani::proof]
    fn deadline_never_in_the_past() {
        let now = Instant::new(kani::any());
        let d = Duration::new(kani::any());
        let deadline = now.saturating_add(d);
        assert!(deadline.reached(now));
    }

    // reached is monotone in the current time: once an instant has reached a
    // deadline, every later instant has too. this is why a timeout, once fired,
    // stays fired as the clock keeps advancing.
    #[kani::proof]
    fn reached_is_monotone_in_now() {
        let now1 = Instant::new(kani::any());
        let now2 = Instant::new(kani::any());
        let deadline = Instant::new(kani::any());
        kani::assume(now1.reached(deadline));
        kani::assume(now2 >= now1);
        assert!(now2.reached(deadline));
    }

    // advancing a clock never moves it backward: now after advance is at or
    // after now before, for any starting tick and any span (saturation included).
    #[kani::proof]
    fn advance_is_monotone() {
        let mut clock = SimClock::at(kani::any());
        let before = clock.now();
        clock.advance(Duration::new(kani::any()));
        assert!(clock.now() >= before);
    }

    // setting a clock never moves it backward: the monotonic guard clamps a
    // backward set, so now after set is at or after now before, for any target.
    #[kani::proof]
    fn set_is_monotone() {
        let mut clock = SimClock::at(kani::any());
        let before = clock.now();
        clock.set(Instant::new(kani::any()));
        assert!(clock.now() >= before);
    }
}
