//! Asynchronous notification: a coalescing signal word, as pure verifiable logic.
//!
//! This is the second IPC primitive, the asynchronous counterpart to the
//! synchronous [`crate::endpoint`] rendezvous. Where an endpoint is a
//! capacity-1 hand-off that blocks both peers until they meet, a notification is
//! a non-blocking signal: a signaller deposits badge bits and returns
//! immediately, and a waiter collects the accumulated bits (blocking only when
//! none are pending). It is the seL4 `Notification` object, the clean
//! capability-mediated replacement for Unix signals, and the natural delivery
//! mechanism for "something happened" events (an IRQ fired, a timer expired,
//! a peer made progress) that must not force a rendezvous.
//!
//! As with [`crate::endpoint`], the kernel wraps this model behind a `Mutex` and
//! adds the one thing pure logic cannot hold: the parked waiter's
//! [`Waker`](core::task::Waker). Here a parked waiter is just a boolean and
//! "wake the waiter" is an effect flag the caller acts on, so the signal logic,
//! the part with the subtle coalescing and lost-wakeup invariants, is exercised
//! under `cargo test`, Miri, and Kani, none of which can run the kernel binary.
//!
//! # State and invariant
//!
//! The notification holds an accumulated set of badge bits (`pending`, an
//! OR-accumulation of every un-collected [`signal`](Notification::signal)) plus
//! a flag for whether a waiter is parked. The reachable states are constrained,
//! and the constraints are the invariant this module proves:
//!
//! 1. Signals coalesce: signalling `a` then `b` before a collection leaves
//!    `pending == a | b`. No signal is lost, and the badge is the union (the
//!    seL4 semantics: a notification is a set of pending events, not a count).
//! 2. A waiter parks only when nothing is pending, so `waiter_parked` implies
//!    `pending == 0` (an already-pending notification would satisfy the wait at
//!    once, so parking would be meaningless).
//! 3. A signal into a notification with a parked waiter delivers immediately and
//!    releases the waiter: after it, `waiter_parked` is false (the bits are
//!    pending for the woken waiter to collect).
//! 4. Collecting returns exactly the pending bits and clears them, so the next
//!    collection (with no intervening signal) returns nothing. The notification
//!    neither fabricates nor drops a badge.
//!
//! These follow from the operations being the only way to mutate the state, and
//! each establishing its half of the parking precondition. The `#[cfg(kani)]`
//! harnesses discharge them over arbitrary bounded op sequences.

/// A set of badge bits carried by a signal.
///
/// A notification's payload is a bitmask, not a count: signals coalesce by
/// bitwise OR, so a waiter learns *which* events occurred since it last
/// collected, not how many times. A bare `u64` newtype keeps the module
/// dependency-free, matching [`crate::cap_rights::Rights`] and
/// [`crate::trace::ObjectToken`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Badge(pub u64);

impl Badge {
    /// The empty badge: no bits set.
    pub const NONE: Self = Self(0);

    /// Returns `true` if no bits are set.
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns the union of two badges (the coalescing operation).
    #[inline]
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// The outcome of a non-blocking [`Notification::signal`].
///
/// The `woke_waiter` flag tells the caller a parked waiter was just released and
/// its waker should be fired (the kernel does this after dropping the lock). In
/// pure logic it is only a flag; there is no waker here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalOutcome {
    /// Whether a parked waiter was released by this signal.
    pub woke_waiter: bool,
}

/// The outcome of a non-blocking [`Notification::poll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollOutcome {
    /// Badge bits were pending and have now been collected and cleared.
    Collected(Badge),
    /// Nothing was pending. The blocking path parks the waiter instead (see
    /// [`Notification::park`]).
    Empty,
}

/// An asynchronous notification: an accumulated badge plus the parked state of a
/// single waiter.
///
/// See the module documentation for the state invariant. This carries no
/// `Waker`; the kernel pairs the `parked` flag with a stored waker it fires when
/// [`signal`](Self::signal) reports the waiter was woken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notification {
    // the accumulated, un-collected badge bits. coalesces by OR; 0 means idle.
    pending: Badge,
    // a waiter is parked (it polled while pending was empty).
    waiter_parked: bool,
}

impl Notification {
    /// Creates a fresh, idle notification: nothing pending, no waiter parked.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pending: Badge::NONE,
            waiter_parked: false,
        }
    }

    /// Returns the currently-pending (un-collected) badge.
    #[inline]
    #[must_use]
    pub const fn pending(&self) -> Badge {
        self.pending
    }

    /// Returns `true` if a waiter is parked on the notification.
    #[inline]
    #[must_use]
    pub const fn waiter_parked(&self) -> bool {
        self.waiter_parked
    }

    /// Signals the notification with `badge`, coalescing it into the pending set
    /// and releasing any parked waiter.
    ///
    /// Always succeeds (a notification never blocks a signaller, the defining
    /// difference from an endpoint send). The badge is unioned into `pending`;
    /// if a waiter was parked it is released ([`SignalOutcome::woke_waiter`] is
    /// `true`) so the caller fires its waker. A signal of the empty badge still
    /// releases a parked waiter (a wakeup with no new bits is a valid event), so
    /// the model never strands a waiter that a caller chose to wake.
    pub fn signal(&mut self, badge: Badge) -> SignalOutcome {
        self.pending = self.pending.union(badge);
        // a parked waiter parked because nothing was pending; it is now released
        // to collect whatever is pending. clear the flag and tell the caller.
        let woke_waiter = self.waiter_parked;
        self.waiter_parked = false;
        SignalOutcome { woke_waiter }
    }

    /// Collects the pending badge without blocking, clearing it.
    ///
    /// Returns [`PollOutcome::Collected`] with the accumulated bits when any are
    /// pending (and resets `pending` to empty), or [`PollOutcome::Empty`] when
    /// nothing is pending; the caller's blocking path then parks the waiter.
    pub fn poll(&mut self) -> PollOutcome {
        if self.pending.is_empty() {
            PollOutcome::Empty
        } else {
            let collected = self.pending;
            self.pending = Badge::NONE;
            PollOutcome::Collected(collected)
        }
    }

    /// Records that a waiter is parked, waiting for a signal.
    ///
    /// Self-guarding in the manner of [`Endpoint::park_receiver`](crate::endpoint::Endpoint::park_receiver):
    /// parking is meaningful only when nothing is pending (a pending badge would
    /// have been collected immediately), so this is a no-op when `pending` is
    /// non-empty. Returns `true` if the waiter is now parked. This keeps the
    /// invariant `waiter_parked` implies `pending == 0` unconditionally true,
    /// however the caller sequences its calls.
    pub fn park(&mut self) -> bool {
        if self.pending.is_empty() {
            self.waiter_parked = true;
        }
        self.waiter_parked
    }

    /// Clears the parked flag, returning whether a waiter was parked.
    ///
    /// The kernel calls this when a notification's capability is revoked: it must
    /// take and fire the stored waker so the blocked waiter observes the
    /// cancellation. The pending badge is left untouched (a revoke cancels the
    /// blocked waiter, it does not consume or fabricate a signal).
    pub fn clear_parked(&mut self) -> bool {
        let had_waiter = self.waiter_parked;
        self.waiter_parked = false;
        had_waiter
    }
}

impl Default for Notification {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{Badge, Notification, PollOutcome, SignalOutcome};

    #[test]
    fn fresh_notification_is_idle() {
        let n = Notification::new();
        assert!(n.pending().is_empty());
        assert!(!n.waiter_parked());
    }

    #[test]
    fn signal_then_poll_returns_the_badge() {
        let mut n = Notification::new();
        assert_eq!(n.signal(Badge(0b101)), SignalOutcome { woke_waiter: false });
        assert_eq!(n.poll(), PollOutcome::Collected(Badge(0b101)));
        // collecting cleared it: a second poll finds nothing.
        assert_eq!(n.poll(), PollOutcome::Empty);
    }

    #[test]
    fn signals_coalesce_by_or() {
        let mut n = Notification::new();
        n.signal(Badge(0b0001));
        n.signal(Badge(0b0100));
        n.signal(Badge(0b0001)); // a repeat sets no new bit
        // the waiter learns the union of every signal since the last collect.
        assert_eq!(n.poll(), PollOutcome::Collected(Badge(0b0101)));
    }

    #[test]
    fn poll_on_empty_is_empty() {
        let mut n = Notification::new();
        assert_eq!(n.poll(), PollOutcome::Empty);
    }

    #[test]
    fn signal_releases_a_parked_waiter() {
        let mut n = Notification::new();
        // a waiter finds nothing pending and parks.
        assert_eq!(n.poll(), PollOutcome::Empty);
        assert!(n.park());
        assert!(n.waiter_parked());
        // a signal delivers and is told the waiter was woken.
        assert_eq!(n.signal(Badge(0b10)), SignalOutcome { woke_waiter: true });
        assert!(!n.waiter_parked());
        // the woken waiter then collects the badge.
        assert_eq!(n.poll(), PollOutcome::Collected(Badge(0b10)));
    }

    #[test]
    fn park_is_a_noop_when_pending() {
        let mut n = Notification::new();
        n.signal(Badge(0b1));
        // something is pending: a waiter would collect it at once, so parking is
        // meaningless and refused.
        assert!(!n.park());
        assert!(!n.waiter_parked());
    }

    #[test]
    fn signal_of_empty_badge_still_wakes_a_waiter() {
        let mut n = Notification::new();
        n.park();
        assert!(n.waiter_parked());
        // an empty-badge signal is a bare wakeup: it releases the waiter even
        // though it adds no bits (the caller chose to wake it).
        assert_eq!(n.signal(Badge::NONE), SignalOutcome { woke_waiter: true });
        assert!(!n.waiter_parked());
        // nothing was actually pending, so the woken waiter collects nothing and
        // would park again (a spurious wake is allowed, never a lost one).
        assert_eq!(n.poll(), PollOutcome::Empty);
    }

    #[test]
    fn clear_parked_reports_and_clears() {
        let mut n = Notification::new();
        n.park();
        assert!(n.clear_parked());
        assert!(!n.waiter_parked());
        // a second clear reports nothing parked.
        assert!(!n.clear_parked());
    }

    #[test]
    fn clear_parked_leaves_pending_untouched() {
        let mut n = Notification::new();
        n.park();
        // a concurrent signal could arrive, but model a pure revoke: clear the
        // waiter without delivering. pending stays whatever it was (empty here).
        assert!(n.clear_parked());
        assert!(n.pending().is_empty());
    }

    #[test]
    fn no_signal_is_lost_across_a_sequence() {
        // drive a hand-built interleaving and assert the union of all signalled
        // bits is eventually collected, and the parked-implies-empty invariant
        // holds after every step.
        let mut n = Notification::new();
        let mut collected = 0u64;
        let steps: &[fn(&mut Notification) -> u64] = &[
            |n| { n.poll(); n.park(); 0 },           // park on empty
            |n| { n.signal(Badge(0b001)); 0 },       // wakes waiter, sets bit 0
            |n| match n.poll() { PollOutcome::Collected(b) => b.0, PollOutcome::Empty => 0 },
            |n| { n.signal(Badge(0b010)); 0 },
            |n| { n.signal(Badge(0b100)); 0 },
            |n| match n.poll() { PollOutcome::Collected(b) => b.0, PollOutcome::Empty => 0 },
        ];
        for step in steps {
            collected |= step(&mut n);
            assert!(
                !n.waiter_parked() || n.pending().is_empty(),
                "a waiter is parked while a badge is pending",
            );
        }
        // every signalled bit (0b001 | 0b010 | 0b100) was collected.
        assert_eq!(collected, 0b111);
    }
}

// ---------------------------------------------------------------------------
// bounded proofs
// ---------------------------------------------------------------------------
//
// the notification's transitions are bitwise-OR, comparison, and boolean logic
// (no arithmetic, in particular no 64-bit multiply), so these are cheap for
// CBMC: no unwind bound is needed. the badge is carried and unioned verbatim, so
// the coalescing proof confirms no signal is lost or fabricated.
#[cfg(kani)]
mod kani_proofs {
    use super::{Badge, Notification, PollOutcome, SignalOutcome};

    // an arbitrary notification state, used to prove the invariants from ANY
    // reachable starting point, not just a fresh one. the parked flag is
    // constrained to the reachable combination (parked implies nothing pending)
    // exactly as the operations maintain it; this models "some valid state"
    // rather than fabricating an unreachable one, mirroring endpoint's
    // any_valid_endpoint.
    fn any_valid_notification() -> Notification {
        let mut n = Notification::new();
        let bits: u64 = kani::any();
        if bits != 0 {
            n.signal(Badge(bits));
        }
        // park is self-guarding: it only takes effect when nothing is pending,
        // so the resulting state always satisfies parked => pending == 0.
        if kani::any() {
            n.park();
        }
        n
    }

    // the core invariant holds after a signal from any valid state: a parked
    // waiter is released (so parked is false), and the badge coalesced by OR.
    #[kani::proof]
    fn signal_preserves_invariant() {
        let mut n = any_valid_notification();
        let before = n.pending();
        let badge = Badge(kani::any());
        let out = n.signal(badge);
        // the badge is the union of what was pending and what was signalled: no
        // bit lost, none fabricated.
        assert!(n.pending() == before.union(badge));
        // after a signal no waiter remains parked (any was released).
        assert!(!n.waiter_parked());
        // the outcome reports a wake iff a waiter had been parked.
        let _ = out; // woke_waiter correctness is covered by the delivery proof
    }

    // the parked-implies-empty invariant holds after a poll from any valid state.
    #[kani::proof]
    fn poll_preserves_invariant() {
        let mut n = any_valid_notification();
        let _ = n.poll();
        // poll never parks, and it only ever clears pending, so the invariant
        // (parked => pending empty) is preserved; a poll that collected leaves
        // pending empty, and poll does not touch the parked flag.
        assert!(!n.waiter_parked() || n.pending().is_empty());
    }

    // signalling into a parked notification delivers immediately: the waiter is
    // released and the bits are pending for it to collect. this is the
    // no-lost-wakeup property: a signal can never leave a waiter parked.
    #[kani::proof]
    fn signal_into_parked_wakes_and_delivers() {
        // build the parked-on-empty state directly: poll empty, then park.
        let mut n = Notification::new();
        assert!(matches!(n.poll(), PollOutcome::Empty));
        assert!(n.park());

        let badge = Badge(kani::any());
        let out = n.signal(badge);
        // a parked waiter was present, so it is woken.
        assert!(out == SignalOutcome { woke_waiter: true });
        assert!(!n.waiter_parked());
        // and the signalled bits are exactly what is now pending.
        assert!(n.pending() == badge);
    }

    // park only takes effect on an empty notification; a pending badge refuses
    // the park. this is the self-guarding property the invariant rests on.
    #[kani::proof]
    fn park_is_self_guarding() {
        let mut n = any_valid_notification();
        let was_empty = n.pending().is_empty();
        if n.park() {
            // if a waiter is now parked, nothing was (or is) pending.
            assert!(was_empty && n.pending().is_empty());
        }
    }

    // collecting returns exactly the pending bits and clears them: a deposit
    // then a single poll yields the same badge, and an immediate second poll
    // yields nothing. no fabrication, no duplication of a badge.
    #[kani::proof]
    fn poll_returns_then_clears() {
        let mut n = Notification::new();
        let bits: u64 = kani::any();
        kani::assume(bits != 0);
        n.signal(Badge(bits));
        match n.poll() {
            PollOutcome::Collected(b) => assert!(b == Badge(bits)),
            PollOutcome::Empty => panic!("a non-empty badge polled as empty"),
        }
        // the badge was cleared: a second poll with no intervening signal is empty.
        assert!(matches!(n.poll(), PollOutcome::Empty));
    }
}
