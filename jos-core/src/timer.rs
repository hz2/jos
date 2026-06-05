//! Deadline-ordered wakeups: a bounded, heap-free timer queue.
//!
//! This is the first consumer of the injected [`KernelClock`](crate::clock)
//! seam, and the building block beneath both IPC receive-with-timeout and a
//! timed scheduler tick. A caller arms timers, each with a deadline (an
//! [`Instant`]) and an opaque `u64` payload naming what to wake, and then, as
//! the clock advances, drains the timers that have come due, earliest first.
//! The kernel side maps the payload to a real effect (firing a `Waker`, marking
//! a thread runnable); here, as with the endpoint's `woke_*` flags, the payload
//! is just data carried verbatim, so the rendezvous logic stays pure and
//! verifiable.
//!
//! Like the [`fault`](crate::fault) delay queue, the storage is a fixed-capacity
//! array with a packed prefix (no heap, no `alloc`), so it runs unchanged in the
//! kernel and is small enough for Kani to discharge its invariants over
//! arbitrary states. Finding the earliest timer is a linear scan rather than a
//! binary heap: for the small capacities a microkernel timer queue holds, the
//! scan is cheap and, more importantly, trivially verifiable (no heap-order
//! invariant to maintain or prove).
//!
//! # State and invariant
//!
//! The queue holds up to `CAP` [`Timer`]s in `slots`, with the live ones packed
//! into the prefix `slots[0..len]` (every entry there is `Some`; every entry at
//! or past `len` is `None`). Each armed timer is given a fresh, strictly
//! increasing [`TimerId`] that is never reused within the queue's lifetime, so a
//! [`cancel`](TimerQueue::cancel) names exactly one timer and there is no ABA
//! confusion across arm/expire/re-arm. The operations maintain:
//!
//! 1. **Capacity.** [`arm`](TimerQueue::arm) succeeds iff the queue is not full;
//!    a successful arm grows `len` by one, a refused arm leaves it unchanged and
//!    consumes no [`TimerId`].
//! 2. **No early fire.** [`expire_next`](TimerQueue::expire_next) returns a timer
//!    only when that timer's deadline has been reached by the supplied time.
//! 3. **Earliest first.** When it does fire, it fires the timer with the
//!    earliest deadline (ties broken by [`TimerId`], a total order), so repeated
//!    draining yields timers in non-decreasing deadline order.
//! 4. **Progress.** Conversely, if the queue is non-empty and its earliest timer
//!    is due, [`expire_next`](TimerQueue::expire_next) does fire it rather than
//!    spuriously reporting nothing. With (2) this characterizes firing exactly:
//!    it fires iff a due timer exists.
//! 5. **Cancel removes at most one.** [`cancel`](TimerQueue::cancel) removes the
//!    single timer with the given id (if present) and nothing else.
//!
//! These follow from the operations being the only way to mutate the state, and
//! the `#[cfg(kani)]` harnesses discharge them over arbitrary bounded queues.

use crate::clock::Instant;

/// A handle to an armed timer, unique within a [`TimerQueue`]'s lifetime.
///
/// Returned by [`arm`](TimerQueue::arm) and passed to
/// [`cancel`](TimerQueue::cancel). Ids are assigned from a strictly increasing
/// counter and never reused, so a stale id (one whose timer already fired or was
/// cancelled) simply matches nothing, never a different timer. The inner value
/// is public like [`ObjectToken`](crate::trace::ObjectToken): an id is a plain
/// handle, not an unforgeable authority token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimerId(pub u64);

/// An armed timer: a deadline, the payload to deliver when it fires, and its id.
///
/// `Copy` (all fields are `Copy`), so arming, draining, and iterating move
/// values with no aliasing. The `data` word is opaque to the queue: it is
/// carried from [`arm`](TimerQueue::arm) to the [`Timer`] returned by
/// [`expire_next`](TimerQueue::expire_next) without interpretation, the way the
/// endpoint carries a [`Message`](crate::endpoint::Message) payload verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timer {
    /// This timer's unique id, for cancellation and correlation.
    pub id: TimerId,
    /// The instant at or after which this timer is due to fire.
    pub deadline: Instant,
    /// Opaque payload naming what to wake (a thread id, a waker key); carried
    /// verbatim by the queue.
    pub data: u64,
}

/// A fixed-capacity, heap-free queue of pending timers, drained earliest-first
/// as a [`KernelClock`](crate::clock::KernelClock) advances.
///
/// `CAP` is the maximum number of simultaneously armed timers. See the module
/// documentation for the state invariant.
#[derive(Debug, Clone)]
pub struct TimerQueue<const CAP: usize> {
    // live timers occupy slots[0..len] (all Some); slots[len..] are None. order
    // within the prefix is arbitrary: the earliest is found by scan, not by
    // position, so removal can swap-fill the hole without resorting.
    slots: [Option<Timer>; CAP],
    len: usize,
    // the next id to hand out. strictly increasing, never reset, so ids are
    // unique for the queue's whole lifetime (no reuse, no ABA on cancel).
    next_id: u64,
}

impl<const CAP: usize> TimerQueue<CAP> {
    /// Creates an empty timer queue.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [None; CAP],
            len: 0,
            next_id: 0,
        }
    }

    /// Returns the number of timers currently armed.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if no timers are armed.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` if the queue is at capacity and cannot accept another arm.
    #[inline]
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.len == CAP
    }

    /// Returns the queue's capacity (`CAP`).
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> usize {
        CAP
    }

    /// Arms a timer for `deadline` carrying `data`, returning its [`TimerId`].
    ///
    /// Returns `None` if the queue is already full, in which case nothing is
    /// armed and no id is consumed (so ids stay dense and in lockstep with a
    /// caller's own accounting). A deadline already in the past is allowed: such
    /// a timer simply fires on the next [`expire_next`](Self::expire_next).
    ///
    /// # Panics
    ///
    /// Panics in debug builds if the internal packing invariant is violated
    /// (it cannot be, by construction); the check is compiled out of release.
    pub fn arm(&mut self, deadline: Instant, data: u64) -> Option<TimerId> {
        if self.len >= CAP {
            return None;
        }
        let id = TimerId(self.next_id);
        // one arm per id; bounded by the number of arms in a run, never near
        // u64::MAX, so a plain increment cannot overflow in practice.
        self.next_id += 1;
        self.slots[self.len] = Some(Timer { id, deadline, data });
        self.len += 1;
        self.debug_assert_packed();
        Some(id)
    }

    /// Cancels the timer with id `id`, returning `true` if one was removed.
    ///
    /// Cancelling an id that is not present (already fired, already cancelled,
    /// or never issued) is a no-op returning `false`. At most one timer is ever
    /// removed, since ids are unique.
    pub fn cancel(&mut self, id: TimerId) -> bool {
        let mut i = 0;
        while i < self.len {
            // 0..len are Some by the packing invariant; match rather than expect
            // so the public method carries no panic path.
            if matches!(self.slots[i], Some(t) if t.id == id) {
                self.remove_at(i);
                return true;
            }
            i += 1;
        }
        false
    }

    /// Returns the earliest-deadline timer without removing it, or `None` if the
    /// queue is empty.
    ///
    /// This is what the kernel programs the hardware timer against: the next
    /// instant it must wake up, regardless of whether that timer is due yet.
    #[must_use]
    pub fn peek_next(&self) -> Option<Timer> {
        // next_index points at a live (Some) slot, so the and_then never yields
        // None there; written without expect so the method carries no panic path.
        self.next_index().and_then(|i| self.slots[i])
    }

    /// Returns the earliest pending deadline, or `None` if the queue is empty.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        self.peek_next().map(|t| t.deadline)
    }

    /// Removes and returns the earliest-deadline timer if it is due at `now`,
    /// else `None`.
    ///
    /// "Due" means `now.reached(timer.deadline)` (the clock is at or past the
    /// deadline). Because the earliest deadline is the smallest, it is due iff
    /// *any* timer is due, so draining in a loop
    /// (`while let Some(t) = q.expire_next(now)`) yields every due timer in
    /// non-decreasing deadline order and stops exactly when none remain due.
    pub fn expire_next(&mut self, now: Instant) -> Option<Timer> {
        let i = self.next_index()?;
        // next_index points at a live slot; match rather than expect so the
        // public method carries no panic path.
        let timer = self.slots[i]?;
        if now.reached(timer.deadline) {
            Some(self.remove_at(i))
        } else {
            None
        }
    }

    /// Returns `true` if a timer with id `id` is currently armed.
    #[must_use]
    pub fn contains(&self, id: TimerId) -> bool {
        self.iter().any(|t| t.id == id)
    }

    /// Iterates the armed timers, in arbitrary (storage) order.
    ///
    /// The order is not the firing order; use [`expire_next`](Self::expire_next)
    /// to drain in deadline order. This is for inspection and for a consumer that
    /// wants to account for everything pending.
    pub fn iter(&self) -> impl Iterator<Item = Timer> + '_ {
        // 0..len are always Some by the packing invariant, so filter_map yields
        // exactly the live timers, never silently swallowing one.
        self.slots[..self.len].iter().filter_map(|slot| *slot)
    }

    // returns the index of the earliest-deadline live timer, ties broken by the
    // smaller id (so the choice is a total order and fully deterministic), or
    // None when empty. the single place the firing order is decided.
    fn next_index(&self) -> Option<usize> {
        let mut best: Option<usize> = None;
        let mut i = 0;
        while i < self.len {
            let cand = self.slots[i].expect("0..len are Some");
            best = match best {
                None => Some(i),
                Some(b) => {
                    let cur = self.slots[b].expect("best points at a live slot");
                    // order by (deadline, id): a total order, so the winner is
                    // unique and the scan is deterministic.
                    if (cand.deadline, cand.id) < (cur.deadline, cur.id) {
                        Some(i)
                    } else {
                        Some(b)
                    }
                }
            };
            i += 1;
        }
        best
    }

    // removes the timer at index `i` and returns it, keeping slots[0..len]
    // packed by moving the last live entry into the hole. preserves the packing
    // invariant for any i < len.
    fn remove_at(&mut self, i: usize) -> Timer {
        let removed = self.slots[i].take().expect("removing a live slot");
        self.len -= 1;
        // if i was the last live slot, the take above already cleared it;
        // otherwise refill the hole from the (new) last slot.
        if i != self.len {
            self.slots[i] = self.slots[self.len].take();
        }
        self.debug_assert_packed();
        removed
    }

    // checks the packing invariant in debug builds: slots[0..len] are all Some
    // and slots[len..] are all None. compiled out of release, this is the
    // machine-checked statement of the invariant the panic-free `?` in peek_next
    // / expire_next and the `iter().count() == len()` proofs rely on. it mirrors
    // the bitmap's debug_assert bounds guards: a guarantee the code maintains by
    // construction, cheaply re-checked where it could be broken.
    #[inline]
    fn debug_assert_packed(&self) {
        debug_assert!(self.len <= CAP, "timer queue len exceeds capacity");
        debug_assert!(
            self.slots[..self.len].iter().all(Option::is_some),
            "timer queue prefix [0..len] must be fully packed (all Some)",
        );
        debug_assert!(
            self.slots[self.len..].iter().all(Option::is_none),
            "timer queue suffix [len..] must be empty (all None)",
        );
    }
}

impl<const CAP: usize> Default for TimerQueue<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{TimerId, TimerQueue};
    use crate::clock::Instant;
    extern crate std;
    use std::vec::Vec;

    fn at(t: u64) -> Instant {
        Instant::new(t)
    }

    #[test]
    fn fresh_queue_is_empty() {
        let q = TimerQueue::<4>::new();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert!(!q.is_full());
        assert_eq!(q.capacity(), 4);
        assert_eq!(q.peek_next(), None);
        assert_eq!(q.next_deadline(), None);
    }

    #[test]
    fn arm_assigns_distinct_increasing_ids() {
        let mut q = TimerQueue::<4>::new();
        let a = q.arm(at(10), 0xA).unwrap();
        let b = q.arm(at(20), 0xB).unwrap();
        let c = q.arm(at(30), 0xC).unwrap();
        assert_eq!((a, b, c), (TimerId(0), TimerId(1), TimerId(2)));
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn arm_refuses_when_full_and_consumes_no_id() {
        let mut q = TimerQueue::<2>::new();
        q.arm(at(1), 0).unwrap();
        q.arm(at(2), 0).unwrap();
        assert!(q.is_full());
        // a refused arm returns None and changes nothing.
        assert_eq!(q.arm(at(3), 0), None);
        assert_eq!(q.len(), 2);
        // and the next successful arm (after a cancel frees a slot) reuses the
        // id that the refused arm did NOT consume.
        q.cancel(TimerId(0));
        assert_eq!(q.arm(at(3), 0), Some(TimerId(2)));
    }

    #[test]
    fn peek_returns_the_earliest_without_removing() {
        let mut q = TimerQueue::<4>::new();
        q.arm(at(30), 0);
        q.arm(at(10), 0);
        q.arm(at(20), 0);
        assert_eq!(q.next_deadline(), Some(at(10)));
        // peek does not consume.
        assert_eq!(q.len(), 3);
        assert_eq!(q.next_deadline(), Some(at(10)));
    }

    #[test]
    fn expire_fires_earliest_first_only_when_due() {
        let mut q = TimerQueue::<4>::new();
        q.arm(at(30), 0xC);
        q.arm(at(10), 0xA);
        q.arm(at(20), 0xB);

        // nothing due yet at t=5.
        assert_eq!(q.expire_next(at(5)), None);
        assert_eq!(q.len(), 3);

        // at t=15, only the t=10 timer is due, and it fires.
        let fired = q.expire_next(at(15)).unwrap();
        assert_eq!(fired.deadline, at(10));
        assert_eq!(fired.data, 0xA);
        assert_eq!(q.len(), 2);
        // the t=20 timer is not due at t=15.
        assert_eq!(q.expire_next(at(15)), None);

        // at t=100 the rest drain in deadline order.
        assert_eq!(q.expire_next(at(100)).unwrap().deadline, at(20));
        assert_eq!(q.expire_next(at(100)).unwrap().deadline, at(30));
        assert_eq!(q.expire_next(at(100)), None);
        assert!(q.is_empty());
    }

    #[test]
    fn draining_yields_nondecreasing_deadlines() {
        // arm in a deliberately scrambled order; draining must still come out
        // sorted by deadline.
        let mut q = TimerQueue::<8>::new();
        for d in [50u64, 10, 90, 30, 70, 20, 80, 40] {
            q.arm(at(d), d);
        }
        let mut drained = Vec::new();
        while let Some(t) = q.expire_next(at(1000)) {
            drained.push(t.deadline.ticks());
        }
        let mut sorted = drained.clone();
        sorted.sort_unstable();
        assert_eq!(drained, sorted, "drain order must be non-decreasing by deadline");
        assert_eq!(drained.len(), 8);
    }

    #[test]
    fn equal_deadlines_break_ties_by_id_deterministically() {
        // three timers share a deadline; they must drain in id (arm) order, a
        // total order, so the result is deterministic rather than storage-order
        // dependent.
        let mut q = TimerQueue::<4>::new();
        let first = q.arm(at(10), 1).unwrap();
        let second = q.arm(at(10), 2).unwrap();
        let third = q.arm(at(10), 3).unwrap();
        assert_eq!(q.expire_next(at(10)).unwrap().id, first);
        assert_eq!(q.expire_next(at(10)).unwrap().id, second);
        assert_eq!(q.expire_next(at(10)).unwrap().id, third);
    }

    #[test]
    fn cancel_removes_exactly_the_named_timer() {
        let mut q = TimerQueue::<4>::new();
        let a = q.arm(at(10), 0xA).unwrap();
        let b = q.arm(at(20), 0xB).unwrap();
        let c = q.arm(at(30), 0xC).unwrap();

        assert!(q.contains(b));
        assert!(q.cancel(b));
        assert!(!q.contains(b));
        assert_eq!(q.len(), 2);

        // a and c survive, still in deadline order.
        assert_eq!(q.expire_next(at(100)).unwrap().id, a);
        assert_eq!(q.expire_next(at(100)).unwrap().id, c);
        assert!(q.is_empty());
    }

    #[test]
    fn cancel_absent_id_is_a_noop() {
        let mut q = TimerQueue::<4>::new();
        q.arm(at(10), 0);
        // an id never issued.
        assert!(!q.cancel(TimerId(999)));
        assert_eq!(q.len(), 1);
        // an id that already fired.
        let fired = q.expire_next(at(10)).unwrap();
        assert!(!q.cancel(fired.id));
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn payload_round_trips_uncorrupted() {
        // the queue carries the data word verbatim from arm to fire, for every
        // timer, regardless of the scramble introduced by swap-remove.
        let mut q = TimerQueue::<8>::new();
        let payloads = [0xDEADu64, 0xBEEF, 0x1234, 0xFFFF_FFFF_FFFF_FFFF, 0, 7, 42, 0xA5A5];
        for (i, &p) in payloads.iter().enumerate() {
            // deadlines descending so storage and fire order differ.
            q.arm(at(100 - u64::try_from(i).unwrap()), p);
        }
        let mut seen = Vec::new();
        while let Some(t) = q.expire_next(at(1000)) {
            // the data must match the deadline it was armed with.
            let i = usize::try_from(100 - t.deadline.ticks()).unwrap();
            assert_eq!(t.data, payloads[i], "payload corrupted for deadline {:?}", t.deadline);
            seen.push(t.data);
        }
        assert_eq!(seen.len(), payloads.len());
    }

    #[test]
    fn iter_yields_every_live_timer_once() {
        let mut q = TimerQueue::<4>::new();
        q.arm(at(10), 0xA);
        q.arm(at(20), 0xB);
        q.cancel(TimerId(0));
        q.arm(at(30), 0xC);
        // iter must yield exactly the live timers (B and C), exactly once each.
        let mut datas: Vec<u64> = q.iter().map(|t| t.data).collect();
        datas.sort_unstable();
        assert_eq!(datas, std::vec![0xB, 0xC]);
        assert_eq!(q.iter().count(), q.len());
    }

    #[test]
    fn swap_remove_keeps_the_prefix_packed() {
        // remove from the middle repeatedly; iter().count() must always equal
        // len(), which only holds if the prefix stays packed (no None hole, no
        // surviving duplicate).
        let mut q = TimerQueue::<8>::new();
        let ids: Vec<TimerId> = (0..8).map(|d| q.arm(at(d), d).unwrap()).collect();
        // cancel every other one, then a few more, checking packing each time.
        for id in [ids[3], ids[0], ids[6], ids[1], ids[7]] {
            assert!(q.cancel(id));
            assert_eq!(q.iter().count(), q.len(), "prefix unpacked after cancel");
        }
        assert_eq!(q.len(), 3);
        // the survivors (2, 4, 5) still drain in deadline order.
        let drained: Vec<u64> = {
            let mut v = Vec::new();
            while let Some(t) = q.expire_next(at(1000)) {
                v.push(t.deadline.ticks());
            }
            v
        };
        assert_eq!(drained, std::vec![2, 4, 5]);
    }
}

// ---------------------------------------------------------------------------
// bounded proofs
// ---------------------------------------------------------------------------
//
// the queue's operations are comparison, enum, and bounded-loop logic with no
// arithmetic on symbolic values (in particular no 64-bit multiply), so CBMC
// discharges them cheaply: each loop is bounded by CAP, so a single small
// #[kani::unwind] covers them, and there is no multiply to bit-blast (the hang
// documented in rng.rs and memory/dst-and-tracing.md). the proofs use a small
// concrete CAP and build an arbitrary reachable queue with `any_queue`, the same
// shape as the endpoint's `any_valid_endpoint`.
#[cfg(kani)]
mod kani_proofs {
    use super::{TimerId, TimerQueue};
    use crate::clock::Instant;

    // proof-time capacity: small, so the bounded scans stay cheap, but >1 so the
    // earliest-of-many and swap-remove paths are exercised.
    const CAP: usize = 4;

    // an arbitrary reachable queue: 0..=CAP timers armed with symbolic deadlines
    // and payloads. built only through arm, so it satisfies the packing and id
    // invariants by construction (modelling "some reachable state", not a
    // fabricated one), exactly as any_valid_endpoint does.
    fn any_queue() -> TimerQueue<CAP> {
        let mut q = TimerQueue::new();
        let n: usize = kani::any();
        kani::assume(n <= CAP);
        let mut i = 0;
        while i < n {
            let _ = q.arm(Instant::new(kani::any()), kani::any());
            i += 1;
        }
        q
    }

    // arm succeeds iff the queue is not full; a success grows len by one, a
    // refusal leaves it unchanged. covers invariant 1.
    #[kani::proof]
    #[kani::unwind(6)]
    fn arm_respects_capacity() {
        let mut q = any_queue();
        let before = q.len();
        let was_full = q.is_full();
        let r = q.arm(Instant::new(kani::any()), kani::any());
        if was_full {
            assert!(r.is_none());
            assert!(q.len() == before);
        } else {
            assert!(r.is_some());
            assert!(q.len() == before + 1);
        }
        // the live count and the packed prefix stay in agreement.
        assert!(q.iter().count() == q.len());
    }

    // expire_next never fires a timer that is not yet due. covers invariant 2
    // (no early fire).
    #[kani::proof]
    #[kani::unwind(6)]
    fn no_early_fire() {
        let mut q = any_queue();
        let now = Instant::new(kani::any());
        if let Some(t) = q.expire_next(now) {
            assert!(now.reached(t.deadline));
        }
    }

    // when expire_next fires, the fired timer's deadline is <= every timer left
    // in the queue: it really was the earliest. covers invariant 3.
    #[kani::proof]
    #[kani::unwind(6)]
    fn fires_the_earliest() {
        let mut q = any_queue();
        let now = Instant::new(kani::any());
        if let Some(fired) = q.expire_next(now) {
            for remaining in q.iter() {
                assert!(fired.deadline <= remaining.deadline);
            }
        }
    }

    // the converse of no_early_fire: if the earliest timer is due, expire_next
    // fires it (and exactly it), rather than reporting nothing. covers invariant
    // 4 (progress). together with no_early_fire this pins firing down exactly.
    #[kani::proof]
    #[kani::unwind(6)]
    fn fires_when_a_due_timer_exists() {
        let mut q = any_queue();
        let now = Instant::new(kani::any());
        if let Some(peeked) = q.peek_next() {
            if now.reached(peeked.deadline) {
                let fired = q.expire_next(now);
                assert!(fired.is_some());
                // it fires precisely the timer peek identified as earliest.
                assert!(fired.expect("just asserted some").id == peeked.id);
            }
        }
    }

    // cancel removes exactly the named timer if present, and nothing otherwise:
    // the return value equals presence, len drops by one iff it was present, and
    // the id is gone afterward. covers invariant 5.
    #[kani::proof]
    #[kani::unwind(6)]
    fn cancel_removes_at_most_one() {
        let mut q = any_queue();
        let id = TimerId(kani::any());
        let before = q.len();
        let present = q.contains(id);
        let removed = q.cancel(id);
        assert!(removed == present);
        if removed {
            assert!(q.len() == before - 1);
            assert!(!q.contains(id));
        } else {
            assert!(q.len() == before);
        }
        assert!(q.iter().count() == q.len());
    }
}
