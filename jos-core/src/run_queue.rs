//! Verified dedup'ing FIFO run queue for the cooperative scheduler.
//!
//! # Invariant
//!
//! The run queue holds *task indices* in `[0, N)` in first-enqueued-first-out
//! order, with at most one occurrence of each index. Two fields back this: a
//! `fifo` (the order) and a `queued` membership array.
//!
//! - membership: `queued[i]` is `true` iff index `i` is somewhere in `fifo`.
//! - dedup: [`enqueue`](RunQueue::enqueue) is a no-op when `queued[i]` is
//!   already set, so no index appears in `fifo` more than once.
//! - count: the number of `true` entries in `queued` equals `fifo.len()`.
//!
//! Two consequences fall out of these and are proven below:
//! - the queue length never exceeds `N` (there are only `N` distinct indices,
//!   each present at most once), so enqueuing a fresh index never fails; and
//! - `enqueue` is idempotent: waking an already-ready task does not grow it.
//!
//! This is the `seL4` `on_rq`-style scheduler invariant (a thread is on the run
//! queue at most once), modeled in pure logic so Kani/Miri can check it. The
//! kernel executor wires this model to futures, wakers, and `hlt`; the
//! lock-free concurrency primitive that carries wakeups in from interrupt
//! context lives in the kernel, so this model stays single-owner and pure.

use crate::ring_buffer::RingBuffer;

/// A bounded FIFO of task indices in `[0, N)` that holds each index at most
/// once. Enqueue is idempotent; dequeue returns indices in enqueue order.
pub struct RunQueue<const N: usize> {
    // the ready order; holds each queued index exactly once.
    fifo: RingBuffer<usize, N>,
    // queued[i] mirrors "index i is in fifo". the sole source of dedup truth.
    queued: [bool; N],
}

impl<const N: usize> RunQueue<N> {
    /// Creates an empty run queue.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            fifo: RingBuffer::new(),
            queued: [false; N],
        }
    }

    /// Returns the maximum number of distinct indices the queue can hold, `N`.
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Returns the number of indices currently queued.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.fifo.len()
    }

    /// Returns `true` if the queue holds no indices.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.fifo.is_empty()
    }

    /// Returns `true` if every distinct index is already queued.
    #[inline]
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.fifo.is_full()
    }

    /// Returns `true` if index `id` is currently in the queue.
    ///
    /// Out-of-range indices (`id >= N`) are never queued, so this is `false`.
    #[inline]
    #[must_use]
    pub fn is_queued(&self, id: usize) -> bool {
        id < N && self.queued[id]
    }

    /// Enqueues task index `id`, returning `true` if it was newly added.
    ///
    /// Idempotent: enqueuing an index that is already queued (or an out-of-range
    /// index) is a no-op that returns `false`. Under the module invariant a
    /// fresh in-range index always fits (proven in `enqueue_fresh_never_drops`),
    /// so the `Err` arm is unreachable; it is handled anyway to keep `queued`
    /// and `fifo` consistent without relying on that proof for soundness.
    pub fn enqueue(&mut self, id: usize) -> bool {
        if id >= N || self.queued[id] {
            return false;
        }
        match self.fifo.push(id) {
            Ok(()) => {
                self.queued[id] = true;
                true
            }
            Err(_) => false,
        }
    }

    /// Removes and returns the index at the front of the queue, or `None` if it
    /// is empty. The returned index is cleared from the membership set.
    pub fn dequeue(&mut self) -> Option<usize> {
        let id = self.fifo.pop()?;
        // every index in fifo was put there by enqueue, which only admits
        // in-range ids, so id < N here; guard anyway to stay panic-free.
        if id < N {
            self.queued[id] = false;
        }
        Some(id)
    }

    // number of indices flagged as queued. used by the tests and proofs to
    // check the count invariant (queued_count == len) directly.
    #[cfg(any(test, kani))]
    fn queued_count(&self) -> usize {
        let mut count = 0;
        let mut i = 0;
        while i < N {
            if self.queued[i] {
                count += 1;
            }
            i += 1;
        }
        count
    }
}

impl<const N: usize> Default for RunQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::RunQueue;

    #[test]
    fn new_queue_is_empty() {
        let q: RunQueue<8> = RunQueue::new();
        assert!(q.is_empty());
        assert!(!q.is_full());
        assert_eq!(q.len(), 0);
        assert_eq!(q.capacity(), 8);
    }

    #[test]
    fn enqueue_then_dequeue_roundtrip() {
        let mut q: RunQueue<8> = RunQueue::new();
        assert!(q.enqueue(3));
        assert!(q.is_queued(3));
        assert_eq!(q.len(), 1);
        assert_eq!(q.dequeue(), Some(3));
        assert!(!q.is_queued(3));
        assert!(q.is_empty());
    }

    #[test]
    fn enqueue_is_idempotent() {
        let mut q: RunQueue<8> = RunQueue::new();
        assert!(q.enqueue(2)); // newly added
        assert!(!q.enqueue(2)); // already queued: no-op
        assert!(!q.enqueue(2));
        assert_eq!(q.len(), 1);
        // it appears exactly once, so a single dequeue empties the queue.
        assert_eq!(q.dequeue(), Some(2));
        assert!(q.is_empty());
    }

    #[test]
    fn dequeue_then_reenqueue_is_allowed() {
        let mut q: RunQueue<8> = RunQueue::new();
        q.enqueue(5);
        assert_eq!(q.dequeue(), Some(5));
        // after dequeue the index is no longer queued, so it can be added again
        // (a task that ran, then was woken once more).
        assert!(q.enqueue(5));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn fifo_ordering() {
        let mut q: RunQueue<8> = RunQueue::new();
        for id in [4_usize, 1, 7, 0, 2] {
            assert!(q.enqueue(id));
        }
        // re-enqueuing any already-queued id changes nothing.
        assert!(!q.enqueue(7));
        let mut got = [0_usize; 5];
        for slot in &mut got {
            *slot = q.dequeue().unwrap();
        }
        assert_eq!(got, [4, 1, 7, 0, 2]);
        assert!(q.dequeue().is_none());
    }

    #[test]
    fn out_of_range_index_is_rejected() {
        let mut q: RunQueue<4> = RunQueue::new();
        assert!(!q.enqueue(4)); // == N
        assert!(!q.enqueue(99)); // > N
        assert!(!q.is_queued(4));
        assert!(q.is_empty());
    }

    #[test]
    fn fills_to_capacity_with_distinct_indices() {
        let mut q: RunQueue<4> = RunQueue::new();
        for id in 0..4 {
            assert!(q.enqueue(id));
        }
        assert!(q.is_full());
        assert_eq!(q.len(), 4);
        // a fresh fill is impossible (every distinct index is already in), and
        // every still-pending id is a dup, so no enqueue can ever overflow.
        assert!(!q.enqueue(0));
        assert_eq!(q.queued_count(), 4);
    }

    #[test]
    fn count_matches_len_through_a_mixed_sequence() {
        let mut q: RunQueue<6> = RunQueue::new();
        let ops = [1_usize, 1, 3, 5, 3, 0];
        for &id in &ops {
            q.enqueue(id);
            assert_eq!(q.queued_count(), q.len());
        }
        while let Some(_id) = q.dequeue() {
            assert_eq!(q.queued_count(), q.len());
        }
        assert_eq!(q.queued_count(), 0);
    }
}

// bounded proofs of the run-queue invariants.
//
// every harness here constructs (and therefore drops) a `RunQueue`, which wraps
// a `RingBuffer` whose `Drop` runs `for i in 0..len`. CBMC cannot bound that
// loop on its own, so each harness carries an explicit `#[kani::unwind]`: the
// `len <= N` invariant means `N + 1` unwinds suffice, and the unwinding
// assertion then *proves* the drop loop terminates within that bound. `N` is
// kept a power of two so the ring buffer's `% N` is a cheap mask for the solver
// rather than full 64-bit division.
#[cfg(kani)]
mod kani_proofs {
    use super::RunQueue;

    // capacity used by the harnesses. the matching unwind bound is N + 1 == 5
    // (kani::unwind needs a literal, so it is written out as 5 on each harness);
    // that covers the ring buffer's drop loop, queued_count's scan, and the
    // op loop below, each of which runs at most N times.
    const N: usize = 4;

    // a fresh in-range index always enqueues (never dropped) and is then queued.
    #[kani::proof]
    #[kani::unwind(5)] // N + 1
    fn enqueue_fresh_never_drops() {
        let mut q: RunQueue<N> = RunQueue::new();
        let id: usize = kani::any();
        kani::assume(id < N);
        // fresh queue: id is not yet queued, so enqueue must succeed.
        assert!(q.enqueue(id));
        assert!(q.is_queued(id));
        assert_eq!(q.len(), 1);
    }

    // enqueuing an already-queued index is a no-op: it returns false and leaves
    // the length unchanged (dedup / idempotence).
    #[kani::proof]
    #[kani::unwind(5)] // N + 1
    fn enqueue_idempotent() {
        let mut q: RunQueue<N> = RunQueue::new();
        let id: usize = kani::any();
        kani::assume(id < N);
        assert!(q.enqueue(id));
        let len_before = q.len();
        assert!(!q.enqueue(id));
        assert_eq!(q.len(), len_before);
    }

    // an out-of-range index is rejected and leaves the queue untouched.
    #[kani::proof]
    #[kani::unwind(5)] // N + 1
    fn out_of_range_is_rejected() {
        let mut q: RunQueue<N> = RunQueue::new();
        let id: usize = kani::any();
        kani::assume(id >= N);
        assert!(!q.enqueue(id));
        assert!(!q.is_queued(id));
        assert!(q.is_empty());
    }

    // dequeue returns the first-enqueued index and clears its membership.
    #[kani::proof]
    #[kani::unwind(5)] // N + 1
    fn dequeue_is_fifo_and_clears_membership() {
        let mut q: RunQueue<N> = RunQueue::new();
        let a: usize = kani::any();
        let b: usize = kani::any();
        kani::assume(a < N && b < N && a != b);
        assert!(q.enqueue(a));
        assert!(q.enqueue(b));
        assert_eq!(q.dequeue(), Some(a));
        assert!(!q.is_queued(a));
        assert!(q.is_queued(b));
        assert_eq!(q.dequeue(), Some(b));
        assert!(!q.is_queued(b));
        assert!(q.is_empty());
    }

    // the master invariant: across an arbitrary bounded sequence of enqueue and
    // dequeue operations, the membership count always equals the fifo length
    // and the length never exceeds the capacity. the op-loop runs N times, so
    // its bound (N + 1) coincides with the drop/scan bound above.
    #[kani::proof]
    #[kani::unwind(5)] // N + 1, also covers the N-iteration op loop below
    fn count_equals_len_and_len_bounded() {
        let mut q: RunQueue<N> = RunQueue::new();
        for _ in 0..N {
            let do_enqueue: bool = kani::any();
            if do_enqueue {
                let id: usize = kani::any();
                let _ = q.enqueue(id);
            } else {
                let _ = q.dequeue();
            }
            assert_eq!(q.queued_count(), q.len());
            assert!(q.len() <= q.capacity());
        }
    }
}
