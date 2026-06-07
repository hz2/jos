//! Pluggable scheduling policy trait and built-in implementations.
//!
//! The trait is hardware-free so each policy can be tested with host `cargo
//! test`, exercised under Miri for UB, and model-checked with Kani. The
//! kernel's `sched` module picks a concrete policy via a type alias:
//!
//! ```ignore
//! type Policy = RoundRobin<MAX_THREADS>;
//! static POLICY: Mutex<Policy> = Mutex::new(RoundRobin::new());
//! ```
//!
//! Switching to a different policy means changing that one line.

use crate::run_queue::RunQueue;

/// Decides which thread runs next.
///
/// Implementors own a ready set of thread IDs in `[0, N)` and return one on
/// each call to [`dequeue`](SchedPolicy::dequeue). The interface is
/// intentionally minimal: blocking and priority are policy details, not trait
/// requirements. Blocking IPC will `remove` a thread when it parks and
/// `enqueue` it again when the counterpart arrives.
pub trait SchedPolicy {
    /// Add `id` to the ready set. Idempotent; already-ready IDs are ignored.
    fn enqueue(&mut self, id: usize);

    /// Remove and return the next thread ID, or `None` if the ready set is
    /// empty. The returned ID leaves the ready set until re-enqueued.
    fn dequeue(&mut self) -> Option<usize>;

    /// Returns `true` if `id` is currently in the ready set.
    fn is_ready(&self, id: usize) -> bool;
}

/// Round-robin policy backed by the dedup-FIFO [`RunQueue`].
///
/// Each dequeue returns the thread that has been waiting longest. Re-enqueueing
/// the dequeued thread places it at the back, giving every thread equal time
/// in arrival order. Starvation-freedom follows from the dedup invariant: each
/// ID appears at most once, so N dequeues cover every ready thread.
pub struct RoundRobin<const N: usize> {
    queue: RunQueue<N>,
}

impl<const N: usize> RoundRobin<N> {
    /// Creates an empty round-robin scheduler.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            queue: RunQueue::new(),
        }
    }
}

impl<const N: usize> Default for RoundRobin<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> SchedPolicy for RoundRobin<N> {
    fn enqueue(&mut self, id: usize) {
        self.queue.enqueue(id);
    }

    fn dequeue(&mut self) -> Option<usize> {
        self.queue.dequeue()
    }

    fn is_ready(&self, id: usize) -> bool {
        self.queue.is_queued(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_robin_fifo_order() {
        let mut p: RoundRobin<4> = RoundRobin::new();
        p.enqueue(2);
        p.enqueue(0);
        p.enqueue(3);
        assert_eq!(p.dequeue(), Some(2));
        assert_eq!(p.dequeue(), Some(0));
        assert_eq!(p.dequeue(), Some(3));
        assert_eq!(p.dequeue(), None);
    }

    #[test]
    fn round_robin_idempotent_enqueue() {
        let mut p: RoundRobin<4> = RoundRobin::new();
        p.enqueue(1);
        p.enqueue(1);
        assert_eq!(p.dequeue(), Some(1));
        assert_eq!(p.dequeue(), None);
    }

    #[test]
    fn is_ready_tracks_membership() {
        let mut p: RoundRobin<4> = RoundRobin::new();
        assert!(!p.is_ready(0));
        p.enqueue(0);
        assert!(p.is_ready(0));
        p.dequeue();
        assert!(!p.is_ready(0));
    }
}
