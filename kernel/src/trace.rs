//! In-kernel structured tracing: a per-CPU ring buffer of syscall events.
//!
//! Because every capability operation from userspace crosses the syscall
//! boundary, the syscall dispatcher is a mandatory chokepoint (VISION star 5:
//! the kernel is where you tap traces, inject faults, and record the input
//! stream for replay). This module taps that chokepoint: it records one
//! [`SyscallEvent`] per dispatched syscall into a bounded ring buffer, so the
//! most recent events are always available for inspection, and an ordered drain
//! of them is the record half of record/replay on real hardware.
//!
//! # Design
//!
//! The store is the Kani-verified [`RingBuffer`], which never allocates and
//! whose bounded-FIFO invariant is already proven. `RingBuffer::push` refuses
//! when full (it never overwrites), which is the right primitive for a queue but
//! the wrong policy for a trace: a trace should keep the most *recent* events
//! and drop the oldest, never go deaf once it fills. [`TraceBuffer::record`]
//! gets that overwrite-oldest policy by popping the oldest event before pushing
//! when the buffer is full, leaving the verified buffer's own invariant intact
//! and counting how many events were displaced.
//!
//! # Per-CPU framing
//!
//! jos runs one userspace thread at a time today, so there is a single global
//! buffer behind a lock, conceptually CPU 0's. The interface ([`record`],
//! [`with_buffer`]) is written so that moving to a genuine per-CPU buffer later
//! (addressed through the [`crate::cpu_local`] block, no lock needed since a CPU
//! only touches its own) is a change of where the buffer lives, not of how it is
//! used.

use jos_core::ring_buffer::RingBuffer;
use jos_core::trace::SyscallEvent;
use spin::Mutex;

/// Number of syscall events retained per CPU. A power of two so the ring
/// buffer's index arithmetic stays a cheap mask, and small: a trace ring keeps a
/// recent window, not unbounded history.
pub const TRACE_CAPACITY: usize = 64;

/// A bounded, overwrite-oldest log of [`SyscallEvent`]s with a monotone sequence
/// counter.
///
/// Wraps the verified [`RingBuffer`]; see the module docs for why the
/// overwrite-oldest policy lives here rather than in the buffer.
pub struct TraceBuffer {
    events: RingBuffer<SyscallEvent, TRACE_CAPACITY>,
    // sequence number assigned to the next recorded event. monotone for the
    // life of the buffer (never reset on overwrite), so it is a total order over
    // every event ever recorded, not just those still retained.
    next_seq: u64,
    // count of events dropped because the buffer was full when a newer event
    // arrived. nonzero means the retained window does not start at seq 0, so a
    // consumer knows the trace has gaps at the old end.
    dropped: u64,
}

impl TraceBuffer {
    /// Creates an empty trace buffer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            events: RingBuffer::new(),
            next_seq: 0,
            dropped: 0,
        }
    }

    /// Records a syscall crossing the boundary, assigning it the next sequence
    /// number, and returns the recorded event.
    ///
    /// Overwrite-oldest: if the buffer is full, the oldest retained event is
    /// dropped (and counted in [`dropped`](Self::dropped)) to make room, so a
    /// busy syscall stream never silences tracing.
    pub fn record(&mut self, syscall: u64, args: [u64; 3], result: u64) -> SyscallEvent {
        let event = SyscallEvent::new(self.next_seq, syscall, args, result);
        // monotone: advance even on wrap, so seq is a global order. saturating so
        // a (practically unreachable) overflow degrades to a stuck counter rather
        // than wrapping a "later" event to an "earlier" seq.
        self.next_seq = self.next_seq.saturating_add(1);
        if self.events.is_full() {
            // drop the oldest to make room; the pop always succeeds here because
            // the buffer is full (hence non-empty).
            let _ = self.events.pop();
            self.dropped = self.dropped.saturating_add(1);
        }
        // push now always succeeds: either the buffer had room, or we just freed
        // a slot. the verified buffer still returns a Result, so handle it rather
        // than unwrap (a push failure here would be a logic error, not reachable).
        let _ = self.events.push(event);
        event
    }

    /// Returns the number of events currently retained.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns `true` if no events are retained.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Returns the sequence number the next recorded event will receive (also
    /// the total number of events ever recorded, barring counter saturation).
    #[inline]
    #[must_use]
    pub const fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Returns how many events were dropped (overwritten) because the buffer was
    /// full. Nonzero means the retained window has been trimmed at the old end.
    #[inline]
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Removes and returns the oldest retained event, or `None` if empty.
    ///
    /// Draining in a loop yields the retained events in the order they were
    /// recorded (ascending sequence number), which is the replay order.
    pub fn drain_oldest(&mut self) -> Option<SyscallEvent> {
        self.events.pop()
    }
}

impl Default for TraceBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// the single global trace buffer (conceptually CPU 0's). RingBuffer::new is a
// const fn, so this initializes at compile time with no runtime setup. behind a
// spin::Mutex because a syscall and a test-side drain both reach it; on
// single-CPU jos the lock is uncontended.
static TRACE: Mutex<TraceBuffer> = Mutex::new(TraceBuffer::new());

/// Records a syscall event into the current CPU's trace buffer.
///
/// Called from the syscall dispatcher with the raw ABI values. Returns the
/// recorded event (with its assigned sequence number) so a caller that also
/// wants to act on the structured record need not re-read it.
pub fn record(syscall: u64, args: [u64; 3], result: u64) -> SyscallEvent {
    TRACE.lock().record(syscall, args, result)
}

/// Runs `f` with exclusive access to the current CPU's trace buffer.
///
/// The inspection entry point (drain the log, read `len` / `dropped`), used by
/// tests and by any future trace consumer. Keeps the static private so all
/// access goes through the locked accessor.
pub fn with_buffer<R>(f: impl FnOnce(&mut TraceBuffer) -> R) -> R {
    f(&mut TRACE.lock())
}

#[cfg(test)]
mod tests {
    use super::{TraceBuffer, TRACE_CAPACITY};

    #[test_case]
    fn records_in_order_with_monotone_seq() {
        let mut buf = TraceBuffer::new();
        for i in 0..5 {
            let ev = buf.record(i, [i, 0, 0], i * 10);
            assert_eq!(ev.seq, i, "seq should match record order");
        }
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.next_seq(), 5);
        assert_eq!(buf.dropped(), 0);
        // draining yields ascending seq (recording order = replay order).
        for i in 0..5 {
            let ev = buf.drain_oldest().expect("event present");
            assert_eq!(ev.seq, i);
            assert_eq!(ev.syscall, i);
            assert_eq!(ev.result, i * 10);
        }
        assert!(buf.drain_oldest().is_none());
    }

    #[test_case]
    fn overwrites_oldest_when_full() {
        let mut buf = TraceBuffer::new();
        // record one full buffer plus three more, forcing three overwrites.
        let total = (TRACE_CAPACITY + 3) as u64;
        for i in 0..total {
            buf.record(i, [0, 0, 0], 0);
        }
        // capacity is unchanged; the three oldest were dropped.
        assert_eq!(buf.len(), TRACE_CAPACITY);
        assert_eq!(buf.dropped(), 3);
        assert_eq!(buf.next_seq(), total);
        // the oldest retained event is seq 3 (0,1,2 were overwritten); seq stays
        // monotone across the wrap.
        let oldest = buf.drain_oldest().expect("event present");
        assert_eq!(oldest.seq, 3, "the three oldest events should have been dropped");
    }

    #[test_case]
    fn seq_is_a_total_order_across_overwrite() {
        // even after wrapping, draining gives strictly increasing seq: the trace
        // is a coherent suffix of the global event order, never reordered.
        let mut buf = TraceBuffer::new();
        for i in 0..(TRACE_CAPACITY as u64 * 2) {
            buf.record(i, [0, 0, 0], 0);
        }
        let mut last = None;
        while let Some(ev) = buf.drain_oldest() {
            if let Some(prev) = last {
                assert!(ev.seq > prev, "seq must be strictly increasing on drain");
            }
            last = Some(ev.seq);
        }
    }
}
