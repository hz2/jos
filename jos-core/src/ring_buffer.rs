//! Bounded SPSC ring buffer backed by a fixed-size `MaybeUninit` array.
//!
//! # Invariant
//!
//! The buffer maintains three fields: `head`, `tail`, and `len`.
//!
//! - `len` is the number of live (initialized) elements, always in `[0, N]`.
//! - `head` is the index where the *next push* will write, always in `[0, N)`.
//! - `tail` is the index where the *next pop* will read, always in `[0, N)`.
//!
//! The relationship is: `tail == head` when `len == 0` or `len == N`.
//! Live elements occupy indices `tail, (tail+1)%N, ..., (tail+len-1)%N`.
//! At any moment exactly `len` slots in `storage` are initialized; no other
//! slot is ever read as a `T`.
//!
//! Both `head` and `tail` are incremented modulo `N` on every push/pop
//! respectively, so they wrap around without any power-of-two requirement.
//! `len` is the sole source of truth for empty/full; comparing `head` and
//! `tail` alone is ambiguous (both cases look identical: `head == tail`).

use core::mem::MaybeUninit;

/// A bounded, first-in first-out ring buffer of at most `N` elements.
///
/// `T` does not need to be `Copy`. Ownership of each element is transferred
/// on push and returned on pop. When the buffer is dropped, all live elements
/// are dropped in tail-to-head order.
pub struct RingBuffer<T, const N: usize> {
    // backing storage; only indices in the live window are initialized.
    storage: [MaybeUninit<T>; N],
    // index of the slot that will be written on the next push.
    head: usize,
    // index of the slot that will be read on the next pop.
    tail: usize,
    // number of initialized elements currently in the buffer.
    len: usize,
}

impl<T, const N: usize> RingBuffer<T, N> {
    /// Creates an empty ring buffer.
    ///
    /// `const` construction is available because `MaybeUninit::uninit()` is
    /// a const fn and the index fields are plain integers.
    #[must_use]
    pub const fn new() -> Self {
        // building an array of uninit MaybeUninit is safe (no unsafe needed):
        // MaybeUninit makes the uninitialized state explicit in the type. we
        // never read a slot until push() has written it, so uninitialized
        // bytes are never observed as a T.
        let storage = [const { MaybeUninit::uninit() }; N];
        Self {
            storage,
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    /// Returns the maximum number of elements the buffer can hold.
    ///
    /// This is always equal to `N`.
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Returns the number of elements currently in the buffer.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the buffer contains no elements.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` if the buffer has no remaining capacity.
    #[inline]
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.len == N
    }

    /// Pushes `value` onto the back of the buffer.
    ///
    /// Returns `Err(value)` without modifying the buffer if it is full,
    /// preserving ownership of the rejected value.
    ///
    /// # Errors
    ///
    /// Returns `Err(value)` when the buffer is at capacity.
    pub fn push(&mut self, value: T) -> Result<(), T> {
        if self.is_full() {
            return Err(value);
        }
        // head is always in [0, N) by construction; the slot at head is
        // uninitialized (no live element occupies it) because len < N
        // guarantees a free slot at the head position per the module invariant.
        // MaybeUninit::write is a safe method; no unsafe block required here.
        self.storage[self.head].write(value);
        self.head = (self.head + 1) % N;
        self.len += 1;
        Ok(())
    }

    /// Removes and returns the element at the front of the buffer.
    ///
    /// Returns `None` if the buffer is empty.
    pub fn pop(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }
        // SAFETY: tail is always in [0, N) by construction; because len > 0
        // the invariant guarantees the slot at tail holds a live, initialized
        // T that we now take ownership of. after this read the slot becomes
        // uninitialized and tail advances past it so it will not be read again
        // until a subsequent push initializes it.
        let value = unsafe { self.storage[self.tail].assume_init_read() };
        self.tail = (self.tail + 1) % N;
        self.len -= 1;
        Some(value)
    }
}

impl<T, const N: usize> Drop for RingBuffer<T, N> {
    fn drop(&mut self) {
        // drop every live element in fifo order. we use assume_init_drop
        // rather than assume_init_read + implicit drop so that the compiler
        // can elide the move when T is large; correctness is identical.
        for i in 0..self.len {
            let idx = (self.tail + i) % N;
            // SAFETY: the loop visits exactly the live indices once each.
            // tail through tail+len-1 (mod N) are the only initialized slots
            // per the module invariant, so every assume_init_drop call here
            // targets a distinct, initialized element.
            unsafe {
                self.storage[idx].assume_init_drop();
            }
        }
    }
}

// default is a natural alias for new() when N is known.
impl<T, const N: usize> Default for RingBuffer<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::RingBuffer;
    use core::sync::atomic::{AtomicUsize, Ordering};

    // helper: a value that increments a shared counter when dropped.
    // Debug is derived so that push(...).unwrap() compiles (unwrap requires
    // E: Debug; the Err variant here is Dropper itself).
    #[derive(Debug)]
    struct Dropper<'a> {
        counter: &'a AtomicUsize,
    }
    impl Drop for Dropper<'_> {
        fn drop(&mut self) {
            self.counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    // --- basic capacity / state tests ---

    #[test]
    fn new_buffer_is_empty() {
        let buf: RingBuffer<u32, 4> = RingBuffer::new();
        assert!(buf.is_empty());
        assert!(!buf.is_full());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.capacity(), 4);
    }

    #[test]
    fn single_push_pop_roundtrip() {
        let mut buf: RingBuffer<u32, 4> = RingBuffer::new();
        assert!(buf.push(42).is_ok());
        assert_eq!(buf.len(), 1);
        assert!(!buf.is_empty());
        assert_eq!(buf.pop(), Some(42));
        assert!(buf.is_empty());
    }

    #[test]
    fn push_until_full() {
        let mut buf: RingBuffer<u32, 3> = RingBuffer::new();
        assert!(buf.push(1).is_ok());
        assert!(buf.push(2).is_ok());
        assert!(buf.push(3).is_ok());
        assert!(buf.is_full());
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn push_on_full_returns_err_with_value() {
        let mut buf: RingBuffer<u32, 2> = RingBuffer::new();
        buf.push(10).unwrap();
        buf.push(20).unwrap();
        let rejected = buf.push(99);
        assert_eq!(rejected, Err(99));
        // buffer state unchanged
        assert!(buf.is_full());
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn pop_on_empty_returns_none() {
        let mut buf: RingBuffer<u32, 4> = RingBuffer::new();
        assert_eq!(buf.pop(), None);
        assert_eq!(buf.len(), 0);
    }

    // --- fifo ordering ---

    #[test]
    fn fifo_ordering() {
        let mut buf: RingBuffer<u32, 8> = RingBuffer::new();
        for i in 0..8_u32 {
            buf.push(i).unwrap();
        }
        for i in 0..8_u32 {
            assert_eq!(buf.pop(), Some(i));
        }
        assert!(buf.is_empty());
    }

    // --- wraparound: push/pop cycles that loop the indices past N many times ---

    #[test]
    fn wraparound_many_cycles() {
        const CAP: usize = 4;
        let mut buf: RingBuffer<u32, CAP> = RingBuffer::new();
        // run 5 * CAP push/pop pairs so head and tail wrap multiple times.
        for round in 0..(5 * CAP) {
            let value = u32::try_from(round).unwrap();
            assert!(buf.push(value).is_ok());
            assert_eq!(buf.pop(), Some(value));
        }
        assert!(buf.is_empty());
    }

    #[test]
    fn wraparound_partial_fill() {
        const CAP: usize = 4;
        let mut buf: RingBuffer<u32, CAP> = RingBuffer::new();
        // fill halfway, drain, repeat many times to exercise index wrap.
        for cycle in 0_u32..20 {
            for i in 0..2_u32 {
                buf.push(cycle * 100 + i).unwrap();
            }
            for i in 0..2_u32 {
                assert_eq!(buf.pop(), Some(cycle * 100 + i));
            }
        }
        assert!(buf.is_empty());
    }

    // --- drop correctness ---

    #[test]
    fn drop_on_nonempty_buffer_drops_all_elements() {
        let counter = AtomicUsize::new(0);
        {
            let mut buf: RingBuffer<Dropper<'_>, 4> = RingBuffer::new();
            buf.push(Dropper { counter: &counter }).unwrap();
            buf.push(Dropper { counter: &counter }).unwrap();
            buf.push(Dropper { counter: &counter }).unwrap();
            // pop one so we exercise a non-zero tail at drop time.
            let _popped = buf.pop(); // drops when _popped goes out of scope
            // buf holds 2 live elements; _popped holds 1
        }
        // all 3 droppers must have fired exactly once.
        assert_eq!(counter.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn no_double_drop_after_pop() {
        let counter = AtomicUsize::new(0);
        {
            let mut buf: RingBuffer<Dropper<'_>, 4> = RingBuffer::new();
            buf.push(Dropper { counter: &counter }).unwrap();
            let popped = buf.pop().unwrap(); // take ownership
            drop(popped); // explicit drop: counter -> 1
            // buf is now empty, its drop should not fire any more droppers.
        }
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn drop_wraps_correctly() {
        // push 4, pop 2 (tail = 2), push 2 more (head wraps to 0 when N=4).
        // live elements are at indices 2, 3, 0, 1 -- crosses the array boundary.
        let counter = AtomicUsize::new(0);
        {
            let mut buf: RingBuffer<Dropper<'_>, 4> = RingBuffer::new();
            for _ in 0..4 {
                buf.push(Dropper { counter: &counter }).unwrap();
            }
            // pop two and drop them immediately.
            drop(buf.pop().unwrap());
            drop(buf.pop().unwrap());
            assert_eq!(counter.load(Ordering::Relaxed), 2);
            // push two more so the live window straddles the array boundary.
            buf.push(Dropper { counter: &counter }).unwrap();
            buf.push(Dropper { counter: &counter }).unwrap();
            // buf now holds 4 elements; dropping buf must fire 4 more.
        }
        assert_eq!(counter.load(Ordering::Relaxed), 6); // 2 manual + 4 from drop
    }

    // --- zero-capacity edge case ---

    #[test]
    fn zero_capacity_is_always_full_and_empty() {
        // a RingBuffer<T, 0> is simultaneously empty and full per the invariant:
        // len==0 => is_empty, len==N==0 => is_full.
        let mut buf: RingBuffer<u32, 0> = RingBuffer::new();
        assert!(buf.is_empty());
        assert!(buf.is_full());
        assert_eq!(buf.pop(), None);
        assert_eq!(buf.push(1), Err(1));
    }

    // --- size-1 edge case ---

    #[test]
    fn size_one_buffer() {
        let mut buf: RingBuffer<u32, 1> = RingBuffer::new();
        assert!(buf.push(7).is_ok());
        assert!(buf.is_full());
        assert_eq!(buf.push(8), Err(8));
        assert_eq!(buf.pop(), Some(7));
        assert!(buf.is_empty());
        // reuse after drain
        assert!(buf.push(99).is_ok());
        assert_eq!(buf.pop(), Some(99));
    }

    // --- default() delegates to new() ---

    #[test]
    fn default_equals_new() {
        let buf: RingBuffer<u32, 4> = RingBuffer::default();
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), 4);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::RingBuffer;

    // prove that push followed immediately by pop on a fresh buffer recovers
    // the exact value that was pushed.
    #[kani::proof]
    fn push_then_pop_identity() {
        // kani will enumerate all u32 values symbolically.
        let value: u32 = kani::any();
        let mut buf: RingBuffer<u32, 4> = RingBuffer::new();
        // buffer starts empty, so push must succeed.
        let result = buf.push(value);
        assert!(result.is_ok());
        let popped = buf.pop();
        assert!(popped == Some(value));
    }

    // prove that len is always <= capacity after a bounded sequence of
    // alternating pushes and pops, with arbitrary values.
    #[kani::proof]
    #[kani::unwind(9)] // 4 pushes + 4 pops + 1 extra check = 9 iterations max
    fn len_never_exceeds_capacity() {
        let mut buf: RingBuffer<u32, 4> = RingBuffer::new();
        // perform up to 4 push/pop operations symbolically.
        for _ in 0..4_usize {
            let do_push: bool = kani::any();
            if do_push {
                let v: u32 = kani::any();
                let _ = buf.push(v);
            } else {
                let _ = buf.pop();
            }
            // invariant: len is always in [0, capacity].
            assert!(buf.len() <= buf.capacity());
        }
    }

    // prove that an empty buffer always returns None from pop.
    #[kani::proof]
    fn empty_pop_is_none() {
        let mut buf: RingBuffer<u32, 4> = RingBuffer::new();
        assert!(buf.is_empty());
        assert!(buf.pop().is_none());
    }

    // prove that a full buffer always rejects push with the original value.
    #[kani::proof]
    fn full_push_returns_err() {
        let mut buf: RingBuffer<u32, 2> = RingBuffer::new();
        buf.push(1).unwrap();
        buf.push(2).unwrap();
        assert!(buf.is_full());
        let v: u32 = kani::any();
        let result = buf.push(v);
        assert!(result == Err(v));
    }

    // prove fifo ordering for a two-element sequence.
    #[kani::proof]
    fn two_element_fifo_order() {
        let a: u32 = kani::any();
        let b: u32 = kani::any();
        let mut buf: RingBuffer<u32, 4> = RingBuffer::new();
        buf.push(a).unwrap();
        buf.push(b).unwrap();
        assert!(buf.pop() == Some(a));
        assert!(buf.pop() == Some(b));
    }
}
