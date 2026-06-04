//! Bitmap frame allocator -- pure logic, no hardware.
//!
//! Each bit in the backing `u64` slice represents one physical page frame.
//!
//! # Bit polarity
//!
//! `1` means the frame is **used**; `0` means it is **free**.
//! This matches the convention used in the Verus-verified `BitMap` reference
//! and makes `alloc` a "find first zero" scan, which is easy to verify later
//! with the `integer_ring` / bit-vector arithmetic proofs.
//!
//! # Struct shape
//!
//! `Bitmap<'a>` borrows a `&'a mut [u64]` rather than owning a const-generic
//! array.  A real frame allocator receives its backing store from a fixed
//! memory region carved out during early boot; that region is a runtime-sized
//! slice, not a compile-time constant.  The borrowed form also avoids
//! monomorphising the entire allocator for every possible size.
//!
//! # Invariants
//!
//! 1. `len_bits <= words.len() * 64` -- every tracked bit has a backing word.
//! 2. Bits in `[len_bits, words.len()*64)` ("tail padding") are always `1`
//!    (marked used) so that `alloc` never returns an out-of-range index.
//! 3. `word_index(idx)  = idx / 64 < words.len()` for any `idx < len_bits`.
//! 4. `bit_index(idx)   = idx % 64 < 64`          for any valid `idx`.
//!
//! These four properties are the exact arithmetic lemmas that Verus
//! `integer_ring` and `bit_vector` proofs will later discharge formally.

/// The number of bits packed into one backing word.
const BITS_PER_WORD: usize = 64;

// ---------------------------------------------------------------------------
// index helpers -- kept as tiny fns so the Verus proof target is clear later
// ---------------------------------------------------------------------------

/// Returns the index of the `u64` word that contains bit `idx`.
#[inline]
const fn word_index(idx: usize) -> usize {
    idx / BITS_PER_WORD
}

/// Returns which bit within its word corresponds to `idx`.
///
/// The result is always in `0..64`, a property that the later Verus
/// `integer_ring` proof will discharge formally.
#[inline]
const fn bit_index(idx: usize) -> usize {
    idx % BITS_PER_WORD
}

/// Returns a mask with exactly the one bit that represents `idx` set.
#[inline]
const fn bit_mask(idx: usize) -> u64 {
    1u64 << bit_index(idx)
}

// ---------------------------------------------------------------------------
// Bitmap
// ---------------------------------------------------------------------------

/// A fixed-capacity bitmap backed by a borrowed slice of `u64` words.
///
/// `1` = used, `0` = free (see module-level docs for rationale).
pub struct Bitmap<'a> {
    /// Backing storage; `words[word_index(i)]` holds bit `i`.
    words: &'a mut [u64],
    /// Number of bits this bitmap logically tracks.
    ///
    /// Must satisfy `len_bits <= words.len() * 64`.
    len_bits: usize,
}

impl<'a> Bitmap<'a> {
    /// Creates a new `Bitmap` from `words` tracking `len_bits` frames.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `len_bits > words.len() * 64`.
    ///
    /// # Postcondition
    ///
    /// All `len_bits` frames are initially **free** (all bits zero).
    /// Tail-padding bits (beyond `len_bits`) are set to `1` so that
    /// `alloc` never returns an out-of-range index.
    pub fn new(words: &'a mut [u64], len_bits: usize) -> Self {
        debug_assert!(
            len_bits <= words.len() * BITS_PER_WORD,
            "len_bits exceeds backing storage capacity"
        );

        // zero all words -- all frames start free
        for w in words.iter_mut() {
            *w = 0;
        }

        let mut bm = Bitmap { words, len_bits };

        // mark tail-padding bits as used so alloc never escapes [0, len_bits)
        bm.seal_tail();
        bm
    }

    /// Returns the total number of bits this bitmap tracks.
    #[must_use]
    #[inline]
    pub fn len_bits(&self) -> usize {
        self.len_bits
    }

    /// Returns `true` if the bitmap tracks zero frames.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len_bits == 0
    }

    // -----------------------------------------------------------------------
    // primitive bit operations
    // -----------------------------------------------------------------------

    /// Returns `true` if frame `idx` is currently **used**.
    ///
    /// # Precondition
    ///
    /// `idx < len_bits`
    #[must_use]
    #[inline]
    pub fn get(&self, idx: usize) -> bool {
        debug_assert!(idx < self.len_bits, "get: idx out of bounds");
        let word = self.words[word_index(idx)];
        (word & bit_mask(idx)) != 0
    }

    /// Marks frame `idx` as **used**.
    ///
    /// # Precondition
    ///
    /// `idx < len_bits`
    #[inline]
    pub fn set(&mut self, idx: usize) {
        debug_assert!(idx < self.len_bits, "set: idx out of bounds");
        self.words[word_index(idx)] |= bit_mask(idx);
    }

    /// Marks frame `idx` as **free**.
    ///
    /// # Precondition
    ///
    /// `idx < len_bits`
    #[inline]
    pub fn clear(&mut self, idx: usize) {
        debug_assert!(idx < self.len_bits, "clear: idx out of bounds");
        self.words[word_index(idx)] &= !bit_mask(idx);
    }

    // -----------------------------------------------------------------------
    // allocator operations
    // -----------------------------------------------------------------------

    /// Marks frame `idx` free.
    ///
    /// # Precondition
    ///
    /// `idx < len_bits`.  Double-free is detected in debug builds.
    pub fn free(&mut self, idx: usize) {
        debug_assert!(idx < self.len_bits, "free: idx out of bounds");
        debug_assert!(self.get(idx), "free: double-free detected at idx {idx}");
        self.clear(idx);
    }

    /// Finds the first free frame, marks it used, and returns its index.
    ///
    /// Returns `None` if no free frames remain.
    pub fn alloc(&mut self) -> Option<usize> {
        for word_idx in 0..self.words.len() {
            let word = self.words[word_idx];
            if word == u64::MAX {
                // all 64 bits are used -- skip whole word
                continue;
            }
            // trailing_ones gives the position of the lowest zero bit
            let bit_pos = word.trailing_ones() as usize;
            let frame_idx = word_idx * BITS_PER_WORD + bit_pos;
            if frame_idx < self.len_bits {
                // set the bit before returning
                self.words[word_idx] |= 1u64 << bit_pos;
                return Some(frame_idx);
            }
        }
        None
    }

    /// Finds `count` consecutive free frames, marks them all used, and returns
    /// the index of the first frame.
    ///
    /// Returns `None` if no such run exists.
    ///
    /// This is the straightforward O(n * count) scan; correctness over
    /// efficiency at this stage.
    pub fn alloc_contiguous(&mut self, count: usize) -> Option<usize> {
        if count == 0 {
            return Some(0);
        }
        if count > self.len_bits {
            return None;
        }

        // search for a run of `count` consecutive zeros
        let limit = self.len_bits - count;
        let mut start = 0usize;
        'outer: while start <= limit {
            // check whether [start, start+count) is all free
            for offset in 0..count {
                if self.get(start + offset) {
                    // this bit is used; advance start past it
                    start += offset + 1;
                    continue 'outer;
                }
            }
            // found a free run -- mark them all used
            for offset in 0..count {
                self.set(start + offset);
            }
            return Some(start);
        }
        None
    }

    /// Returns the number of free frames (bits equal to `0`).
    #[must_use]
    pub fn count_free(&self) -> usize {
        // count ones across all words, which includes both real "used" bits
        // and tail-padding bits (forced to 1).  subtract padding to get the
        // number of real used bits, then derive free from len_bits.
        let total_ones: usize = self
            .words
            .iter()
            .map(|w| w.count_ones() as usize)
            .sum();
        // saturating_sub: under the seal_tail invariant every padding bit is 1,
        // so total_ones >= tail_padding_count and this never saturates. the
        // saturating form makes count_free total (no underflow panic) even for a
        // bitmap whose tail was not sealed, which is what kani proved we need.
        let real_used = total_ones.saturating_sub(self.tail_padding_count());
        self.len_bits - real_used
    }

    /// Returns the number of used frames (bits equal to `1`, excluding padding).
    #[must_use]
    pub fn count_used(&self) -> usize {
        self.len_bits - self.count_free()
    }

    // -----------------------------------------------------------------------
    // internal helpers
    // -----------------------------------------------------------------------

    /// Number of tail-padding bits that are always forced to `1`.
    fn tail_padding_count(&self) -> usize {
        self.words.len() * BITS_PER_WORD - self.len_bits
    }

    /// Forces all bits in `[len_bits, words.len()*64)` to `1` so that `alloc`
    /// will never return an out-of-range index even if a word scan overshoots.
    fn seal_tail(&mut self) {
        let padding = self.tail_padding_count();
        if padding == 0 {
            return;
        }
        // the last word may be partially used by real bits
        let last_word = self.words.len() - 1;
        let real_bits_in_last_word = self.len_bits % BITS_PER_WORD;
        if real_bits_in_last_word == 0 {
            // all bits in the last word are padding -- fill entirely
            self.words[last_word] = u64::MAX;
        } else {
            // mask covering the bits above the last real bit
            let tail_mask = !((1u64 << real_bits_in_last_word) - 1);
            self.words[last_word] |= tail_mask;
        }
        // any words beyond the last word that were zeroed should be all-ones
        // (this can't happen if len_bits >= (words.len()-1)*64, but be safe)
        for w in &mut self.words[last_word + 1..] {
            *w = u64::MAX;
        }
    }
}

// ---------------------------------------------------------------------------
// unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // test harness links std, so we can use std::vec here even though the
    // library itself is no_std
    extern crate std;

    // helper: allocate backing storage for a small bitmap
    fn make_words(n_words: usize) -> std::vec::Vec<u64> {
        std::vec![0u64; n_words]
    }

    // ------------------------------------------------------------------
    // basic set / get / clear round-trips
    // ------------------------------------------------------------------

    #[test]
    fn set_get_clear() {
        let mut storage = make_words(1);
        let mut bm = Bitmap::new(&mut storage, 64);

        assert!(!bm.get(0));
        assert!(!bm.get(63));

        bm.set(0);
        assert!(bm.get(0));
        assert!(!bm.get(1));

        bm.set(63);
        assert!(bm.get(63));

        bm.clear(0);
        assert!(!bm.get(0));
        assert!(bm.get(63));

        bm.clear(63);
        assert!(!bm.get(63));
    }

    // ------------------------------------------------------------------
    // alloc until full, then None
    // ------------------------------------------------------------------

    #[test]
    fn alloc_until_full() {
        const N: usize = 130;
        let mut storage = make_words((N + 63) / 64);
        let mut bm = Bitmap::new(&mut storage, N);

        for expected in 0..N {
            let got = bm.alloc().expect("should have free frames");
            assert_eq!(got, expected, "alloc should return lowest free frame");
        }
        assert!(bm.alloc().is_none(), "bitmap is full -- should return None");
    }

    // ------------------------------------------------------------------
    // free then re-alloc reuses the released slot
    // ------------------------------------------------------------------

    #[test]
    fn free_then_realloc() {
        let mut storage = make_words(2);
        let mut bm = Bitmap::new(&mut storage, 128);

        // alloc the first 10 frames
        for _ in 0..10 {
            bm.alloc().unwrap();
        }
        assert_eq!(bm.count_free(), 118);

        // free frame 3
        bm.free(3);
        assert_eq!(bm.count_free(), 119);

        // next alloc must reuse frame 3 (lowest free)
        assert_eq!(bm.alloc().unwrap(), 3);
        assert_eq!(bm.count_free(), 118);
    }

    // ------------------------------------------------------------------
    // conservation invariant: count_free + count_used == len_bits
    // ------------------------------------------------------------------

    #[test]
    fn conservation_after_op_sequence() {
        const N: usize = 200;
        let mut storage = make_words((N + 63) / 64);
        let mut bm = Bitmap::new(&mut storage, N);

        let check = |bm: &Bitmap| {
            let free = bm.count_free();
            let used = bm.count_used();
            assert_eq!(free + used, N, "conservation violated: free={free} used={used}");
        };

        check(&bm);

        // alloc 100 frames one by one
        let mut allocated = std::vec::Vec::new();
        for _ in 0..100 {
            let idx = bm.alloc().unwrap();
            allocated.push(idx);
            check(&bm);
        }
        assert_eq!(bm.count_used(), 100);

        // free every other allocated frame
        for &idx in allocated.iter().step_by(2) {
            bm.free(idx);
            check(&bm);
        }
        assert_eq!(bm.count_used(), 50);

        // re-alloc 10 more
        for _ in 0..10 {
            bm.alloc().unwrap();
            check(&bm);
        }
    }

    // ------------------------------------------------------------------
    // alloc_contiguous across word boundaries (bits 62,63,64,65)
    // ------------------------------------------------------------------

    #[test]
    fn contiguous_across_word_boundary() {
        let mut storage = make_words(3);
        let mut bm = Bitmap::new(&mut storage, 192);

        // alloc frames 0..62 to push the free region near the boundary
        for _ in 0..62 {
            bm.alloc().unwrap();
        }
        // frames 62,63,64,65 are now free; ask for 4 consecutive
        let start = bm
            .alloc_contiguous(4)
            .expect("should find 4 consecutive frames at boundary");
        assert_eq!(start, 62, "run should start at bit 62");

        // those four frames are now used
        for i in 62..66 {
            assert!(bm.get(i), "frame {i} should be used");
        }
        // frame 66 is still free
        assert!(!bm.get(66));
    }

    #[test]
    fn contiguous_none_when_full() {
        let mut storage = make_words(1);
        let mut bm = Bitmap::new(&mut storage, 64);

        // fill completely
        for _ in 0..64 {
            bm.alloc().unwrap();
        }
        assert!(bm.alloc_contiguous(1).is_none());
    }

    #[test]
    fn contiguous_fragmented_fails() {
        let mut storage = make_words(1);
        let mut bm = Bitmap::new(&mut storage, 64);

        // alloc then free alternating bits: every even bit is free, every odd used
        for i in 0..64 {
            bm.set(i);
        }
        for i in (0..64).step_by(2) {
            bm.clear(i);
        }
        // no 2-consecutive free bits exist
        assert!(bm.alloc_contiguous(2).is_none());
    }

    #[test]
    fn contiguous_zero_count() {
        let mut storage = make_words(1);
        let mut bm = Bitmap::new(&mut storage, 64);
        // count=0 always succeeds, returns 0
        assert_eq!(bm.alloc_contiguous(0), Some(0));
    }

    // ------------------------------------------------------------------
    // non-power-of-64 size: tail padding must not leak as free frames
    // ------------------------------------------------------------------

    #[test]
    fn tail_padding_not_allocable() {
        // 65 bits -> 2 words; bits 65..127 are padding
        let mut storage = make_words(2);
        let mut bm = Bitmap::new(&mut storage, 65);

        assert_eq!(bm.count_free(), 65);

        // drain all 65 frames
        for i in 0..65 {
            let idx = bm.alloc().expect("should still have frames");
            assert!(idx < 65, "alloc returned out-of-range frame {idx} at step {i}");
        }
        assert!(bm.alloc().is_none(), "no more frames -- None expected");
    }

    // ------------------------------------------------------------------
    // count_free reflects actual state
    // ------------------------------------------------------------------

    #[test]
    fn count_free_tracks_state() {
        let mut storage = make_words(2);
        let mut bm = Bitmap::new(&mut storage, 128);
        assert_eq!(bm.count_free(), 128);

        bm.set(0);
        assert_eq!(bm.count_free(), 127);

        bm.set(127);
        assert_eq!(bm.count_free(), 126);

        bm.clear(0);
        assert_eq!(bm.count_free(), 127);
    }

    // ------------------------------------------------------------------
    // debug_assert guards (only active in debug; verify they fire)
    // ------------------------------------------------------------------

    #[test]
    #[should_panic]
    fn double_free_panics_in_debug() {
        let mut storage = make_words(1);
        let mut bm = Bitmap::new(&mut storage, 64);
        let idx = bm.alloc().unwrap();
        bm.free(idx);
        bm.free(idx); // second free -- must panic in debug
    }

    #[test]
    #[should_panic]
    fn get_out_of_bounds_panics() {
        let mut storage = make_words(1);
        let bm = Bitmap::new(&mut storage, 8);
        // the panic fires inside get before the return value is used, but
        // we bind it to silence the must_use lint
        let _ = bm.get(8); // out of bounds
    }

    #[test]
    #[should_panic]
    fn set_out_of_bounds_panics() {
        let mut storage = make_words(1);
        let mut bm = Bitmap::new(&mut storage, 8);
        bm.set(8);
    }

    #[test]
    #[should_panic]
    fn clear_out_of_bounds_panics() {
        let mut storage = make_words(1);
        let mut bm = Bitmap::new(&mut storage, 8);
        bm.clear(8);
    }
}

// ---------------------------------------------------------------------------
// Kani proof harnesses
// ---------------------------------------------------------------------------

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // bounded backing storage for proofs -- 2 words = 128 bits is enough to
    // exercise cross-word arithmetic while keeping Kani's state space small
    const PROOF_WORDS: usize = 2;
    const PROOF_BITS: usize = PROOF_WORDS * BITS_PER_WORD; // 128

    // ------------------------------------------------------------------
    // helper: index helpers stay in bounds for any valid idx
    // ------------------------------------------------------------------

    #[kani::proof]
    fn index_helpers_in_bounds() {
        let idx: usize = kani::any();
        kani::assume(idx < PROOF_BITS);

        let wi = word_index(idx);
        let bi = bit_index(idx);

        assert!(wi < PROOF_WORDS, "word_index out of bounds");
        assert!((bi as usize) < BITS_PER_WORD, "bit_index out of bounds");
    }

    // ------------------------------------------------------------------
    // set then get returns true
    // ------------------------------------------------------------------

    #[kani::proof]
    fn set_then_get_true() {
        let mut storage = [0u64; PROOF_WORDS];
        let mut bm = Bitmap::new(&mut storage, PROOF_BITS);

        let idx: usize = kani::any();
        kani::assume(idx < PROOF_BITS);

        bm.set(idx);
        assert!(bm.get(idx));
    }

    // ------------------------------------------------------------------
    // clear then get returns false
    // ------------------------------------------------------------------

    #[kani::proof]
    fn clear_then_get_false() {
        let mut storage = [0u64; PROOF_WORDS];
        let mut bm = Bitmap::new(&mut storage, PROOF_BITS);

        let idx: usize = kani::any();
        kani::assume(idx < PROOF_BITS);

        // set first so clear has something to undo
        bm.set(idx);
        bm.clear(idx);
        assert!(!bm.get(idx));
    }

    // ------------------------------------------------------------------
    // set does not clobber a different bit
    // ------------------------------------------------------------------

    #[kani::proof]
    fn set_does_not_clobber_other_bits() {
        let mut storage = [0u64; PROOF_WORDS];
        let mut bm = Bitmap::new(&mut storage, PROOF_BITS);

        let i: usize = kani::any();
        let j: usize = kani::any();
        kani::assume(i < PROOF_BITS);
        kani::assume(j < PROOF_BITS);
        kani::assume(i != j);

        // j is free initially; set i; j must still be free
        assert!(!bm.get(j));
        bm.set(i);
        assert!(!bm.get(j));
    }

    // ------------------------------------------------------------------
    // alloc returns an in-bounds index when the bitmap is not full
    // ------------------------------------------------------------------

    #[kani::proof]
    fn alloc_returns_in_bounds_index() {
        let mut storage = [0u64; PROOF_WORDS];
        // use a smaller len_bits to keep the harness bounded
        const LEN: usize = 16;
        let mut bm = Bitmap::new(&mut storage, LEN);

        // non-deterministically mark some frames used
        let mask: u16 = kani::any();
        for i in 0..LEN {
            if (mask >> i) & 1 == 1 {
                bm.set(i);
            }
        }

        if let Some(idx) = bm.alloc() {
            assert!(idx < LEN, "alloc returned out-of-range index {idx}");
            assert!(bm.get(idx), "alloc must mark the returned frame used");
        }
    }

    // ------------------------------------------------------------------
    // conservation: count_free + count_used == len_bits
    // ------------------------------------------------------------------

    #[kani::proof]
    fn conservation_invariant() {
        let mut storage = [0u64; PROOF_WORDS];
        const LEN: usize = 16;
        let mut bm = Bitmap::new(&mut storage, LEN);

        let mask: u16 = kani::any();
        for i in 0..LEN {
            if (mask >> i) & 1 == 1 {
                bm.set(i);
            }
        }

        assert_eq!(bm.count_free() + bm.count_used(), LEN);
    }
}
