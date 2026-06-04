//! Physical frame allocator -- pure logic, no hardware.
//!
//! A [`FrameAllocator`] wraps a [`Bitmap`] and a physical base address to
//! manage a contiguous range of 4 KiB physical page frames. The bitmap tracks
//! which frames are free and which are allocated; this module provides the
//! address arithmetic that maps between physical addresses and bitmap indices.
//!
//! # Invariant
//!
//! Let `base` be the physical address of frame 0 and `frame_count` be the
//! total number of frames managed. For any frame index `i` in
//! `[0, frame_count)`:
//!
//! - `frame_addr(i) = base + i * FRAME_SIZE`
//! - `frame_index(addr) = (addr - base) / FRAME_SIZE`
//!
//! These two functions are inverses on the set of frame-aligned addresses in
//! `[base, base + frame_count * FRAME_SIZE)`:
//!
//! - `frame_addr(frame_index(addr)) == addr` for any `addr` that is
//!   frame-aligned and in `[base, base + frame_count * FRAME_SIZE)`.
//! - `frame_index(frame_addr(i)) == i` for any `i` in `[0, frame_count)`.
//!
//! `base` must itself be `FRAME_SIZE`-aligned (i.e. `base % FRAME_SIZE == 0`).
//!
//! [`allocate_frame`] returns a physical address that satisfies:
//! - `addr % FRAME_SIZE == 0` (frame-aligned)
//! - `addr >= base`
//! - `addr < base + frame_count * FRAME_SIZE`
//!
//! These properties are the exact lemmas targeted by the `#[cfg(kani)]` proofs
//! below, analogous to the index-arithmetic harnesses in `page_table`.
//!
//! [`Bitmap`]: crate::bitmap::Bitmap
//! [`FrameAllocator`]: FrameAllocator
//! [`allocate_frame`]: FrameAllocator::allocate_frame

use crate::bitmap::Bitmap;

/// Size of one physical page frame in bytes (4 KiB, 2^12).
pub const FRAME_SIZE: u64 = 4096;

// ---------------------------------------------------------------------------
// address <-> index helpers
// ---------------------------------------------------------------------------
//
// these two tiny functions are the entire address-arithmetic surface of the
// allocator. keeping them separate lets the Kani harnesses target the pure
// arithmetic in isolation, exactly as page_table.rs does for its index helpers.

/// Returns the physical address of frame `index` in an allocator whose first
/// frame starts at `base`.
///
/// The result is `base + index * FRAME_SIZE`.
///
/// # Precondition
///
/// `base` must be `FRAME_SIZE`-aligned and `index` must be less than the
/// allocator's `frame_count`. These are not enforced here; callers must
/// uphold them.
#[inline]
#[must_use]
pub const fn frame_addr(base: u64, index: usize) -> u64 {
    base + (index as u64) * FRAME_SIZE
}

/// Returns the frame index for a physical address `addr` given the allocator's
/// `base` address.
///
/// The result is `(addr - base) / FRAME_SIZE`.
///
/// # Precondition
///
/// `addr` must be `>= base`, `FRAME_SIZE`-aligned, and within the allocator's
/// managed range. These are not enforced here; callers must uphold them.
#[inline]
#[must_use]
pub const fn frame_index(base: u64, addr: u64) -> usize {
    ((addr - base) / FRAME_SIZE) as usize
}

// ---------------------------------------------------------------------------
// FrameAllocator
// ---------------------------------------------------------------------------

/// A physical frame allocator backed by a [`Bitmap`].
///
/// The allocator manages `frame_count` contiguous 4 KiB page frames starting
/// at physical address `base`. Allocation and deallocation are delegated to
/// the bitmap; this struct provides the address arithmetic layer on top.
///
/// # Ownership
///
/// `FrameAllocator<'a>` borrows the backing `u64` slice for lifetime `'a`
/// (via `Bitmap`). A real kernel provides this slice from a static pool carved
/// out during early boot.
pub struct FrameAllocator<'a> {
    /// the bitmap that tracks free/used status of each frame.
    bitmap: Bitmap<'a>,
    /// physical address of frame 0; must be FRAME_SIZE-aligned.
    base: u64,
    /// total number of frames managed.
    frame_count: usize,
}

impl<'a> FrameAllocator<'a> {
    /// Creates a new `FrameAllocator` from a backing word slice.
    ///
    /// `storage` is the `u64` slice used as the bitmap's backing store;
    /// it must be large enough to hold at least `(frame_count + 63) / 64`
    /// words. `base` is the physical address of frame 0 and must be
    /// `FRAME_SIZE`-aligned. `frame_count` is the number of frames to manage.
    ///
    /// # Preconditions
    ///
    /// - `base % FRAME_SIZE == 0` (base must be frame-aligned)
    /// - `frame_count <= storage.len() * 64` (storage must be large enough)
    ///
    /// Both preconditions are checked with [`debug_assert`] in debug builds.
    ///
    /// # Postcondition
    ///
    /// All `frame_count` frames are initially free.
    #[must_use]
    pub fn new(storage: &'a mut [u64], base: u64, frame_count: usize) -> Self {
        debug_assert!(
            base.is_multiple_of(FRAME_SIZE),
            "base address {base:#x} is not FRAME_SIZE-aligned"
        );
        // bitmap::new will debug_assert the storage length; no need to repeat.
        let bitmap = Bitmap::new(storage, frame_count);
        FrameAllocator {
            bitmap,
            base,
            frame_count,
        }
    }

    /// Allocates the lowest free frame and returns its physical address.
    ///
    /// Returns `None` when all frames are in use.
    ///
    /// The returned address satisfies:
    /// - `addr % FRAME_SIZE == 0`
    /// - `addr >= self.base`
    /// - `addr < self.base + self.frame_count * FRAME_SIZE`
    pub fn allocate_frame(&mut self) -> Option<u64> {
        let idx = self.bitmap.alloc()?;
        Some(frame_addr(self.base, idx))
    }

    /// Deallocates the frame at physical address `addr`, returning it to the
    /// free pool.
    ///
    /// # Preconditions
    ///
    /// - `addr % FRAME_SIZE == 0` (must be frame-aligned)
    /// - `addr >= self.base`
    /// - `addr < self.base + self.frame_count * FRAME_SIZE`
    /// - The frame must currently be allocated (no double-free).
    ///
    /// All four conditions are checked with [`debug_assert`] in debug builds.
    pub fn deallocate_frame(&mut self, addr: u64) {
        debug_assert!(
            addr.is_multiple_of(FRAME_SIZE),
            "address {addr:#x} is not FRAME_SIZE-aligned"
        );
        debug_assert!(
            addr >= self.base,
            "address {addr:#x} is below base {:#x}",
            self.base
        );
        debug_assert!(
            addr < self.base + (self.frame_count as u64) * FRAME_SIZE,
            "address {addr:#x} is out of managed range"
        );
        let idx = frame_index(self.base, addr);
        self.bitmap.free(idx);
    }

    /// Allocates `count` physically contiguous frames and returns the address
    /// of the first one.
    ///
    /// Returns `None` when no suitable run exists in the free pool.
    ///
    /// The returned address satisfies the same bounds as [`allocate_frame`]:
    /// frame-aligned, `>= base`, and the entire run fits within the managed
    /// range.
    ///
    /// [`allocate_frame`]: FrameAllocator::allocate_frame
    pub fn allocate_contiguous(&mut self, count: usize) -> Option<u64> {
        let idx = self.bitmap.alloc_contiguous(count)?;
        Some(frame_addr(self.base, idx))
    }

    /// Returns the number of free (unallocated) frames.
    #[inline]
    #[must_use]
    pub fn free_frames(&self) -> usize {
        self.bitmap.count_free()
    }

    /// Returns the total number of frames managed by this allocator.
    #[inline]
    #[must_use]
    pub const fn frame_count(&self) -> usize {
        self.frame_count
    }

    /// Returns the physical base address (address of frame 0).
    #[inline]
    #[must_use]
    pub const fn base(&self) -> u64 {
        self.base
    }
}

// ---------------------------------------------------------------------------
// unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{FrameAllocator, FRAME_SIZE, frame_addr, frame_index};

    // test harness links std; the library itself stays no_std.
    extern crate std;

    // helper: allocate backing words for `frame_count` frames.
    fn make_storage(frame_count: usize) -> std::vec::Vec<u64> {
        let words = (frame_count + 63) / 64;
        std::vec![0u64; words]
    }

    // ---- address/index round-trip arithmetic --------------------------------

    #[test]
    fn frame_addr_frame_index_roundtrip_zero_base() {
        let base: u64 = 0;
        for i in 0..16_usize {
            let addr = frame_addr(base, i);
            assert_eq!(addr, i as u64 * FRAME_SIZE);
            assert_eq!(frame_index(base, addr), i);
        }
    }

    #[test]
    fn frame_addr_frame_index_roundtrip_nonzero_base() {
        // use a realistic physical base well above zero to exercise the offset.
        let base: u64 = 0x10_0000; // 1 MiB
        for i in 0..32_usize {
            let addr = frame_addr(base, i);
            assert_eq!(addr, base + i as u64 * FRAME_SIZE);
            assert_eq!(frame_index(base, addr), i);
        }
    }

    // ---- allocations are sequential, starting from base -------------------

    #[test]
    fn alloc_returns_sequential_addresses_from_base() {
        let base: u64 = 0;
        let count = 8;
        let mut storage = make_storage(count);
        let mut fa = FrameAllocator::new(&mut storage, base, count);

        for i in 0..count {
            let addr = fa.allocate_frame().expect("should have frames");
            assert_eq!(addr, base + (i as u64) * FRAME_SIZE);
        }
        assert!(fa.allocate_frame().is_none(), "allocator should be exhausted");
    }

    #[test]
    fn alloc_returns_sequential_addresses_nonzero_base() {
        let base: u64 = 0x10_0000; // 1 MiB -- exercises non-zero base offset
        let count = 8;
        let mut storage = make_storage(count);
        let mut fa = FrameAllocator::new(&mut storage, base, count);

        for i in 0..count {
            let addr = fa.allocate_frame().expect("should have frames");
            assert_eq!(addr, base + (i as u64) * FRAME_SIZE);
        }
        assert!(fa.allocate_frame().is_none(), "allocator should be exhausted");
    }

    // ---- alloc until full then None ----------------------------------------

    #[test]
    fn alloc_until_full_returns_none() {
        let base: u64 = 0x20_0000;
        let count = 130;
        let mut storage = make_storage(count);
        let mut fa = FrameAllocator::new(&mut storage, base, count);

        for _ in 0..count {
            assert!(fa.allocate_frame().is_some());
        }
        assert!(fa.allocate_frame().is_none());
    }

    // ---- dealloc then re-alloc reuses the slot -----------------------------

    #[test]
    fn dealloc_then_realloc_reuses_frame() {
        let base: u64 = 0x30_0000;
        let count = 16;
        let mut storage = make_storage(count);
        let mut fa = FrameAllocator::new(&mut storage, base, count);

        // allocate the first four frames
        let mut addrs = [0u64; 4];
        for a in &mut addrs {
            *a = fa.allocate_frame().unwrap();
        }

        // deallocate frame 1 (the second one allocated = base + 4096)
        let freed = addrs[1];
        fa.deallocate_frame(freed);

        // the bitmap returns the lowest free index, which is now index 1 again.
        let reallocated = fa.allocate_frame().unwrap();
        assert_eq!(reallocated, freed, "reallocated address must match the freed frame");
    }

    // ---- free_frames conservation invariant --------------------------------

    #[test]
    fn free_frames_conservation() {
        let base: u64 = 0;
        let count = 64;
        let mut storage = make_storage(count);
        let mut fa = FrameAllocator::new(&mut storage, base, count);

        assert_eq!(fa.free_frames(), count);

        let mut allocated = std::vec::Vec::new();
        for _ in 0..32 {
            allocated.push(fa.allocate_frame().unwrap());
            // after each alloc: free + allocated == frame_count
            let held = allocated.len();
            assert_eq!(fa.free_frames() + held, count);
        }

        for addr in &allocated {
            fa.deallocate_frame(*addr);
        }
        assert_eq!(fa.free_frames(), count);
    }

    // ---- all returned addresses are frame-aligned --------------------------

    #[test]
    fn all_allocated_addresses_are_frame_aligned() {
        let base: u64 = 0x40_0000;
        let count = 64;
        let mut storage = make_storage(count);
        let mut fa = FrameAllocator::new(&mut storage, base, count);

        while let Some(addr) = fa.allocate_frame() {
            assert_eq!(addr % FRAME_SIZE, 0, "address {addr:#x} is not frame-aligned");
        }
    }

    // ---- all returned addresses are within the managed range ---------------

    #[test]
    fn all_allocated_addresses_in_managed_range() {
        let base: u64 = 0x50_0000;
        let count = 32;
        let mut storage = make_storage(count);
        let mut fa = FrameAllocator::new(&mut storage, base, count);

        let end = base + (count as u64) * FRAME_SIZE;
        while let Some(addr) = fa.allocate_frame() {
            assert!(addr >= base, "address {addr:#x} below base {base:#x}");
            assert!(addr < end, "address {addr:#x} >= end {end:#x}");
        }
    }

    // ---- contiguous allocation across word boundaries ----------------------

    #[test]
    fn allocate_contiguous_basic() {
        let base: u64 = 0x60_0000;
        let count = 192;
        let mut storage = make_storage(count);
        let mut fa = FrameAllocator::new(&mut storage, base, count);

        // consume the first 62 frames so the free run starts near the word boundary.
        for _ in 0..62 {
            fa.allocate_frame().unwrap();
        }

        // request 4 contiguous frames; should land at index 62 (= base + 62*4096).
        let addr = fa.allocate_contiguous(4).expect("must find 4 contiguous frames");
        assert_eq!(addr, base + 62 * FRAME_SIZE);
        assert_eq!(addr % FRAME_SIZE, 0);
    }

    #[test]
    fn allocate_contiguous_none_when_full() {
        let base: u64 = 0;
        let count = 8;
        let mut storage = make_storage(count);
        let mut fa = FrameAllocator::new(&mut storage, base, count);

        for _ in 0..count {
            fa.allocate_frame().unwrap();
        }
        assert!(fa.allocate_contiguous(1).is_none());
    }

    // ---- frame_count and base accessors ------------------------------------

    #[test]
    fn accessors_return_construction_values() {
        let base: u64 = 0x10_0000;
        let count = 42;
        let mut storage = make_storage(count);
        let fa = FrameAllocator::new(&mut storage, base, count);

        assert_eq!(fa.base(), base);
        assert_eq!(fa.frame_count(), count);
        assert_eq!(fa.free_frames(), count);
    }
}

// ---------------------------------------------------------------------------
// Kani bounded proof harnesses
// ---------------------------------------------------------------------------

#[cfg(kani)]
mod kani_proofs {
    use super::{FrameAllocator, FRAME_SIZE, frame_addr, frame_index};

    // the number of frames used in bounded proofs. small enough that Kani's
    // state space stays manageable (2 backing words = 128 frames max, but 16
    // is plenty to exercise the arithmetic while keeping verification fast).
    const PROOF_FRAMES: usize = 16;
    const PROOF_WORDS: usize = (PROOF_FRAMES + 63) / 64; // 1

    // ---- pure arithmetic round-trips (no struct state needed) --------------

    /// `frame_index(base, frame_addr(base, i)) == i` for any in-range index.
    ///
    /// this is the core arithmetic identity: converting an index to an address
    /// and back yields the original index. it holds for any aligned `base` and
    /// any `i` in `[0, PROOF_FRAMES)`.
    #[kani::proof]
    fn frame_index_frame_addr_roundtrip() {
        let base: u64 = kani::any();
        let i: usize = kani::any();
        // restrict base to be frame-aligned and small enough to avoid overflow.
        kani::assume(base % FRAME_SIZE == 0);
        kani::assume(i < PROOF_FRAMES);
        // guard against u64 overflow in frame_addr.
        kani::assume(base.checked_add((i as u64) * FRAME_SIZE).is_some());

        let addr = frame_addr(base, i);
        assert_eq!(frame_index(base, addr), i);
    }

    /// `frame_addr(base, frame_index(base, addr)) == addr` for any
    /// frame-aligned address in `[base, base + PROOF_FRAMES * FRAME_SIZE)`.
    #[kani::proof]
    fn frame_addr_frame_index_roundtrip() {
        let base: u64 = kani::any();
        let addr: u64 = kani::any();
        // addr must be frame-aligned and in the managed range.
        kani::assume(base % FRAME_SIZE == 0);
        kani::assume(addr % FRAME_SIZE == 0);
        kani::assume(addr >= base);
        let span = (PROOF_FRAMES as u64) * FRAME_SIZE;
        kani::assume(base.checked_add(span).is_some());
        kani::assume(addr < base + span);

        let idx = frame_index(base, addr);
        assert_eq!(frame_addr(base, idx), addr);
    }

    // ---- allocator postconditions ------------------------------------------

    /// `allocate_frame` always returns a frame-aligned address.
    #[kani::proof]
    fn allocate_frame_is_aligned() {
        let mut storage = [0u64; PROOF_WORDS];
        let base: u64 = kani::any();
        kani::assume(base % FRAME_SIZE == 0);
        // prevent base + frame_count * FRAME_SIZE from overflowing u64.
        kani::assume(
            base.checked_add((PROOF_FRAMES as u64) * FRAME_SIZE).is_some(),
        );

        let mut fa = FrameAllocator::new(&mut storage, base, PROOF_FRAMES);

        // non-deterministically pre-fill some frames to reach any reachable state.
        let mask: u16 = kani::any();
        for i in 0..PROOF_FRAMES {
            if (mask >> i) & 1 == 1 {
                // consume one frame by allocating (ignore the result).
                let _ = fa.allocate_frame();
            }
        }

        if let Some(addr) = fa.allocate_frame() {
            assert_eq!(addr % FRAME_SIZE, 0, "returned address must be frame-aligned");
        }
    }

    /// `allocate_frame` always returns an address in `[base, base + count*FRAME_SIZE)`.
    #[kani::proof]
    fn allocate_frame_in_range() {
        let mut storage = [0u64; PROOF_WORDS];
        // use a concrete base so the range check arithmetic stays bounded.
        let base: u64 = 0x10_0000;
        let mut fa = FrameAllocator::new(&mut storage, base, PROOF_FRAMES);

        let mask: u16 = kani::any();
        for i in 0..PROOF_FRAMES {
            if (mask >> i) & 1 == 1 {
                let _ = fa.allocate_frame();
            }
        }

        if let Some(addr) = fa.allocate_frame() {
            let end = base + (PROOF_FRAMES as u64) * FRAME_SIZE;
            assert!(addr >= base, "address must be >= base");
            assert!(addr < end, "address must be < base + count * FRAME_SIZE");
        }
    }

    /// alloc followed by dealloc restores the free count.
    ///
    /// this is the allocator analogue of the bitmap's `set->clear` identity:
    /// allocating one frame and immediately deallocating it is a no-op on the
    /// observable state (`free_frames`).
    #[kani::proof]
    fn alloc_then_dealloc_is_identity() {
        let mut storage = [0u64; PROOF_WORDS];
        let base: u64 = 0x20_0000;
        let mut fa = FrameAllocator::new(&mut storage, base, PROOF_FRAMES);

        let free_before = fa.free_frames();
        if let Some(addr) = fa.allocate_frame() {
            fa.deallocate_frame(addr);
            assert_eq!(
                fa.free_frames(),
                free_before,
                "free count must be restored after alloc+dealloc"
            );
        }
    }

    /// `free_frames + used == frame_count` after any allocation pattern.
    #[kani::proof]
    fn free_frames_conservation() {
        let mut storage = [0u64; PROOF_WORDS];
        let base: u64 = 0;
        let mut fa = FrameAllocator::new(&mut storage, base, PROOF_FRAMES);

        // apply a non-deterministic allocation pattern.
        let mask: u16 = kani::any();
        let mut allocated: usize = 0;
        for i in 0..PROOF_FRAMES {
            if (mask >> i) & 1 == 1 {
                if fa.allocate_frame().is_some() {
                    allocated += 1;
                }
            }
        }

        assert_eq!(
            fa.free_frames() + allocated,
            PROOF_FRAMES,
            "free + used must equal frame_count"
        );
    }
}
