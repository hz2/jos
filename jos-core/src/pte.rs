//! `x86_64` page-table *entry* encoding (pure logic, no hardware).
//!
//! [`page_table`](crate::page_table) splits a virtual address into the four
//! table indices. This module covers the complementary half: the 64-bit
//! *entry* stored in a page table, which pairs a physical frame address with a
//! set of flag bits. A `VSpace` mapper (the retypeable page-table objects in the
//! kernel) builds entries with [`encode`] and reads them back with
//! [`frame_addr`] / [`flags`]; keeping that bit math here lets Kani prove the
//! round-trip and bounds before the kernel ever dereferences a table.
//!
//! # Entry layout (4 KiB pages, 4-level paging)
//!
//! ```text
//! bit 63        NX (no-execute)            -- a flag
//! bits 62..52   available / reserved       -- treated as flag bits
//! bits 51..12   physical frame address     -- the 40-bit aligned frame field
//! bits 11..0    flags (P, RW, US, ...)     -- flag bits
//! ```
//!
//! The physical-address field is bits `51..12`: a 4 KiB-aligned frame address
//! has its low 12 bits zero (they hold flags) and, on the architectural 52-bit
//! physical-address maximum, no bits above 51. So [`ADDR_MASK`] selects exactly
//! the frame field and [`FLAGS_MASK`] is its complement.
//!
//! # Invariant
//!
//! For any `addr` that is 4 KiB-aligned and within the 52-bit physical range
//! (`addr & !ADDR_MASK == 0`) and any `flags` confined to the flag bits
//! (`flags & ADDR_MASK == 0`):
//!
//! - `frame_addr(encode(addr, flags)) == addr` -- the address round-trips,
//! - `flags(encode(addr, flags)) == flags` -- the flags round-trip,
//! - `frame_addr(e) & !ADDR_MASK == 0` for *any* `e` -- the extracted address
//!   is always aligned and in range (the mask guarantees it),
//! - `encode(addr, flags) == addr | flags` when the two do not overlap.
//!
//! These are the lemmas discharged by the `#[cfg(kani)]` harnesses below. Like
//! [`page_table`](crate::page_table) the code is straight-line bit math with no
//! loops, so the proofs need no `#[kani::unwind]` bound.

// ---------------------------------------------------------------------------
// masks
// ---------------------------------------------------------------------------

/// Mask selecting the physical frame-address field of a page-table entry
/// (bits `51..12`). A 4 KiB-aligned physical address on the 52-bit maximum
/// occupies exactly these bits.
pub const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Mask selecting the flag bits of a page-table entry: everything that is not
/// the frame address (the low 12 bits plus bits `63..52`). The exact
/// complement of [`ADDR_MASK`].
pub const FLAGS_MASK: u64 = !ADDR_MASK;

/// The page-table entry flag bits jos cares about.
///
/// A subset of the architectural flags, named for the operations the `VSpace`
/// mapper performs. Every defined bit lies within [`FLAGS_MASK`] (the low 12
/// bits, plus `NO_EXECUTE` at bit 63), so flags never collide with the frame
/// address. Hand-rolled as a `repr(transparent)` newtype over `u64` to keep
/// `jos-core` dependency-free, matching [`Rights`](crate::cap_rights::Rights).
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PteFlags(u64);

impl PteFlags {
    /// The entry maps a present page; a walk through a not-present entry faults.
    pub const PRESENT: Self = Self(1 << 0);
    /// The mapped page is writable (else read-only).
    pub const WRITABLE: Self = Self(1 << 1);
    /// The mapped page is reachable from ring 3 (user mode). Required on every
    /// level of a userspace mapping's walk.
    pub const USER: Self = Self(1 << 2);
    /// Writes bypass the cache (write-through).
    pub const WRITE_THROUGH: Self = Self(1 << 3);
    /// The page is not cached.
    pub const NO_CACHE: Self = Self(1 << 4);
    /// Set by the cpu when the entry is used in a translation.
    pub const ACCESSED: Self = Self(1 << 5);
    /// Set by the cpu when the mapped page is written.
    pub const DIRTY: Self = Self(1 << 6);
    /// At a non-leaf level, marks the entry as mapping a large page rather than
    /// pointing to the next table.
    pub const HUGE_PAGE: Self = Self(1 << 7);
    /// The mapping is global (not flushed on a `CR3` reload).
    pub const GLOBAL: Self = Self(1 << 8);
    /// The mapped page is non-executable (requires `EFER.NXE`).
    pub const NO_EXECUTE: Self = Self(1 << 63);

    /// The empty flag set.
    #[inline]
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Returns the raw `u64` bit pattern of these flags.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Keeps only the bits that fall within [`FLAGS_MASK`], dropping any that
    /// would collide with the frame-address field. The canonical constructor
    /// from a raw entry's flag portion.
    #[inline]
    #[must_use]
    pub const fn from_bits_truncate(bits: u64) -> Self {
        Self(bits & FLAGS_MASK)
    }

    /// Returns the union of two flag sets (bitwise OR).
    #[inline]
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns `true` if every bit in `other` is also set in `self`.
    #[inline]
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for PteFlags {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

// ---------------------------------------------------------------------------
// encode / decode
// ---------------------------------------------------------------------------

/// Builds a page-table entry from a physical frame address and flag bits.
///
/// `addr` must be 4 KiB-aligned and within the 52-bit physical range (its bits
/// outside [`ADDR_MASK`] must be zero); `flags` must be confined to the flag
/// bits (its bits inside [`ADDR_MASK`] must be zero). Both are masked
/// defensively so the function is total: stray bits are dropped rather than
/// allowed to corrupt the other field. When the inputs are well-formed the
/// result is exactly `addr | flags`.
#[inline]
#[must_use]
pub const fn encode(addr: u64, flags: u64) -> u64 {
    (addr & ADDR_MASK) | (flags & FLAGS_MASK)
}

/// Builds a page-table entry from a physical frame address and typed
/// [`PteFlags`]. The typed wrapper over [`encode`]: `PteFlags` are always
/// within [`FLAGS_MASK`] by construction, so only `addr` needs masking.
#[inline]
#[must_use]
pub const fn encode_flags(addr: u64, flags: PteFlags) -> u64 {
    encode(addr, flags.bits())
}

/// Extracts the physical frame address from a page-table entry.
///
/// The result is always 4 KiB-aligned and within the 52-bit physical range
/// (`result & !ADDR_MASK == 0`), because the mask clears every non-address bit.
#[inline]
#[must_use]
pub const fn frame_addr(entry: u64) -> u64 {
    entry & ADDR_MASK
}

/// Extracts the raw flag bits from a page-table entry (everything that is not
/// the frame address).
#[inline]
#[must_use]
pub const fn flags(entry: u64) -> u64 {
    entry & FLAGS_MASK
}

/// Extracts the typed [`PteFlags`] from a page-table entry, dropping any flag
/// bits not modeled by [`PteFlags`].
#[inline]
#[must_use]
pub const fn pte_flags(entry: u64) -> PteFlags {
    PteFlags::from_bits_truncate(flags(entry))
}

/// Returns `true` if the entry's `PRESENT` bit is set (a walk may follow it).
#[inline]
#[must_use]
pub const fn is_present(entry: u64) -> bool {
    entry & PteFlags::PRESENT.bits() != 0
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{
        ADDR_MASK, FLAGS_MASK, PteFlags, encode, encode_flags, flags, frame_addr, is_present,
        pte_flags,
    };

    #[test]
    fn masks_are_complementary() {
        assert_eq!(ADDR_MASK & FLAGS_MASK, 0);
        assert_eq!(ADDR_MASK | FLAGS_MASK, u64::MAX);
    }

    #[test]
    fn addr_mask_covers_bits_12_to_52() {
        // low 12 bits clear, bits 12..52 set, bits 52..64 clear.
        assert_eq!(ADDR_MASK & 0xFFF, 0);
        assert_eq!(ADDR_MASK >> 52, 0);
        assert_eq!((ADDR_MASK >> 12) & 1, 1);
    }

    #[test]
    fn encode_combines_aligned_addr_and_flags() {
        let addr = 0x1234_5000;
        let f = PteFlags::PRESENT | PteFlags::WRITABLE | PteFlags::USER;
        let entry = encode_flags(addr, f);
        assert_eq!(frame_addr(entry), addr);
        assert_eq!(pte_flags(entry), f);
        // when inputs do not overlap, encode is just OR.
        assert_eq!(entry, addr | f.bits());
    }

    #[test]
    fn roundtrip_addr_and_flags() {
        let addr = 0x000A_BCDE_F000;
        let raw_flags = PteFlags::PRESENT.bits()
            | PteFlags::WRITABLE.bits()
            | PteFlags::NO_EXECUTE.bits();
        let entry = encode(addr, raw_flags);
        assert_eq!(frame_addr(entry), addr);
        assert_eq!(flags(entry), raw_flags);
    }

    #[test]
    fn no_execute_bit_is_a_flag_not_an_address() {
        // bit 63 must live in FLAGS_MASK, not the address field.
        assert_eq!(PteFlags::NO_EXECUTE.bits() & ADDR_MASK, 0);
        assert_ne!(PteFlags::NO_EXECUTE.bits() & FLAGS_MASK, 0);
        let entry = encode_flags(0, PteFlags::NO_EXECUTE);
        assert_eq!(frame_addr(entry), 0);
        assert!(pte_flags(entry).contains(PteFlags::NO_EXECUTE));
    }

    #[test]
    fn encode_masks_stray_bits_defensively() {
        // an unaligned addr has low bits that would collide with flags; encode
        // must drop them rather than corrupt the flag field.
        let unaligned = 0x1234_5FFF;
        let entry = encode(unaligned, PteFlags::PRESENT.bits());
        assert_eq!(frame_addr(entry), 0x1234_5000); // low 12 bits dropped
        assert_eq!(pte_flags(entry), PteFlags::PRESENT);
    }

    #[test]
    fn frame_addr_always_aligned_and_in_range() {
        for e in [0u64, u64::MAX, 0xDEAD_BEEF_CAFE_F123, 0x8000_0000_0000_0001] {
            let a = frame_addr(e);
            assert_eq!(a & !ADDR_MASK, 0, "frame_addr must clear all non-address bits");
        }
    }

    #[test]
    fn is_present_reads_bit_0() {
        assert!(is_present(encode_flags(0x1000, PteFlags::PRESENT)));
        assert!(!is_present(encode_flags(0x1000, PteFlags::WRITABLE)));
        assert!(!is_present(0));
    }
}

// ---------------------------------------------------------------------------
// Kani bounded proof harnesses
// ---------------------------------------------------------------------------
//
// straight-line bit math (no loops), so no #[kani::unwind] bound is needed,
// exactly as in page_table.rs. Kani verifies each property for ALL u64 inputs.

#[cfg(kani)]
mod kani_proofs {
    use super::{ADDR_MASK, FLAGS_MASK, encode, flags, frame_addr};

    // the two masks partition all 64 bits: complementary and exhaustive.
    #[kani::proof]
    fn masks_partition_all_bits() {
        assert_eq!(ADDR_MASK & FLAGS_MASK, 0);
        assert_eq!(ADDR_MASK | FLAGS_MASK, u64::MAX);
    }

    // for any entry, the extracted frame address has no bits outside ADDR_MASK
    // (it is always 4 KiB-aligned and within the 52-bit physical range).
    #[kani::proof]
    fn frame_addr_always_in_range() {
        let entry: u64 = kani::any();
        assert_eq!(frame_addr(entry) & !ADDR_MASK, 0);
    }

    // for any entry, the extracted flags have no bits inside ADDR_MASK.
    #[kani::proof]
    fn flags_never_touch_address() {
        let entry: u64 = kani::any();
        assert_eq!(flags(entry) & ADDR_MASK, 0);
    }

    // round-trip: for a well-formed (aligned, in-range) address and flags
    // confined to the flag bits, encode then decode is the identity on both.
    #[kani::proof]
    fn encode_decode_roundtrip() {
        let addr: u64 = kani::any();
        let f: u64 = kani::any();
        kani::assume(addr & !ADDR_MASK == 0); // addr is aligned + in range
        kani::assume(f & ADDR_MASK == 0); // flags stay in the flag bits
        let entry = encode(addr, f);
        assert_eq!(frame_addr(entry), addr);
        assert_eq!(flags(entry), f);
    }

    // encode never lets one field bleed into the other, even for adversarial
    // (overlapping) inputs: the address field of the result depends only on
    // addr's in-range bits, and the flag field only on f's flag bits.
    #[kani::proof]
    fn encode_isolates_fields() {
        let addr: u64 = kani::any();
        let f: u64 = kani::any();
        let entry = encode(addr, f);
        assert_eq!(frame_addr(entry), addr & ADDR_MASK);
        assert_eq!(flags(entry), f & FLAGS_MASK);
    }
}
