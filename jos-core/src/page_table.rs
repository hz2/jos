//! `x86_64` 4-level page-table index arithmetic (pure logic, no hardware).
//!
//! A 64-bit virtual address on `x86_64` is split into five fields when 4-level
//! (48-bit) paging is active. From most-significant to least-significant:
//!
//! ```text
//! bits 63..48  sign extension of bit 47 (canonical form; not a table index)
//! bits 47..39  PML4 index  (9 bits, range 0..512)
//! bits 38..30  PDPT index  (9 bits, range 0..512)
//! bits 29..21  PD index    (9 bits, range 0..512)
//! bits 20..12  PT index    (9 bits, range 0..512)
//! bits 11..0   page offset (12 bits, range 0..4096)
//! ```
//!
//! The hardware interprets bit ranges as `[lo, hi)` (lo inclusive, hi
//! exclusive), so the 9-bit `PML4` field is `vaddr[47:39]`.
//!
//! # Invariant
//!
//! For any virtual address `v` that is **canonical** (i.e. `is_canonical(v)`
//! returns `true`):
//!
//! - `page_offset(v)  < PAGE_SIZE`   (equivalently, `< 4096`)
//! - `pt_index(v)     < TABLE_ENTRIES` (equivalently, `< 512`)
//! - `pd_index(v)     < TABLE_ENTRIES`
//! - `pdpt_index(v)   < TABLE_ENTRIES`
//! - `pml4_index(v)   < TABLE_ENTRIES`
//!
//! Furthermore the **round-trip** property holds: given any canonical `v`,
//! reconstructing the address from its four indices and page offset via
//! `from_parts` yields the original address exactly.
//!
//! These three classes of invariant (range bounds, extraction correctness,
//! reconstruction identity) are the same lemmas targeted by the Verus
//! `integer_ring` example and are expressed here as `#[cfg(kani)]` bounded
//! model-check harnesses for easy future migration to full Verus proofs.

// ---------------------------------------------------------------------------
// constants
// ---------------------------------------------------------------------------

/// Number of entries in each page-table level (2^9).
pub const TABLE_ENTRIES: usize = 512;

/// Size of a 4 KiB base page in bytes (2^12).
pub const PAGE_SIZE: u64 = 4096;

// bit-width of the page offset field.
const OFFSET_BITS: u64 = 12;

// bit-width of each 9-bit table-index field.
const INDEX_BITS: u64 = 9;

// mask selecting a single 9-bit table index.
const INDEX_MASK: u64 = (TABLE_ENTRIES as u64) - 1; // 0x1FF

// ---------------------------------------------------------------------------
// canonical-address check
// ---------------------------------------------------------------------------

/// Returns `true` if `vaddr` is a canonical `x86_64` virtual address.
///
/// A 48-bit canonical address requires that bits 63..48 are all copies of
/// bit 47 (the sign-extension rule). Addresses that violate this cause a
/// general-protection fault on real hardware.
///
/// Equivalently: the address is canonical iff the upper 17 bits (63..47) are
/// all `0` (lower half, `0x0000_0000_0000_0000` to `0x0000_7FFF_FFFF_FFFF`)
/// or all `1` (higher half, `0xFFFF_8000_0000_0000` to
/// `0xFFFF_FFFF_FFFF_FFFF`).
#[inline]
#[must_use]
pub const fn is_canonical(vaddr: u64) -> bool {
    // reinterpret the u64 bit pattern as a signed i64, then arithmetic-shift
    // right by 47. an arithmetic shift replicates the sign bit, so the
    // result is 0 (all zero bits) for lower-half addresses and -1 (all one
    // bits) for upper-half addresses, provided bits 63..47 were already the
    // sign-extension of bit 47. any non-canonical address produces a result
    // that is neither 0 nor -1.
    let shifted = vaddr.cast_signed() >> 47;
    shifted == 0 || shifted == -1_i64
}

// ---------------------------------------------------------------------------
// field extraction helpers
// ---------------------------------------------------------------------------

/// Returns the 12-bit page offset of `vaddr` (always in `0..4096`).
#[inline]
#[must_use]
pub const fn page_offset(vaddr: u64) -> u64 {
    vaddr & (PAGE_SIZE - 1)
}

/// Returns the 9-bit `PT` (level-1 page table) index of `vaddr` (always in
/// `0..512`).
#[inline]
#[must_use]
pub const fn pt_index(vaddr: u64) -> usize {
    ((vaddr >> OFFSET_BITS) & INDEX_MASK) as usize
}

/// Returns the 9-bit `PD` (level-2 page directory) index of `vaddr` (always
/// in `0..512`).
#[inline]
#[must_use]
pub const fn pd_index(vaddr: u64) -> usize {
    ((vaddr >> (OFFSET_BITS + INDEX_BITS)) & INDEX_MASK) as usize
}

/// Returns the 9-bit `PDPT` (level-3 page-directory-pointer table) index of
/// `vaddr` (always in `0..512`).
#[inline]
#[must_use]
pub const fn pdpt_index(vaddr: u64) -> usize {
    ((vaddr >> (OFFSET_BITS + 2 * INDEX_BITS)) & INDEX_MASK) as usize
}

/// Returns the 9-bit `PML4` (level-4 page-map level-4) index of `vaddr`
/// (always in `0..512`).
#[inline]
#[must_use]
pub const fn pml4_index(vaddr: u64) -> usize {
    ((vaddr >> (OFFSET_BITS + 3 * INDEX_BITS)) & INDEX_MASK) as usize
}

// ---------------------------------------------------------------------------
// `PageTableLevel` enum for dispatch
// ---------------------------------------------------------------------------

/// The four levels of an `x86_64` 4-level page table hierarchy.
///
/// Levels are numbered from the walk entry point (`L4`) down to the leaf
/// (`L1`). The naming mirrors the Intel manual: `L4` = `PML4`, `L3` = `PDPT`,
/// `L2` = `PD`, `L1` = `PT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageTableLevel {
    /// Level 4: `PML4` (page-map level 4), bits 47..39 of the virtual address.
    L4,
    /// Level 3: `PDPT` (page-directory-pointer table), bits 38..30.
    L3,
    /// Level 2: `PD` (page directory), bits 29..21.
    L2,
    /// Level 1: `PT` (page table), bits 20..12.
    L1,
}

/// Returns the table index for `vaddr` at the given `level` (always in
/// `0..512`).
///
/// This is a unified dispatcher over the four level-specific functions.
/// Prefer the named functions (`pml4_index`, etc.) when the level is a
/// compile-time constant; use `table_index` when the level is a runtime
/// value.
#[inline]
#[must_use]
pub const fn table_index(vaddr: u64, level: PageTableLevel) -> usize {
    match level {
        PageTableLevel::L4 => pml4_index(vaddr),
        PageTableLevel::L3 => pdpt_index(vaddr),
        PageTableLevel::L2 => pd_index(vaddr),
        PageTableLevel::L1 => pt_index(vaddr),
    }
}

// ---------------------------------------------------------------------------
// multi-index extraction and reconstruction
// ---------------------------------------------------------------------------

/// Returns all four table indices for `vaddr` as `[pml4, pdpt, pd, pt]`.
///
/// The returned array is ordered from the outermost table walk to the
/// innermost, matching the hardware walk sequence.
#[inline]
#[must_use]
pub const fn indices(vaddr: u64) -> [usize; 4] {
    [
        pml4_index(vaddr),
        pdpt_index(vaddr),
        pd_index(vaddr),
        pt_index(vaddr),
    ]
}

/// Reconstructs a canonical virtual address from four table indices and a page
/// offset.
///
/// The arguments must satisfy:
/// - `idx[0]` (`PML4`) in `0..512`
/// - `idx[1]` (`PDPT`) in `0..512`
/// - `idx[2]` (`PD`) in `0..512`
/// - `idx[3]` (`PT`) in `0..512`
/// - `offset` in `0..4096`
///
/// If any index or the offset is out of range, the extra bits are silently
/// masked, and the result is sign-extended to produce a canonical address.
/// This matches the bit-manipulation the hardware would perform.
///
/// The primary invariant is the **round-trip**: for any canonical `v`,
/// `from_parts(indices(v), page_offset(v)) == v`.
#[inline]
#[must_use]
pub const fn from_parts(idx: [usize; 4], offset: u64) -> u64 {
    // assemble the raw 48-bit address from the four masked index fields and
    // the masked offset field.
    let raw: u64 = ((idx[0] as u64 & INDEX_MASK) << (OFFSET_BITS + 3 * INDEX_BITS))
        | ((idx[1] as u64 & INDEX_MASK) << (OFFSET_BITS + 2 * INDEX_BITS))
        | ((idx[2] as u64 & INDEX_MASK) << (OFFSET_BITS + INDEX_BITS))
        | ((idx[3] as u64 & INDEX_MASK) << OFFSET_BITS)
        | (offset & (PAGE_SIZE - 1));

    // sign-extend bit 47 into the upper 16 bits to produce a canonical address.
    // arithmetic right-shift of i64 propagates the sign bit.
    ((raw << 16).cast_signed() >> 16).cast_unsigned()
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{
        PageTableLevel, TABLE_ENTRIES, PAGE_SIZE,
        from_parts, indices, is_canonical,
        pd_index, pdpt_index, pml4_index, pt_index, page_offset, table_index,
    };

    // ---- known-value extraction -------------------------------------------
    //
    // vaddr = 0xFFFF_9234_5678_9ABC
    //
    // binary (lower 48 bits + sign):
    //   bit 47..39  (PML4):  0b1_0010_010  = 0x12 = 18
    //     (bits 47..39 of 0x9234_5678_9ABC)
    //
    // let's compute by hand:
    //   vaddr        = 0xFFFF_9234_5678_9ABC
    //   bits 47..0   = 0x9234_5678_9ABC
    //   bit 47       = 1  => canonical (sign extension all ones)
    //
    //   page_offset  = 0x9ABC & 0xFFF         = 0xABC = 2748
    //   pt_index     = (0x9ABC >> 12) & 0x1FF = 0x9 & 0x1FF = 9
    //                  (0x9234_5678_9ABC >> 12 = 0x9234_5678_9)
    //                  0x9 & 0x1FF = 9
    //   pd_index     = (vaddr >> 21) & 0x1FF
    //                  0x9234_5678_9ABC >> 21 = 0x9234_5678_9ABC / 0x200000
    //                  = 0x491A_2B
    //                  0x91A_2B >> 0... let's be precise:
    //                  0x9234_5678_9ABC >> 21 = 0x49_1A2B (top bits)
    //                  & 0x1FF = 0x12B = 299
    //
    // to avoid hand-computation errors, pick a carefully crafted vaddr.
    // use vaddr = 0x0000_1234_5678_9000 where each field is obvious.
    //
    // 0x0000_1234_5678_9000 in binary (lower 48 bits):
    //   0x1234_5678_9000
    //   = 0001 0010 0011 0100  0101 0110 0111 1000  1001 0000 0000 0000
    //
    // bits 47..39 (PML4):  bits 47-39 of 0x1234_5678_9000
    //   0x1234_5678_9000 >> 39 = 0x24 >> 3... let's compute:
    //   0x1234_5678_9000 = 0x0000_1234_5678_9000
    //   >> 39: 0x0000_1234_5678_9000 / 2^39
    //           2^39 = 0x80_0000_0000
    //           0x1234_5678_9000 / 0x80_0000_0000 = 0x24 (approx)
    //   let's just verify with the actual constants in the test below.

    // A hand-crafted address where every field is easily read:
    //   pml4  = 1   placed at bits 47..39: 1 << 39 = 0x0000_0080_0000_0000
    //   pdpt  = 2   placed at bits 38..30: 2 << 30 = 0x0000_0000_8000_0000
    //   pd    = 3   placed at bits 29..21: 3 << 21 = 0x0000_0000_0060_0000
    //   pt    = 4   placed at bits 20..12: 4 << 12 = 0x0000_0000_0000_4000
    //   off   = 5   placed at bits 11..0:  5        = 0x0000_0000_0000_0005
    //   sum              = 0x0000_0080_8064_4005
    //   bit 47 = 0 => canonical (upper half = all zeros)
    const KNOWN_VADDR: u64 = (1_u64 << 39)
        | (2_u64 << 30)
        | (3_u64 << 21)
        | (4_u64 << 12)
        | 5_u64;

    #[test]
    fn known_value_page_offset() {
        assert_eq!(page_offset(KNOWN_VADDR), 5);
    }

    #[test]
    fn known_value_pt_index() {
        assert_eq!(pt_index(KNOWN_VADDR), 4);
    }

    #[test]
    fn known_value_pd_index() {
        assert_eq!(pd_index(KNOWN_VADDR), 3);
    }

    #[test]
    fn known_value_pdpt_index() {
        assert_eq!(pdpt_index(KNOWN_VADDR), 2);
    }

    #[test]
    fn known_value_pml4_index() {
        assert_eq!(pml4_index(KNOWN_VADDR), 1);
    }

    #[test]
    fn known_value_indices_array() {
        assert_eq!(indices(KNOWN_VADDR), [1, 2, 3, 4]);
    }

    // ---- table_index dispatcher ------------------------------------------

    #[test]
    fn table_index_matches_named_fns() {
        assert_eq!(table_index(KNOWN_VADDR, PageTableLevel::L4), pml4_index(KNOWN_VADDR));
        assert_eq!(table_index(KNOWN_VADDR, PageTableLevel::L3), pdpt_index(KNOWN_VADDR));
        assert_eq!(table_index(KNOWN_VADDR, PageTableLevel::L2), pd_index(KNOWN_VADDR));
        assert_eq!(table_index(KNOWN_VADDR, PageTableLevel::L1), pt_index(KNOWN_VADDR));
    }

    // ---- boundary / maximum index values ---------------------------------

    #[test]
    fn max_index_is_511() {
        // verify that each 9-bit field is extracted as 0x1FF (511) when all
        // nine bits in that position are set. each address has exactly one
        // field at its maximum; the other fields are zero.
        //
        // note: these addresses are not necessarily canonical (setting only
        // the pml4 field to 0x1FF places bit 47 high with bits 63..48 = 0,
        // violating canonical form). that is fine: the extraction functions
        // do not require canonical input; the bound proofs hold for all u64.
        let max_pml4: u64 = (0x1FF_u64) << 39;
        assert_eq!(pml4_index(max_pml4), 0x1FF);

        let max_pdpt: u64 = (0x1FF_u64) << 30;
        assert_eq!(pdpt_index(max_pdpt), 0x1FF);

        let max_pd: u64 = (0x1FF_u64) << 21;
        assert_eq!(pd_index(max_pd), 0x1FF);

        let max_pt: u64 = (0x1FF_u64) << 12;
        assert_eq!(pt_index(max_pt), 0x1FF);

        // separately verify that the canonical address with all four fields
        // set to 0x1FF is indeed canonical and each field extracts correctly.
        // all fields = 0x1FF means bit 47 is set (from pml4 = 0x1FF), and
        // the upper 16 bits come from sign extension in from_parts. so build
        // it via from_parts to guarantee canonicality.
        let all_max = from_parts([0x1FF, 0x1FF, 0x1FF, 0x1FF], 0xFFF);
        assert!(is_canonical(all_max));
        assert_eq!(pml4_index(all_max), 0x1FF);
        assert_eq!(pdpt_index(all_max), 0x1FF);
        assert_eq!(pd_index(all_max), 0x1FF);
        assert_eq!(pt_index(all_max), 0x1FF);
        assert_eq!(page_offset(all_max), 0xFFF);
    }

    #[test]
    fn max_page_offset_is_4095() {
        let addr_with_max_offset: u64 = PAGE_SIZE - 1; // 0xFFF
        assert_eq!(page_offset(addr_with_max_offset), 4095);
    }

    // ---- index and offset bounds always hold -----------------------------

    #[test]
    fn all_indices_are_in_range() {
        // spot-check a handful of addresses that span both address halves.
        let addrs: &[u64] = &[
            0x0000_0000_0000_0000,
            0x0000_7FFF_FFFF_FFFF, // highest lower-half canonical
            0xFFFF_8000_0000_0000, // lowest upper-half canonical
            0xFFFF_FFFF_FFFF_FFFF,
            KNOWN_VADDR,
        ];
        for &v in addrs {
            assert!(pml4_index(v) < TABLE_ENTRIES, "pml4_index out of range for {v:#x}");
            assert!(pdpt_index(v) < TABLE_ENTRIES, "pdpt_index out of range for {v:#x}");
            assert!(pd_index(v) < TABLE_ENTRIES, "pd_index out of range for {v:#x}");
            assert!(pt_index(v) < TABLE_ENTRIES, "pt_index out of range for {v:#x}");
            assert!(page_offset(v) < PAGE_SIZE, "page_offset out of range for {v:#x}");
        }
    }

    // ---- round-trip: from_parts(indices(v), offset(v)) == v for canonical v

    #[test]
    fn roundtrip_known_vaddr() {
        let reconstructed = from_parts(indices(KNOWN_VADDR), page_offset(KNOWN_VADDR));
        assert_eq!(reconstructed, KNOWN_VADDR);
    }

    #[test]
    fn roundtrip_zero() {
        let v: u64 = 0;
        assert_eq!(from_parts(indices(v), page_offset(v)), v);
    }

    #[test]
    fn roundtrip_max_lower_half() {
        let v: u64 = 0x0000_7FFF_FFFF_FFFF;
        assert_eq!(from_parts(indices(v), page_offset(v)), v);
    }

    #[test]
    fn roundtrip_min_upper_half() {
        let v: u64 = 0xFFFF_8000_0000_0000;
        assert_eq!(from_parts(indices(v), page_offset(v)), v);
    }

    #[test]
    fn roundtrip_all_ones_canonical() {
        let v: u64 = 0xFFFF_FFFF_FFFF_FFFF;
        assert_eq!(from_parts(indices(v), page_offset(v)), v);
    }

    #[test]
    fn roundtrip_upper_half_address() {
        // a realistic kernel virtual address in the upper half.
        let v: u64 = 0xFFFF_8080_1234_5678;
        assert!(is_canonical(v));
        assert_eq!(from_parts(indices(v), page_offset(v)), v);
    }

    // ---- is_canonical cases ----------------------------------------------

    #[test]
    fn canonical_lower_half() {
        assert!(is_canonical(0x0000_0000_0000_0000));
        assert!(is_canonical(0x0000_0000_0000_0001));
        assert!(is_canonical(0x0000_7FFF_FFFF_FFFF));
    }

    #[test]
    fn canonical_upper_half() {
        assert!(is_canonical(0xFFFF_FFFF_FFFF_FFFF));
        assert!(is_canonical(0xFFFF_8000_0000_0000));
        assert!(is_canonical(0xFFFF_8080_1234_5678));
    }

    #[test]
    fn non_canonical_addresses() {
        // the "canonical hole": bit 47 clear but upper bits non-zero, or
        // bit 47 set but upper bits not all-ones.
        assert!(!is_canonical(0x0000_8000_0000_0000)); // bit 47 set, upper bits = 0
        assert!(!is_canonical(0x1234_0000_0000_0000)); // random non-zero upper bits
        assert!(!is_canonical(0xFFFE_8000_0000_0000)); // bit 47 set, upper not -1
        assert!(!is_canonical(0x8000_0000_0000_0000)); // bit 63 set, bit 47 clear
    }

    // ---- from_parts sign-extension produces canonical addresses ----------

    #[test]
    fn from_parts_lower_half_canonical() {
        // pml4 index 0 => bit 47 = 0 => lower half.
        let addr = from_parts([0, 0, 0, 0], 0);
        assert!(is_canonical(addr));
        assert_eq!(addr, 0);
    }

    #[test]
    fn from_parts_upper_half_canonical() {
        // pml4 index 0x100 sets bit 47 of the assembled 48-bit value,
        // so sign-extension must fill the upper 16 bits with 1s.
        let addr = from_parts([0x100, 0, 0, 0], 0);
        assert!(is_canonical(addr));
        // upper 16 bits should be 0xFFFF after sign-extension.
        assert_eq!(addr >> 48, 0xFFFF);
    }

    // ---- constants sanity ------------------------------------------------

    #[test]
    fn constants_values() {
        assert_eq!(TABLE_ENTRIES, 512);
        assert_eq!(PAGE_SIZE, 4096);
    }
}

// ---------------------------------------------------------------------------
// Kani bounded proof harnesses
// ---------------------------------------------------------------------------
//
// Run with: cargo kani -p jos-core (once cargo-kani is configured in the
// nix shell). The `#[cfg(kani)]` gate keeps these out of the normal build.
// Each harness is intentionally small: Kani verifies the property for ALL
// possible u64 inputs, not a bounded loop, so no `#[kani::unwind]` is needed
// for the arithmetic lemmas (they are straight-line code with no loops).

#[cfg(kani)]
mod kani_proofs {
    use super::{
        TABLE_ENTRIES, PAGE_SIZE,
        from_parts, indices, is_canonical,
        pd_index, pdpt_index, pml4_index, pt_index, page_offset,
    };

    // for any u64 address, page_offset is always strictly less than PAGE_SIZE.
    #[kani::proof]
    fn offset_always_in_range() {
        let v: u64 = kani::any();
        assert!(page_offset(v) < PAGE_SIZE);
    }

    // for any u64 address, every 9-bit index is always strictly less than
    // TABLE_ENTRIES (512). these four harnesses discharge the core arithmetic
    // bounds that the Verus `integer_ring` proofs would express as lemmas.
    #[kani::proof]
    fn pt_index_always_in_range() {
        let v: u64 = kani::any();
        assert!(pt_index(v) < TABLE_ENTRIES);
    }

    #[kani::proof]
    fn pd_index_always_in_range() {
        let v: u64 = kani::any();
        assert!(pd_index(v) < TABLE_ENTRIES);
    }

    #[kani::proof]
    fn pdpt_index_always_in_range() {
        let v: u64 = kani::any();
        assert!(pdpt_index(v) < TABLE_ENTRIES);
    }

    #[kani::proof]
    fn pml4_index_always_in_range() {
        let v: u64 = kani::any();
        assert!(pml4_index(v) < TABLE_ENTRIES);
    }

    // for any canonical address, from_parts(indices(v), page_offset(v)) == v.
    // kani::assume narrows the symbolic input to the canonical subset.
    #[kani::proof]
    fn roundtrip_for_canonical_addresses() {
        let v: u64 = kani::any();
        kani::assume(is_canonical(v));
        assert_eq!(from_parts(indices(v), page_offset(v)), v);
    }

    // from_parts always produces a canonical result (sign-extension is
    // unconditional in the implementation).
    #[kani::proof]
    fn from_parts_always_canonical() {
        let idx0: usize = kani::any();
        let idx1: usize = kani::any();
        let idx2: usize = kani::any();
        let idx3: usize = kani::any();
        let off: u64 = kani::any();
        let v = from_parts([idx0, idx1, idx2, idx3], off);
        assert!(is_canonical(v));
    }
}
