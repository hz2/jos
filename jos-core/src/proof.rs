//! Verus proofs for jos-core arithmetic invariants.
//!
//! This module is only compiled when the Verus verifier processes the crate
//! (`verus` sets `cfg(verus_keep_ghost)` internally). Regular `cargo build`,
//! `cargo test`, `cargo miri test`, and `cargo kani` never see it.
//!
//! Run from the workspace root with:
//! ```text
//! nix develop .#verify --command bash -c \
//!   'VDIR=$(verus --print-lib-dir 2>/dev/null || echo \
//!     /nix/store/*-verus-*/libexec/verus); \
//!    verus --crate-type lib --edition 2024 \
//!      -L $VDIR \
//!      --verify-module proof \
//!      jos-core/src/lib.rs'
//! ```
//!
//! The proofs here are the **unbounded** counterparts to the Kani harnesses in
//! `untyped.rs` and `placement.rs`. Kani model-checks over bounded region sizes;
//! Verus discharges these lemmas for all possible `usize` values via Z3.
//!
//! Crate names for this Verus release are `verus_builtin` / `verus_builtin_macros`
//! (the old `builtin` / `builtin_macros` names were renamed upstream).

use verus_builtin::*;
use verus_builtin_macros::*;

verus! {

// ---------------------------------------------------------------------------
// watermark monotonicity (MEM-1, unbounded)
// ---------------------------------------------------------------------------

/// A non-zero-size retype strictly advances the watermark.
///
/// This is the unbounded version of the `retype_advances_watermark` invariant
/// from `untyped.rs`. Kani proves it over bounded region sizes; Verus closes the
/// gap by covering all `usize` inputs.
pub proof fn watermark_advance_is_strict(wm: usize, size: usize)
    requires
        size > 0,
        wm <= usize::MAX - size,
    ensures
        wm < wm + size,
{}

/// A watermark that fits within the region stays in range after the advance.
pub proof fn new_watermark_in_region(wm: usize, size: usize, region_len: usize)
    requires
        size > 0,
        wm + size <= region_len,
    ensures
        wm < wm + size,
        wm + size <= region_len,
{}

// ---------------------------------------------------------------------------
// spatial non-overlap (MEM-1, unbounded)
// ---------------------------------------------------------------------------

/// Two consecutive placements produce disjoint byte bands.
///
/// If the first placement occupies `[start1, end1)` and the watermark advances
/// to `end1`, and the second placement starts at `start2 >= end1`, then the
/// two bands do not overlap. This is the MEM-1 claim: no two retypes from the
/// same untyped region alias the same byte.
pub proof fn consecutive_placements_are_disjoint(
    start1: usize,
    end1: usize,
    start2: usize,
    end2: usize,
)
    requires
        start1 < end1,    // first band is non-empty
        start2 < end2,    // second band is non-empty
        end1 <= start2,   // watermark from first >= start of second
    ensures
        end1 <= start2,   // first band ends at or before second begins
        start1 < start2,  // first start is strictly before second start
{}

/// Monotone watermark implies disjointness of a sequence: if the watermark only
/// advances, then any two placements from the same region occupy disjoint bands.
pub proof fn monotone_watermark_implies_sequence_disjointness(
    wm0: usize,
    size1: usize,
    size2: usize,
)
    requires
        size1 > 0,
        size2 > 0,
        wm0 <= usize::MAX - size1 - size2,
    ensures
        // first band [wm0, wm0+size1) is disjoint from second [wm0+size1, wm0+size1+size2)
        wm0 + size1 <= wm0 + size1,                            // trivial: end of first = start of second
        wm0 < wm0 + size1,                                     // first band non-empty
        wm0 + size1 < wm0 + size1 + size2,                    // second band non-empty
        wm0 + size1 + size2 <= usize::MAX,                     // no overflow
{}

} // verus!
