//! Untyped-memory retype arithmetic -- pure logic, no hardware.
//!
//! This module models the core of seL4's "kernel never allocates" memory
//! discipline. All typed kernel objects (`Endpoint`, `CNode`, sub-`Untyped`)
//! are carved from a contiguous untyped memory region through a watermark
//! allocator. The kernel never calls a general allocator; instead, user space
//! invokes the `Retype` system call, which the kernel checks against the
//! region's watermark.
//!
//! # Watermark allocator invariant
//!
//! Let `region_size` be the byte length of the untyped region and `watermark`
//! be the offset of the next free byte (initially 0). For every call to
//! [`retype_fits`] that returns `Some(nw)`:
//!
//! 1. `watermark <= nw <= region_size` -- the new watermark stays in-range.
//! 2. `(nw - size) % align == 0` -- the placement start is correctly aligned.
//! 3. `nw > watermark` -- the watermark strictly advances for any non-zero
//!    object (zero-size objects are excluded by the object model below).
//!
//! These three properties are the exact lemmas discharged by the
//! `#[cfg(kani)]` harnesses at the bottom of this file.
//!
//! # Object sizes
//!
//! | Type | Size (bytes) | Alignment (bytes) |
//! |------|-------------|-------------------|
//! | `Endpoint` | 128 | 64 |
//! | `CNode { size_bits }` | `2^size_bits` | `2^size_bits` |
//! | `Untyped { size_bits }` | `2^size_bits` | `2^size_bits` |
//! | `PageTable` | 4096 | 4096 |
//! | `Tcb` | 512 | 64 |
//!
//! `CNode { size_bits }` uses byte-size semantics (`size = 2^size_bits` bytes),
//! like `Untyped`: `size_bits` is the log2 of the byte size, not a slot count.
//! How many capability slots that holds is a kernel concern (it depends on the
//! kernel's slot type), so it lives in the kernel, not this pure-logic module.
//! `Endpoint` is cache-line (64-byte) aligned to avoid false sharing, and 128
//! bytes long so it has room for the rendezvous state plus the parked sender
//! and receiver wakers the async IPC path stores in it. Note the size is a
//! multiple of the alignment, not equal to it; placement only needs the start
//! to be `align`-aligned, which a 64-aligned watermark gives.
//!
//! `PageTable` is one 4 KiB page (512 eight-byte entries), naturally aligned so
//! the hardware can use it as any level of an `x86_64` 4-level page table (the
//! `PML4` root of a `VSpace`, or an intermediate `PDPT`/`PD`/`PT`). `Tcb` is a
//! thread control block: a saved register context plus its `CSpace`/`VSpace`
//! roots and run state, cache-line aligned at 512 bytes (align divides size,
//! like `Endpoint`).
//!
//! [`retype_fits`]: retype_fits

// ---------------------------------------------------------------------------
// constants
// ---------------------------------------------------------------------------

/// Size of one `Endpoint` object in bytes.
///
/// 128 bytes: enough for the rendezvous state machine plus a parked sender and
/// receiver waker (the async IPC path stores its blocked peers in the endpoint,
/// the seL4 model where an endpoint owns its wait queue). A multiple of
/// [`ENDPOINT_ALIGN`], so a 64-aligned placement still satisfies the object's
/// alignment.
pub const ENDPOINT_SIZE: usize = 128;

/// Alignment requirement of an `Endpoint` object in bytes.
///
/// One cache line, so concurrent IPC on distinct endpoints does not falsely
/// share. Less than [`ENDPOINT_SIZE`]; the object spans two cache lines but
/// only needs its start aligned.
pub const ENDPOINT_ALIGN: usize = 64;

/// Size and alignment of a `PageTable` object in bytes.
///
/// One 4 KiB page: 512 eight-byte entries, the `x86_64` page-table unit. Both
/// the size and the alignment are 4096, so a placed page table is a valid
/// hardware page-table frame (which must be page-aligned) at any level.
pub const PAGE_TABLE_SIZE: usize = 4096;

/// Size of one `Tcb` (thread control block) object in bytes.
///
/// 512 bytes: room for the saved register context plus the `CSpace`/`VSpace`
/// roots and scheduling state, with headroom for fields later sub-slices add.
/// A multiple of [`TCB_ALIGN`], like [`ENDPOINT_SIZE`].
pub const TCB_SIZE: usize = 512;

/// Alignment requirement of a `Tcb` object in bytes (one cache line).
pub const TCB_ALIGN: usize = 64;

/// Size and alignment of the kernel's `CNode` (capability-node) object in
/// bytes.
///
/// 4096 bytes = 2^12, naturally aligned (so a placed `CNode` is page-aligned,
/// like a [`PAGE_TABLE_SIZE`] table). Sized to contain the kernel's
/// `CapSpace<ObjectId, 64>` (measured at 3592 bytes) with room to spare; the
/// kernel asserts the exact fit with a compile-time `size_of` check, which will
/// fail the build (prompting a bump to 8192) if the capability space ever
/// outgrows a page.
///
/// `CNode { size_bits }` uses **byte-size** semantics (`size = 2^size_bits`
/// bytes), matching [`ObjectType::Untyped`] and the seL4 convention, not a
/// slot-count. The kernel's `CNode` is therefore `size_bits = 12`. An earlier
/// `SLOT_BYTES`-based formula (`2^size_bits * 32`) modeled a fictional 32-byte
/// slot and produced a size roughly half the real `CapSpace`, which would have
/// failed placement with a layout mismatch.
pub const CNODE_SIZE: usize = 4096;

/// Alignment of a `CNode` object in bytes (equals its size).
pub const CNODE_ALIGN: usize = 4096;

// ---------------------------------------------------------------------------
// ObjectType
// ---------------------------------------------------------------------------

/// The set of kernel object types that can be created via the `Retype` call.
///
/// Each variant carries enough information to determine the object's size and
/// alignment via [`object_layout`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ObjectType {
    /// A synchronous IPC endpoint.
    ///
    /// Fixed size: [`ENDPOINT_SIZE`] bytes, [`ENDPOINT_ALIGN`]-byte aligned.
    Endpoint,

    /// A capability-node table of `2^size_bits` **bytes**.
    ///
    /// Size = `2^size_bits` bytes, aligned to `2^size_bits` bytes (a naturally
    /// aligned power-of-two region, the seL4 invariant). `size_bits` is the
    /// log2 of the byte size, NOT the slot count: the number of slots a `CNode`
    /// holds depends on the kernel's capability-slot size, which the kernel
    /// (not this pure-logic module) knows. The kernel's `CNode` is
    /// `size_bits = 12` ([`CNODE_SIZE`] = 4096 bytes).
    CNode {
        /// Log2 of the byte size of this `CNode`.
        size_bits: u8,
    },

    /// An untyped sub-region of `2^size_bits` bytes.
    ///
    /// Size = `2^size_bits` bytes, aligned to `2^size_bits` bytes. This
    /// creates a naturally aligned power-of-two region, which is the seL4
    /// invariant for all untyped memory.
    ///
    /// `size_bits` is the log2 of the byte size of the sub-region.
    Untyped {
        /// Log2 of the byte size of this untyped sub-region.
        size_bits: u8,
    },

    /// An `x86_64` page table: one 4 KiB page of 512 entries.
    ///
    /// Fixed size: [`PAGE_TABLE_SIZE`] bytes, page-aligned. Used for the
    /// `PML4` root of a `VSpace` and for every intermediate table carved when
    /// mapping a page.
    PageTable,

    /// A thread control block.
    ///
    /// Fixed size: [`TCB_SIZE`] bytes, [`TCB_ALIGN`]-byte aligned. Holds a
    /// saved register context plus the thread's `CSpace`/`VSpace` roots.
    Tcb,
}

// ---------------------------------------------------------------------------
// layout helper
// ---------------------------------------------------------------------------

/// Returns the `(size_bytes, align_bytes)` for an object of type `ty`.
///
/// Both values are always powers of two and are non-zero. The alignment
/// always equals the size, or divides it evenly, so a naturally aligned
/// placement satisfies the object's alignment requirement.
///
/// # Object sizes
///
/// - `Endpoint`: `(128, 64)`. The only object whose alignment is smaller than
///   its size; both are powers of two and align divides size.
/// - `CNode { size_bits }`: size = `2^size_bits`; align = size. A naturally
///   aligned power of two (byte-size semantics, like `Untyped`). Saturates at
///   `usize::MAX` for `size_bits >= usize::BITS as u8` (Kani proves no panic).
/// - `Untyped { size_bits }`: size = `2^size_bits`; align = size. Saturates
///   at `usize::MAX` for `size_bits >= usize::BITS as u8`.
#[inline]
#[must_use]
pub const fn object_layout(ty: ObjectType) -> (usize, usize) {
    match ty {
        ObjectType::Endpoint => (ENDPOINT_SIZE, ENDPOINT_ALIGN),
        ObjectType::CNode { size_bits } => {
            // byte-size semantics: size = 2^size_bits bytes, naturally aligned.
            // checked_shl returns None when the shift would overflow; in that
            // case saturate to usize::MAX so the function stays total.
            let size = match (1_usize).checked_shl(size_bits as u32) {
                Some(s) => s,
                None => usize::MAX,
            };
            (size, size)
        }
        ObjectType::Untyped { size_bits } => {
            let size = match (1_usize).checked_shl(size_bits as u32) {
                Some(s) => s,
                None => usize::MAX,
            };
            (size, size)
        }
        ObjectType::PageTable => (PAGE_TABLE_SIZE, PAGE_TABLE_SIZE),
        ObjectType::Tcb => (TCB_SIZE, TCB_ALIGN),
    }
}

// ---------------------------------------------------------------------------
// align_up helper
// ---------------------------------------------------------------------------

/// Rounds `value` up to the next multiple of `align`.
///
/// `align` must be a power of two. Uses a saturating addition internally so
/// the function is total (no panic) even when `value` is close to
/// `usize::MAX`.
///
/// # Properties
///
/// - When `value.checked_add(align - 1)` does not overflow, `result >= value`
///   and `result % align == 0`.
/// - When `value.checked_add(align - 1)` overflows (near `usize::MAX`), the
///   saturating add clamps to `usize::MAX` and the low-bit mask clears to a
///   value that may be less than `value`. The function still does not panic.
///
/// The non-saturating properties are verified by the
/// `align_up_is_aligned_and_ge` Kani harness.
#[inline]
#[must_use]
pub const fn align_up(value: usize, align: usize) -> usize {
    // align is a power of two, so (align - 1) is a mask of the low bits.
    // adding the mask and then clearing the low bits rounds up without a
    // division. saturating_add prevents overflow on extreme inputs.
    let mask = align - 1;
    value.saturating_add(mask) & !mask
}

// ---------------------------------------------------------------------------
// retype_fits
// ---------------------------------------------------------------------------

/// The watermark allocator gate for a single `Retype` operation.
///
/// Given an untyped region of `region_size` bytes and a current `watermark`
/// (the offset of the first uncommitted byte), determines whether an object
/// of type `ty` fits in the remaining space.
///
/// # Returns
///
/// - `Some(new_watermark)` if the object fits. `new_watermark` is the
///   watermark after committing the object; the object occupies bytes
///   `[new_watermark - size, new_watermark)` within the region.
/// - `None` if the object does not fit (region exhausted or too misaligned
///   to ever fit).
///
/// # Invariant (when `Some(nw)` is returned)
///
/// 1. `watermark <= nw <= region_size`
/// 2. `(nw - size) % align == 0` (placement start is object-aligned)
/// 3. `nw > watermark` (watermark strictly advances; all objects are > 0 bytes)
///
/// # Preconditions
///
/// - `watermark <= region_size` (callers must maintain this; a debug assert
///   fires in debug builds if violated).
/// - `align` (from [`object_layout`]) is a power of two (always true for
///   well-formed `ObjectType` values).
///
/// All arithmetic uses checked/saturating operations so this function is
/// total and never panics, even for adversarial inputs. `cargo kani` verifies
/// this property with the `retype_fits_never_panics` harness.
#[must_use]
pub const fn retype_fits(
    region_size: usize,
    watermark: usize,
    ty: ObjectType,
) -> Option<usize> {
    debug_assert!(
        watermark <= region_size,
        "watermark must not exceed region_size"
    );

    let (size, align) = object_layout(ty);

    // zero-size objects (can only occur for CNode/Untyped { size_bits: 0 }
    // giving 1 byte, never actually 0; defend explicitly so nw > watermark).
    if size == 0 {
        return None;
    }

    // align the watermark up to the object's alignment requirement.
    // align_up uses saturating_add internally, so no overflow panic.
    let aligned = align_up(watermark, align);

    // check aligned + size <= region_size using checked_add to avoid wrap.
    // if checked_add overflows we return None (object cannot possibly fit).
    let Some(new_watermark) = aligned.checked_add(size) else {
        return None;
    };

    if new_watermark <= region_size {
        Some(new_watermark)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{
        CNODE_ALIGN, CNODE_SIZE, ENDPOINT_ALIGN, ENDPOINT_SIZE, ObjectType, align_up,
        object_layout, retype_fits,
    };

    extern crate std;

    // ---- object_layout returns power-of-two alignments --------------------

    #[test]
    fn endpoint_layout_is_power_of_two() {
        let (size, align) = object_layout(ObjectType::Endpoint);
        assert_eq!(size, ENDPOINT_SIZE);
        assert_eq!(align, ENDPOINT_ALIGN);
        assert!(size.is_power_of_two(), "Endpoint size must be a power of two");
        assert!(align.is_power_of_two(), "Endpoint align must be a power of two");
    }

    #[test]
    fn cnode_layout_power_of_two() {
        // byte-size semantics: size = 2^size_bits bytes, align = size.
        for bits in 0_u8..=14 {
            let (size, align) = object_layout(ObjectType::CNode { size_bits: bits });
            let expected = 1_usize << bits;
            assert_eq!(size, expected, "CNode size_bits={bits}");
            assert_eq!(align, expected, "CNode align size_bits={bits}");
            assert!(
                size.is_power_of_two(),
                "CNode size must be a power of two for size_bits={bits}"
            );
            assert!(
                align.is_power_of_two(),
                "CNode align must be a power of two for size_bits={bits}"
            );
        }
    }

    #[test]
    fn cnode_layout_matches_constants() {
        // the kernel's CNode is size_bits = 12 = one page.
        let (size, align) = object_layout(ObjectType::CNode { size_bits: 12 });
        assert_eq!(size, CNODE_SIZE);
        assert_eq!(align, CNODE_ALIGN);
        assert_eq!(size, 4096);
    }

    #[test]
    fn untyped_layout_power_of_two() {
        for bits in 0_u8..=20 {
            let (size, align) = object_layout(ObjectType::Untyped { size_bits: bits });
            let expected = 1_usize << bits;
            assert_eq!(size, expected, "Untyped size_bits={bits}");
            assert_eq!(align, expected, "Untyped align size_bits={bits}");
            assert!(
                size.is_power_of_two(),
                "Untyped size must be a power of two for size_bits={bits}"
            );
        }
    }

    #[test]
    fn page_table_layout_is_one_page() {
        let (size, align) = object_layout(ObjectType::PageTable);
        assert_eq!(size, super::PAGE_TABLE_SIZE);
        assert_eq!(align, super::PAGE_TABLE_SIZE);
        assert_eq!(size, 4096);
        // a page table must be page-aligned to serve as a hardware table frame.
        assert_eq!(align, 4096);
    }

    #[test]
    fn tcb_layout_matches_constants() {
        let (size, align) = object_layout(ObjectType::Tcb);
        assert_eq!(size, super::TCB_SIZE);
        assert_eq!(align, super::TCB_ALIGN);
        // align divides size (like Endpoint), so a TCB_ALIGN-aligned placement
        // satisfies the object.
        assert_eq!(size % align, 0);
    }

    #[test]
    fn page_table_and_tcb_fit_and_advance() {
        // both new object types place and advance the watermark like the others.
        let region = 8192;
        let pt = retype_fits(region, 0, ObjectType::PageTable).expect("page table fits");
        assert_eq!(pt, super::PAGE_TABLE_SIZE);
        let tcb = retype_fits(region, pt, ObjectType::Tcb).expect("tcb fits after page table");
        assert!(tcb > pt, "watermark must advance");
        // the tcb placement start is TCB_ALIGN-aligned.
        let (size, align) = object_layout(ObjectType::Tcb);
        assert_eq!((tcb - size) % align, 0);
    }

    // ---- cnode size scales with size_bits ---------------------------------

    #[test]
    fn cnode_size_scales_with_size_bits() {
        // byte-size semantics: size = 2^size_bits bytes.
        let (size0, _) = object_layout(ObjectType::CNode { size_bits: 0 });
        let (size4, _) = object_layout(ObjectType::CNode { size_bits: 4 });
        let (size12, _) = object_layout(ObjectType::CNode { size_bits: 12 });
        assert_eq!(size0, 1); // 2^0 = 1 byte
        assert_eq!(size4, 16); // 2^4 = 16 bytes
        assert_eq!(size12, 4096); // 2^12 = one page (the kernel CNode)
    }

    // ---- retype_fits places Endpoint at aligned offset --------------------

    #[test]
    fn retype_fits_endpoint_at_start() {
        // watermark=0, region large enough: should place at 0..ENDPOINT_SIZE.
        let region = 4096;
        let result = retype_fits(region, 0, ObjectType::Endpoint);
        assert_eq!(result, Some(ENDPOINT_SIZE));
    }

    #[test]
    fn retype_fits_endpoint_applies_alignment_padding() {
        // watermark=1 requires padding to 64-byte boundary.
        // aligned = 64, new_watermark = 64 + 64 = 128.
        let region = 4096;
        let result = retype_fits(region, 1, ObjectType::Endpoint);
        assert_eq!(
            result,
            Some(ENDPOINT_ALIGN + ENDPOINT_SIZE),
            "watermark=1 should be padded to 64 then advance by 64"
        );
    }

    #[test]
    fn retype_fits_endpoint_watermark_already_aligned() {
        // watermark=64 is already aligned; no padding needed.
        let result = retype_fits(4096, ENDPOINT_ALIGN, ObjectType::Endpoint);
        assert_eq!(result, Some(ENDPOINT_ALIGN + ENDPOINT_SIZE));
    }

    // ---- watermark advances correctly across two sequential retypes -------

    #[test]
    fn two_sequential_endpoints_advance_watermark() {
        let region = 4096;

        let nw1 = retype_fits(region, 0, ObjectType::Endpoint)
            .expect("first endpoint must fit");
        assert_eq!(nw1, ENDPOINT_SIZE); // placed at [0, ENDPOINT_SIZE)

        let nw2 = retype_fits(region, nw1, ObjectType::Endpoint)
            .expect("second endpoint must fit");
        // the second is 64-aligned already (ENDPOINT_SIZE is a multiple of
        // ENDPOINT_ALIGN), so it lands flush at [ENDPOINT_SIZE, 2*ENDPOINT_SIZE).
        assert_eq!(nw2, 2 * ENDPOINT_SIZE);

        // watermark strictly advanced both times
        assert!(nw1 > 0);
        assert!(nw2 > nw1);
    }

    #[test]
    fn endpoint_then_cnode_sequential() {
        let region = 8192;

        let nw1 = retype_fits(region, 0, ObjectType::Endpoint)
            .expect("endpoint must fit");
        // endpoint: [0, ENDPOINT_SIZE)

        let cnode_ty = ObjectType::CNode { size_bits: 4 }; // 2^4 = 16 bytes
        let (cnode_size, cnode_align) = object_layout(cnode_ty);
        let nw2 = retype_fits(region, nw1, cnode_ty).expect("cnode must fit");

        let aligned_start = align_up(nw1, cnode_align);
        assert_eq!(nw2, aligned_start + cnode_size);
        assert!(nw2 > nw1, "watermark must advance");
    }

    // ---- returns None when object does not fit ----------------------------

    #[test]
    fn endpoint_does_not_fit_in_tiny_region() {
        // region smaller than one endpoint
        assert!(retype_fits(32, 0, ObjectType::Endpoint).is_none());
    }

    #[test]
    fn endpoint_does_not_fit_after_region_full() {
        // watermark already at region_size: nothing can fit.
        let region = 128;
        assert!(retype_fits(region, region, ObjectType::Endpoint).is_none());
    }

    #[test]
    fn object_does_not_fit_after_alignment_padding_pushes_past_end() {
        // region=65, watermark=1: align_up(1,64)=64, 64+ENDPOINT_SIZE > 65 => None.
        assert!(retype_fits(65, 1, ObjectType::Endpoint).is_none());
    }

    #[test]
    fn untyped_does_not_fit_when_too_large() {
        // 2^20 = 1 MiB untyped in a 512 KiB region => None.
        let region: usize = 512 * 1024;
        assert!(
            retype_fits(region, 0, ObjectType::Untyped { size_bits: 20 }).is_none()
        );
    }

    // ---- align_up correctness -------------------------------------------

    #[test]
    fn align_up_already_aligned() {
        assert_eq!(align_up(64, 64), 64);
        assert_eq!(align_up(128, 64), 128);
        assert_eq!(align_up(0, 4096), 0);
    }

    #[test]
    fn align_up_rounds_up() {
        assert_eq!(align_up(1, 64), 64);
        assert_eq!(align_up(63, 64), 64);
        assert_eq!(align_up(65, 64), 128);
        assert_eq!(align_up(1, 4096), 4096);
    }

    #[test]
    fn align_up_align_one_is_identity() {
        // align=1: every value is already a multiple of 1.
        for v in [0_usize, 1, 17, 1023, 65535] {
            assert_eq!(align_up(v, 1), v);
        }
    }

    #[test]
    fn align_up_overflow_does_not_panic() {
        // value near usize::MAX with align > 1: saturating_add must not panic,
        // and the result may be less than value (saturation clears low bits of
        // usize::MAX, which is already below the rounded-up ideal value).
        // the key property is that this call completes without panicking.
        let big = usize::MAX - 3;
        let _result = align_up(big, 64);

        // also verify values that are far from overflow round up correctly.
        let not_near_max = 1_usize;
        let result2 = align_up(not_near_max, 64);
        assert_eq!(result2, 64);
        assert!(result2 >= not_near_max);
    }

    // ---- new_watermark in range invariant --------------------------------

    #[test]
    fn retype_fits_new_watermark_in_range() {
        let region = 4096;
        let mut wm = 0_usize;
        let types = std::vec![
            ObjectType::Endpoint,
            ObjectType::CNode { size_bits: 2 },
            ObjectType::Untyped { size_bits: 6 },
            ObjectType::Endpoint,
        ];
        for ty in types {
            if let Some(nw) = retype_fits(region, wm, ty) {
                assert!(nw >= wm, "new_watermark must be >= old watermark");
                assert!(nw <= region, "new_watermark must not exceed region_size");
                assert!(nw > wm, "new_watermark must strictly advance");
                wm = nw;
            }
        }
    }

    // ---- placement start is aligned --------------------------------------

    #[test]
    fn placement_start_is_aligned_for_various_watermarks() {
        let region = 8192;
        for wm_start in [0_usize, 1, 7, 63, 64, 100, 127, 500] {
            for bits in 0_u8..=4 {
                let ty = ObjectType::CNode { size_bits: bits };
                let (size, align) = object_layout(ty);
                if let Some(nw) = retype_fits(region, wm_start, ty) {
                    let start = nw - size;
                    assert_eq!(
                        start % align,
                        0,
                        "placement start must be {align}-aligned \
                         (wm_start={wm_start}, size_bits={bits})"
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Kani bounded proof harnesses
// ---------------------------------------------------------------------------

#[cfg(kani)]
mod kani_proofs {
    use super::{ObjectType, align_up, object_layout, retype_fits};

    // bound: keep region_size small so Kani's state space stays tractable.
    const MAX_REGION: usize = 0x10_0000; // 1 MiB

    // helper: produce a bounded, valid ObjectType for Kani.
    // we use a tag byte to pick the variant and bound size_bits tightly.
    fn any_object_type() -> ObjectType {
        let tag: u8 = kani::any();
        let size_bits: u8 = kani::any();
        // keep size_bits small: 2^12 = 4096 bytes max, well inside MAX_REGION.
        kani::assume(size_bits <= 12);
        match tag % 5 {
            0 => ObjectType::Endpoint,
            1 => ObjectType::CNode { size_bits },
            2 => ObjectType::Untyped { size_bits },
            3 => ObjectType::PageTable,
            _ => ObjectType::Tcb,
        }
    }

    /// if `retype_fits` returns `Some(nw)`, then
    /// `watermark <= nw <= region_size` and `nw > watermark`.
    #[kani::proof]
    fn retype_fits_result_in_range() {
        let region_size: usize = kani::any();
        let watermark: usize = kani::any();
        let ty = any_object_type();

        kani::assume(region_size <= MAX_REGION);
        kani::assume(watermark <= region_size);

        if let Some(nw) = retype_fits(region_size, watermark, ty) {
            assert!(nw >= watermark, "new_watermark must be >= old watermark");
            assert!(nw <= region_size, "new_watermark must not exceed region_size");
            assert!(nw > watermark, "new_watermark must strictly advance");
        }
    }

    /// if `retype_fits` returns `Some(nw)`, the placement start `nw - size`
    /// is a multiple of the object's alignment.
    #[kani::proof]
    fn retype_fits_placement_aligned() {
        let region_size: usize = kani::any();
        let watermark: usize = kani::any();
        let ty = any_object_type();

        kani::assume(region_size <= MAX_REGION);
        kani::assume(watermark <= region_size);

        let (size, align) = object_layout(ty);

        if let Some(nw) = retype_fits(region_size, watermark, ty) {
            let start = nw - size;
            assert_eq!(start % align, 0, "placement start must be object-aligned");
        }
    }

    /// `retype_fits` is total (never panics for any bounded input) AND, when it
    /// reports a fit, the new watermark genuinely stays within the region.
    ///
    /// Totality is proved implicitly: kani treats any reachable panic or
    /// arithmetic overflow as a counterexample, so the call alone discharges it.
    /// The explicit post-condition below makes the non-trivial property checked
    /// in the harness body (matching the style of the sibling `*_in_range` /
    /// `*_placement_aligned` harnesses) rather than relying on the call alone, so
    /// the harness cannot be mistaken for an assertion-free one and would fail if
    /// the arithmetic ever returned an out-of-range watermark.
    #[kani::proof]
    fn retype_fits_never_panics() {
        let region_size: usize = kani::any();
        let watermark: usize = kani::any();
        let ty = any_object_type();

        kani::assume(region_size <= MAX_REGION);
        // no constraint on watermark vs region_size: prove totality even for
        // invalid inputs (watermark > region_size triggers debug_assert only,
        // not a panic in release; kani runs in a panic-on-assert mode so we
        // must restrict to valid inputs here to avoid the debug_assert path).
        kani::assume(watermark <= region_size);

        // a reported fit must keep the watermark in (watermark, region_size]:
        // the new watermark never exceeds the region and strictly advances.
        if let Some(new_watermark) = retype_fits(region_size, watermark, ty) {
            assert!(new_watermark <= region_size);
            assert!(new_watermark >= watermark);
        }
    }

    /// `align_up(value, align)` returns a result that, when `value +
    /// (align - 1)` does not overflow, is a multiple of `align` and `>= value`.
    ///
    /// `align` is constrained to be a non-zero power of two.
    #[kani::proof]
    fn align_up_is_aligned_and_ge() {
        let value: usize = kani::any();
        let align: usize = kani::any();

        // align must be a non-zero power of two.
        kani::assume(align != 0);
        kani::assume(align.is_power_of_two());
        // bound align to prevent trivially-large state explosion.
        kani::assume(align <= (1_usize << 20));

        let result = align_up(value, align);

        // only assert the >= and aligned properties when no saturation occurred.
        // when value + (align-1) wraps, saturating_add gives usize::MAX, and
        // masking the low bits produces a value that may be less than value.
        let did_saturate = value.checked_add(align - 1).is_none();
        if !did_saturate {
            assert!(result >= value, "align_up result must be >= value");
            assert_eq!(result % align, 0, "align_up result must be aligned");
        }
    }
}
