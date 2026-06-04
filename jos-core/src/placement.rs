//! Placement of kernel objects into untyped memory.
//!
//! This is the in-bounds, correctly-aligned `ptr::write` that carves a typed
//! kernel object out of an untyped region's bytes, with no heap allocation
//! (the seL4 "kernel never allocates" discipline). It operates on a `&mut [u8]`
//! slice rather than a raw physical address, so the slice carries valid Rust
//! provenance and the whole placement core is exercisable under Miri and host
//! tests. The kernel turns a static array or a physical frame into that slice;
//! that acquisition is the only part that stays kernel-only.
//!
//! The size and alignment come from the Kani-verified [`crate::untyped`] module:
//! [`retype_fits`](crate::untyped::retype_fits) decides whether the object fits
//! at the current watermark and where it lands. This module then does the
//! actual placement at that offset.
//!
//! # Invariant
//!
//! On success, [`place`] returns `(start, new_watermark)` where:
//! - `watermark <= start`, `start + size_of::<T>() == new_watermark <= region.len()`
//! - `start` is aligned to `align_of::<T>()`
//! - the bytes `[start, new_watermark)` now hold a valid `T` (written via
//!   `ptr::write`, which does not read or drop the prior bytes)

use crate::untyped::{object_layout, retype_fits, ObjectType};

/// Errors from [`place`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceError {
    /// The object does not fit at the current watermark (region exhausted).
    DoesNotFit,
    /// `T`'s layout does not match the `ObjectType`'s declared size/alignment.
    /// This is a programming error: the caller paired the wrong Rust type with
    /// the wrong `ObjectType`.
    LayoutMismatch,
    /// `region`'s base address is not aligned enough for `T`. The caller must
    /// provide a region whose start is at least `align_of::<T>()`-aligned.
    RegionMisaligned,
}

/// Places `value` of type `T` into `region` at the watermark, carving it from
/// untyped memory the way seL4 `Retype` does.
///
/// Returns `(start_offset, new_watermark)` on success: `value` now lives at
/// `region[start_offset..]` and the caller should record `new_watermark` as the
/// region's advanced watermark.
///
/// `ty` must be the [`ObjectType`] whose [`object_layout`] matches `T`'s size
/// and alignment; this is checked (returning [`PlaceError::LayoutMismatch`] on
/// mismatch) so the verified watermark arithmetic and the real type stay in
/// sync.
///
/// # Errors
///
/// - [`PlaceError::DoesNotFit`] if the object does not fit at the watermark.
/// - [`PlaceError::LayoutMismatch`] if `T`'s layout differs from `ty`'s.
/// - [`PlaceError::RegionMisaligned`] if `region`'s base is under-aligned for `T`.
pub fn place<T>(
    region: &mut [u8],
    watermark: usize,
    ty: ObjectType,
    value: T,
) -> Result<(usize, usize), PlaceError> {
    let (decl_size, decl_align) = object_layout(ty);
    // the real type must match the declared layout, or the verified arithmetic
    // is about a different object than the one we are placing.
    if core::mem::size_of::<T>() != decl_size || core::mem::align_of::<T>() != decl_align {
        return Err(PlaceError::LayoutMismatch);
    }

    // the region base must be aligned for T; placement offsets are relative to
    // it, and retype_fits only guarantees the offset is aligned, not the base.
    let base = region.as_mut_ptr();
    if !(base as usize).is_multiple_of(decl_align) {
        return Err(PlaceError::RegionMisaligned);
    }

    // verified arithmetic: does it fit, and where does the watermark advance to.
    let new_watermark = retype_fits(region.len(), watermark, ty).ok_or(PlaceError::DoesNotFit)?;
    let start = new_watermark - decl_size;

    // derive the placement pointer from the region base (never from an integer),
    // preserving provenance over the region's bytes.
    // SAFETY: start <= region.len() - decl_size < region.len() (from
    // retype_fits), so the offset is strictly in bounds and `add` stays within
    // the region's provenance. base is aligned to decl_align (checked above) and
    // start is a multiple of decl_align (retype_fits guarantees the placement is
    // aligned), so base.add(start) is aligned for T. the cast is therefore
    // well-aligned, and the target bytes are owned by `region` (valid provenance,
    // no live aliasing reference into [start, new_watermark) since the watermark
    // only advances). ptr::write neither reads nor drops the prior bytes, so it
    // is correct even though they were uninitialized.
    unsafe {
        let obj_ptr = base.add(start).cast::<T>();
        core::ptr::write(obj_ptr, value);
    }

    Ok((start, new_watermark))
}

#[cfg(test)]
mod tests {
    use super::*;
    // the test harness links std, so we can use std helpers here even though
    // the library itself is no_std.
    extern crate std;
    use std::boxed::Box;

    // a stand-in object whose layout matches ObjectType::Endpoint (64/64).
    #[repr(C, align(64))]
    #[derive(Debug, PartialEq, Eq)]
    struct FakeEndpoint {
        tag: u64,
        rest: [u8; 56],
    }

    impl FakeEndpoint {
        fn new(tag: u64) -> Self {
            Self { tag, rest: [0; 56] }
        }
    }

    // returns a heap-backed byte buffer whose start is `align`-aligned, so the
    // slice has real provenance (for Miri) and a known-aligned base.
    fn aligned_buf(len: usize, align: usize) -> (Box<[u8]>, usize) {
        // over-allocate, then report the offset to the first aligned byte.
        let buf = std::vec![0u8; len + align].into_boxed_slice();
        let base = buf.as_ptr() as usize;
        let offset = (align - (base % align)) % align;
        (buf, offset)
    }

    #[test]
    fn places_endpoint_and_advances_watermark() {
        let (mut buf, off) = aligned_buf(256, 64);
        let region = &mut buf[off..off + 128];
        let (start, new_wm) =
            place(region, 0, ObjectType::Endpoint, FakeEndpoint::new(0xABCD)).unwrap();
        assert_eq!(start, 0);
        assert_eq!(new_wm, 64);
        // read the placed tag back from the first 8 bytes. reading the raw
        // bytes (rather than casting the slice to a more-aligned pointer)
        // sidesteps the alignment-cast lint while still proving the write
        // landed: FakeEndpoint is repr(C) with `tag: u64` first.
        let tag = u64::from_ne_bytes(region[0..8].try_into().unwrap());
        assert_eq!(tag, 0xABCD);
    }

    #[test]
    fn second_placement_respects_alignment_padding() {
        let (mut buf, off) = aligned_buf(256, 64);
        let region = &mut buf[off..off + 200];
        // first endpoint at 0..64.
        let (_, wm1) = place(region, 0, ObjectType::Endpoint, FakeEndpoint::new(1)).unwrap();
        assert_eq!(wm1, 64);
        // second endpoint: watermark 64 is already 64-aligned, lands at 64..128.
        let (start2, wm2) =
            place(region, wm1, ObjectType::Endpoint, FakeEndpoint::new(2)).unwrap();
        assert_eq!(start2, 64);
        assert_eq!(wm2, 128);
    }

    #[test]
    fn does_not_fit_when_region_too_small() {
        let (mut buf, off) = aligned_buf(128, 64);
        let region = &mut buf[off..off + 32]; // smaller than one 64-byte endpoint
        assert_eq!(
            place(region, 0, ObjectType::Endpoint, FakeEndpoint::new(0)),
            Err(PlaceError::DoesNotFit)
        );
    }

    #[test]
    fn layout_mismatch_is_rejected() {
        let (mut buf, off) = aligned_buf(128, 64);
        let region = &mut buf[off..off + 128];
        // u64 (8 bytes) does not match Endpoint's declared 64-byte layout.
        assert_eq!(
            place(region, 0, ObjectType::Endpoint, 0u64),
            Err(PlaceError::LayoutMismatch)
        );
    }

    #[test]
    fn misaligned_region_is_rejected() {
        let (mut buf, off) = aligned_buf(256, 64);
        // start one byte past the aligned base, so the region is not 64-aligned.
        let region = &mut buf[off + 1..off + 1 + 128];
        assert_eq!(
            place(region, 0, ObjectType::Endpoint, FakeEndpoint::new(0)),
            Err(PlaceError::RegionMisaligned)
        );
    }
}
