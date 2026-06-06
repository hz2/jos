//! Minimal multiboot2 boot-information parser.
//!
//! Grub passes a pointer to the multiboot2 info structure in the second arg of
//! `kernel_main`. That structure is an 8-byte header (total_size, reserved)
//! followed by a sequence of 8-byte-aligned tags (type, size, payload),
//! terminated by an end tag (type 0). We only need the memory map tag (type 6)
//! to discover usable RAM for the frame allocator.
//!
//! We hand-roll this rather than pull in the `multiboot2` crate: the format is
//! small and stable, and avoiding the dependency keeps the build closed over
//! exactly what we control (no crate-version churn). The info structure lives
//! in low memory, which our trampoline identity-maps, so the pointer is valid
//! to read directly.

/// Memory area type for usable RAM in a multiboot2 memory map entry.
pub const MMAP_AVAILABLE: u32 = 1;

// the 8-byte info-structure header at the multiboot2 info pointer.
#[repr(C)]
struct InfoHeader {
    total_size: u32,
    _reserved: u32,
}

// the 8-byte header that precedes every tag's payload.
#[repr(C)]
struct TagHeader {
    tag_type: u32,
    size: u32,
}

// the memory map tag's payload header, before the entries.
#[repr(C)]
struct MmapPayload {
    entry_size: u32,
    _entry_version: u32,
}

// one memory map entry.
#[repr(C)]
struct MmapEntry {
    base_addr: u64,
    length: u64,
    typ: u32,
    _reserved: u32,
}

/// Invokes `callback(base, length)` for each usable (`type == 1`) memory map
/// region in the multiboot2 info structure.
///
/// # Safety
///
/// `info_ptr` must be the multiboot2 info pointer grub passed to `kernel_main`,
/// and the whole info structure at that address must be readable (it is, under
/// the trampoline's identity map of low memory). Call at most once per boot.
pub unsafe fn for_each_usable_region(info_ptr: u32, callback: impl FnMut(u64, u64)) {
    // SAFETY: info_ptr points at the grub-provided info header in identity
    // mapped low memory, valid for the lifetime of the kernel (per this fn's
    // contract). walk_tags reads only within [base, base + total_size).
    unsafe { walk_tags(info_ptr as usize, callback) }
}

// walks the multiboot2 tags at `base`, invoking `callback` for each usable mmap
// region. factored out of the public entry so the tag-walk loop (and its
// malformed-tag termination guarantee) can be unit-tested against a synthetic
// buffer without a real grub pointer.
//
// # Safety
//
// `base` must point at a readable multiboot2 info structure: an `InfoHeader`
// followed by `total_size - 8` bytes of tags, all readable.
unsafe fn walk_tags(base: usize, mut callback: impl FnMut(u64, u64)) {
    // SAFETY: per the contract, base points at a readable InfoHeader.
    let header = unsafe { &*(base as *const InfoHeader) };
    let total_size = header.total_size as usize;

    // tags start right after the 8-byte info header.
    let mut offset = core::mem::size_of::<InfoHeader>();
    while offset + core::mem::size_of::<TagHeader>() <= total_size {
        let tag_addr = base + offset;
        // SAFETY: tag_addr is within [header_end, total_size), inside the
        // identity-mapped info structure grub guarantees is valid.
        let tag = unsafe { &*(tag_addr as *const TagHeader) };

        if tag.tag_type == 0 {
            break; // end tag
        }

        if tag.tag_type == 6 {
            for_each_mmap_entry(tag_addr, tag.size as usize, &mut callback);
        }

        // advance to the next tag, rounding the size up to an 8-byte boundary.
        // a well-formed tag has size >= the 8-byte TagHeader; a malformed tag
        // with size < that (in particular size == 0) would otherwise advance by
        // 0 once rounded (offset is always 8-aligned here), spinning forever and
        // hanging the boot with no diagnostic. clamp the step to at least one
        // TagHeader so the walk always makes progress and terminates. grub never
        // emits such a tag, but a fuzzer, a broken loader, or a non-grub
        // multiboot2 source could, and a hang is the worst failure mode.
        let step = (tag.size as usize).max(core::mem::size_of::<TagHeader>());
        offset += (step + 7) & !7;
    }
}

// walks the entries of a memory map tag, calling `callback` for usable ones.
fn for_each_mmap_entry(tag_addr: usize, tag_size: usize, callback: &mut impl FnMut(u64, u64)) {
    let payload_addr = tag_addr + core::mem::size_of::<TagHeader>();
    // SAFETY: a type-6 tag is large enough to hold its payload header; the tag
    // lies within the identity-mapped info structure.
    let payload = unsafe { &*(payload_addr as *const MmapPayload) };
    let entry_size = payload.entry_size as usize;
    if entry_size < core::mem::size_of::<MmapEntry>() {
        return; // malformed; nothing safe to read
    }

    let entries_start = payload_addr + core::mem::size_of::<MmapPayload>();
    let entries_end = tag_addr + tag_size;
    let mut entry_addr = entries_start;
    while entry_addr + entry_size <= entries_end {
        // SAFETY: entry_addr + entry_size is within the tag bounds, inside the
        // identity-mapped info structure.
        let entry = unsafe { &*(entry_addr as *const MmapEntry) };
        if entry.typ == MMAP_AVAILABLE {
            callback(entry.base_addr, entry.length);
        }
        entry_addr += entry_size;
    }
}

#[cfg(test)]
mod tests {
    use super::{walk_tags, TagHeader};

    // a 64-byte, 8-aligned scratch buffer for a synthetic multiboot2 info
    // structure. align(8) matches the multiboot2 tag-alignment the walker
    // assumes, so building tags in it mirrors a real info structure.
    #[repr(C, align(8))]
    struct Buf([u8; 64]);

    // writes a u32 little-endian at byte offset `at`.
    fn put_u32(buf: &mut Buf, at: usize, v: u32) {
        buf.0[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    // builds an InfoHeader(total_size) at offset 0; returns the base address.
    fn header(buf: &mut Buf, total_size: u32) -> usize {
        put_u32(buf, 0, total_size); // total_size
        put_u32(buf, 4, 0); // reserved
        core::ptr::from_ref(buf).cast::<u8>() as usize
    }

    // the regression test for the zero-size-tag infinite loop: a malformed tag
    // with size == 0 must not wedge the walker. before the fix, advancing by a
    // rounded size of 0 left offset unchanged and the while loop spun forever
    // (hanging the boot); the step-clamp to one TagHeader makes it terminate.
    // reaching the assertion at all proves no hang.
    #[test_case]
    fn zero_size_tag_does_not_loop_forever() {
        let mut buf = Buf([0; 64]);
        // header says the whole 64-byte buffer is tags.
        let base = header(&mut buf, 64);
        // a non-end tag (type 9 = boot command line, arbitrary non-zero,
        // non-mmap) with size 0: the malformed case.
        put_u32(&mut buf, 8, 9); // tag_type
        put_u32(&mut buf, 12, 0); // size == 0 (malformed)
        // the rest of the buffer is zero, so once the walker steps past the bad
        // tag it eventually reads a type-0 end tag and stops.

        let mut count = 0;
        // SAFETY: base points at our 8-aligned Buf holding a valid InfoHeader
        // and 64 bytes of readable tag space; walk_tags reads only within it.
        unsafe {
            walk_tags(base, |_, _| count += 1);
        }
        // no usable mmap tag present, so no callback; the point is that we got
        // here without hanging.
        assert_eq!(count, 0, "no mmap tag, so no usable region");
    }

    // a well-formed tag with size < the 8-byte TagHeader is also malformed and
    // must terminate (the same clamp covers size 1..7).
    #[test_case]
    fn undersize_tag_does_not_loop_forever() {
        let mut buf = Buf([0; 64]);
        let base = header(&mut buf, 64);
        put_u32(&mut buf, 8, 9);
        put_u32(&mut buf, 12, 3); // size 3 < 8-byte TagHeader (malformed)

        let mut count = 0;
        // SAFETY: as above; base is our readable 8-aligned buffer.
        unsafe {
            walk_tags(base, |_, _| count += 1);
        }
        assert_eq!(count, 0);
    }

    // a well-formed end tag terminates immediately, and a well-formed non-mmap
    // tag is skipped: confirms the fix did not break normal walking.
    #[test_case]
    fn well_formed_tags_walk_and_terminate() {
        let mut buf = Buf([0; 64]);
        let base = header(&mut buf, 64);
        // a well-formed non-mmap tag: type 9, size = one TagHeader (8 bytes).
        put_u32(&mut buf, 8, 9);
        put_u32(&mut buf, 12, core::mem::size_of::<TagHeader>() as u32);
        // next tag at offset 16 (8 + 8): an end tag (type 0).
        put_u32(&mut buf, 16, 0);
        put_u32(&mut buf, 20, 8);

        let mut count = 0;
        // SAFETY: as above.
        unsafe {
            walk_tags(base, |_, _| count += 1);
        }
        assert_eq!(count, 0, "no mmap tag");
    }
}
