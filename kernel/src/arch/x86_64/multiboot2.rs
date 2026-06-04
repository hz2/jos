//! Minimal multiboot2 boot-information parser.
//!
//! grub passes a pointer to the multiboot2 info structure in the second arg of
//! `kernel_main`. that structure is an 8-byte header (total_size, reserved)
//! followed by a sequence of 8-byte-aligned tags (type, size, payload),
//! terminated by an end tag (type 0). we only need the memory map tag (type 6)
//! to discover usable RAM for the frame allocator.
//!
//! we hand-roll this rather than pull in the `multiboot2` crate: the format is
//! small and stable, and avoiding the dependency keeps the build closed over
//! exactly what we control (no crate-version churn). the info structure lives
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
pub unsafe fn for_each_usable_region(info_ptr: u32, mut callback: impl FnMut(u64, u64)) {
    let base = info_ptr as usize;
    // SAFETY: info_ptr points at the grub-provided info header in identity
    // mapped low memory, valid for the lifetime of the kernel.
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
        let next = offset + (tag.size as usize);
        offset = (next + 7) & !7;
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
