//! Kernel heap initialization (blog_os post 10).
//!
//! Maps a fixed virtual range to fresh physical frames and hands it to the
//! global `linked_list_allocator`, after which `alloc` types (Box, Vec, ...)
//! work.
//!
//! Jos divergence: the heap lives at an UPPER-HALF virtual address, not in the
//! identity-mapped low 1 GiB. That region is mapped with 2 MiB huge pages by
//! the trampoline, so a 4 KiB `map_to` there fails with ParentEntryHugePage.
//! An upper-half address has no existing mapping, so `map_to` builds a fresh
//! 4 KiB page-table hierarchy for it.

use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;

/// Heap start: a canonical upper-half virtual address, clear of the identity
/// map. Recognizable in debug output.
pub const HEAP_START: usize = 0xFFFF_8000_0000_0000;
/// Heap size: 1 MiB to start.
pub const HEAP_SIZE: usize = 1024 * 1024;

/// Maps the heap range to fresh frames and initializes the global allocator.
///
/// # Errors
///
/// Returns `MapToError` if the frame allocator runs out of frames while
/// mapping the heap pages.
pub fn init_heap(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapToError<Size4KiB>> {
    let start = VirtAddr::new(HEAP_START as u64);
    let end = start + (HEAP_SIZE as u64 - 1);
    let start_page = Page::containing_address(start);
    let end_page = Page::containing_address(end);

    for page in Page::range_inclusive(start_page, end_page) {
        let frame = frame_allocator
            .allocate_frame()
            .ok_or(MapToError::FrameAllocationFailed)?;
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        // SAFETY: each page is in the fresh, previously-unmapped heap range, and
        // each frame is a unique frame just handed out by the allocator, so this
        // creates a new mapping with no aliasing. the heap is not yet live, so
        // nothing races with these mappings.
        unsafe {
            mapper.map_to(page, frame, flags, frame_allocator)?.flush();
        }
    }

    // SAFETY: the whole [HEAP_START, HEAP_START + HEAP_SIZE) range was just
    // mapped to writable frames, no allocations have happened yet, and init is
    // called exactly once, so the allocator owns this region exclusively.
    unsafe {
        crate::ALLOCATOR.lock().init(HEAP_START, HEAP_SIZE);
    }

    Ok(())
}
