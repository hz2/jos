//! Physical memory management: page-table access and frame allocation.
//!
//! This is blog_os posts 08-09, adapted to jos's setup. The big divergence:
//! blog_os gets a complete physical-memory map at a `physical_memory_offset`
//! from the bootloader crate. Our trampoline instead identity-maps the first
//! 1 GiB (phys == virt there), so we use an `OffsetPageTable` with offset 0,
//! which is exactly an identity-mapped page-table walker.
//!
//! Frame allocation is bootstrapped by `BootstrapFrameAllocator`, a stateless
//! iterator over the multiboot2 usable regions (no backing storage needed,
//! which solves the chicken-and-egg with the heap). Once the heap is live the
//! verified `jos_core` bitmap allocator can take over.

use x86_64::structures::paging::{
    FrameAllocator, OffsetPageTable, PageTable, PhysFrame, Size4KiB,
};
use x86_64::registers::control::Cr3;
use x86_64::{PhysAddr, VirtAddr};

use crate::arch::x86_64::multiboot2;

/// Returns a mutable reference to the active level-4 page table.
///
/// # Safety
///
/// The caller must guarantee the first 1 GiB of physical memory is identity
/// mapped (established by `boot.s` before `kernel_main`), and must not create a
/// second live `&mut` to the same table while this one is in use.
pub unsafe fn active_level4_table() -> &'static mut PageTable {
    // Cr3::read returns the physical frame of the active PML4. under the
    // identity map its physical address is also its virtual address.
    let (l4_frame, _) = Cr3::read();
    let phys = l4_frame.start_address().as_u64();
    let ptr = phys as *mut PageTable;
    // SAFETY: phys == virt under the identity map, the PML4 frame is page
    // aligned (Cr3 holds a frame), and PageTable is repr(C); the caller
    // guarantees no aliasing.
    unsafe { &mut *ptr }
}

/// Builds an `OffsetPageTable` over the identity-mapped address space.
///
/// With a physical offset of 0, every page-table frame access computes
/// `virt = 0 + phys = phys`, i.e. the identity map our trampoline installed.
///
/// # Safety
///
/// Same requirements as [`active_level4_table`].
pub unsafe fn init_mapper() -> OffsetPageTable<'static> {
    // SAFETY: per this function's contract, forwarded to active_level4_table.
    let l4 = unsafe { active_level4_table() };
    // SAFETY: offset 0 is correct for the identity map; all page-table frames
    // we touch live in the identity-mapped low 1 GiB.
    unsafe { OffsetPageTable::new(l4, VirtAddr::new(0)) }
}

/// First physical address the frame allocator may hand out. Everything below
/// is reserved: the trampoline page tables (at 0x1000), real-mode/BIOS data,
/// and the kernel image (loaded at 1 MiB). We round the kernel end up to a
/// frame boundary.
fn reserved_end() -> u64 {
    unsafe extern "C" {
        // defined by link.ld at the end of the kernel image.
        static _kernel_end: u8;
    }
    // taking the address of an extern static (never dereferencing it) is safe.
    let kernel_end = core::ptr::addr_of!(_kernel_end) as u64;
    (kernel_end + 0xFFF) & !0xFFF
}

/// A frame allocator that hands out 4 KiB frames from the multiboot2 usable
/// regions, in order, never reusing one. Used to bootstrap paging and the heap
/// before the verified bitmap allocator (which needs heap storage) is online.
pub struct BootstrapFrameAllocator {
    // usable regions, clipped to frame boundaries, as (start, end) pairs.
    regions: [(u64, u64); MAX_REGIONS],
    region_count: usize,
    // index of the region we are currently handing frames out of.
    current: usize,
    // next frame address to return within the current region.
    next: u64,
}

const MAX_REGIONS: usize = 32;

impl BootstrapFrameAllocator {
    /// Builds the allocator from the multiboot2 memory map, skipping all frames
    /// below the kernel image (so it never collides with the kernel, the boot
    /// page tables, or the multiboot2 info structure).
    ///
    /// # Safety
    ///
    /// `info_ptr` must be the multiboot2 info pointer grub passed to
    /// `kernel_main`. The frames this allocator returns must be genuinely
    /// unused, which holds because everything loaded so far sits below the
    /// reserved boundary.
    pub unsafe fn new(info_ptr: u32) -> Self {
        let mut allocator = Self {
            regions: [(0, 0); MAX_REGIONS],
            region_count: 0,
            current: 0,
            next: 0,
        };

        // SAFETY: forwarded to the caller's contract on info_ptr.
        unsafe {
            multiboot2::for_each_usable_region(info_ptr, |base, len| {
                if allocator.region_count >= MAX_REGIONS {
                    // out of region slots: this drops usable RAM. warn rather
                    // than drop silently, so an over-fragmented memory map is
                    // visible on the serial log instead of mysteriously short on
                    // memory. the cue to bump MAX_REGIONS. (QEMU/grub hand us a
                    // handful of regions, so this is not expected to fire.)
                    crate::serial_println!(
                        "WARNING: multiboot2 memory map has more than {} usable regions; \
                         dropping region at {:#x} (+{:#x}). bump MAX_REGIONS.",
                        MAX_REGIONS, base, len
                    );
                    return;
                }
                // clip to frame boundaries: round the start up, the end down.
                let start = (base + 0xFFF) & !0xFFF;
                let end = (base + len) & !0xFFF;
                if end > start {
                    allocator.regions[allocator.region_count] = (start, end);
                    allocator.region_count += 1;
                }
            });
        }

        allocator.skip_reserved(reserved_end());
        allocator
    }

    // positions `current`/`next` past the reserved boundary so the first frame
    // handed out is the first free frame at or above `boundary`.
    fn skip_reserved(&mut self, boundary: u64) {
        while self.current < self.region_count {
            let (start, end) = self.regions[self.current];
            if end <= boundary {
                self.current += 1;
                continue;
            }
            self.next = start.max(boundary);
            self.next = (self.next + 0xFFF) & !0xFFF;
            return;
        }
    }
}

// SAFETY: every frame returned comes from a multiboot2 AVAILABLE region above
// the reserved boundary (kernel + boot page tables + info struct), and `next`
// only ever advances, so no frame is returned twice.
unsafe impl FrameAllocator<Size4KiB> for BootstrapFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        loop {
            if self.current >= self.region_count {
                return None;
            }
            let (_, end) = self.regions[self.current];
            if self.next + 0x1000 > end {
                // exhausted this region; move to the next.
                self.current += 1;
                if self.current < self.region_count {
                    self.next = self.regions[self.current].0;
                }
                continue;
            }
            let addr = self.next;
            self.next += 0x1000;
            return Some(PhysFrame::containing_address(PhysAddr::new(addr)));
        }
    }
}
