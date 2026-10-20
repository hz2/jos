//! Physical memory management: page-table access and frame allocation.
//!
//! The trampoline identity-maps the first 1 GiB (phys == virt there), so an
//! `OffsetPageTable` with offset 0 is exactly an identity-mapped page-table
//! walker.
//!
//! Which physical memory is free is decided once, by [`plan_memory`]: the
//! available areas of the multiboot2 memory map minus the low megabyte, the
//! kernel image, the info structure, and every boot module, clipped to the
//! identity map. That arithmetic is `jos_core::boot_regions`, Kani-proved. The
//! [`BootstrapFrameAllocator`] hands out frames from the plan for paging and
//! the heap; whatever it has not handed out becomes the root task's untyped
//! memory.

use jos_core::boot_regions::{PhysRange, RegionList, usable_regions};
use jos_core::multiboot2::{BootInformation, MEMORY_AVAILABLE};
use x86_64::structures::paging::{
    FrameAllocator, OffsetPageTable, PageTable, PhysFrame, Size4KiB,
};
use x86_64::registers::control::Cr3;
use x86_64::{PhysAddr, VirtAddr};

use crate::arch::x86_64::multiboot2;
use crate::cap::IDENTITY_MAPPED_LIMIT;

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

/// The end of the kernel image, rounded up to a frame. Everything below it is
/// in use: real-mode and BIOS data, the trampoline's page tables at 0x1000,
/// and the kernel itself, loaded at 1 MiB.
fn reserved_end() -> u64 {
    unsafe extern "C" {
        /// Defined by link.ld at the end of the kernel image.
        static _kernel_end: u8;
    }
    // taking the address of an extern static (never dereferencing it) is safe.
    let kernel_end = core::ptr::addr_of!(_kernel_end) as u64;
    (kernel_end + 0xFFF) & !0xFFF
}

/// How many free ranges a [`MemoryPlan`] tracks.
pub const MAX_REGIONS: usize = 32;

/// The physical memory that is free at boot.
pub struct MemoryPlan {
    /// The free ranges, page aligned and inside the identity map.
    pub free: RegionList<MAX_REGIONS>,
    /// Bytes of available memory above the identity map, which the kernel
    /// cannot reach yet and so leaves out.
    pub ignored: u64,
}

/// Works out which physical memory is free: every available area of the
/// memory map, minus everything below the end of the kernel image, the info
/// structure itself (at `info_range`), and the span holding the boot modules,
/// below the identity-map limit.
#[must_use]
pub fn plan_memory(info: BootInformation<'_>, info_range: PhysRange) -> MemoryPlan {
    // the modules usually sit back to back after the kernel; reserving the span
    // that holds them all covers any number of them.
    let mut modules = PhysRange { start: u64::MAX, end: 0 };
    for module in info.modules() {
        modules.start = modules.start.min(u64::from(module.start));
        modules.end = modules.end.max(u64::from(module.end));
    }
    let reserved = [PhysRange { start: 0, end: reserved_end() }, info_range, modules];
    let available = || {
        info.memory_map()
            .filter(|area| area.area_type == MEMORY_AVAILABLE)
            .map(|area| PhysRange { start: area.base, end: area.base.saturating_add(area.length) })
    };
    let free = usable_regions(available(), &reserved, IDENTITY_MAPPED_LIMIT);
    let ignored = available()
        .map(|area| area.end.saturating_sub(area.start.max(IDENTITY_MAPPED_LIMIT)))
        .fold(0_u64, u64::saturating_add);
    if free.dropped_bytes() != 0 {
        crate::serial_println!(
            "WARNING: the memory map needs more than {} free ranges; {} bytes left out",
            MAX_REGIONS,
            free.dropped_bytes()
        );
    }
    MemoryPlan { free, ignored }
}

/// A frame allocator that hands out 4 KiB frames from the free ranges of a
/// [`MemoryPlan`], in order, never reusing one. It bootstraps paging and the
/// heap; what it has not handed out ([`remaining`](Self::remaining)) becomes
/// untyped memory.
pub struct BootstrapFrameAllocator {
    /// The free ranges, page aligned.
    regions: [PhysRange; MAX_REGIONS],
    /// How many of `regions` are in use.
    region_count: usize,
    /// Index of the region frames are being handed out of.
    current: usize,
    /// Next frame address to hand out within the current region.
    next: u64,
}

impl BootstrapFrameAllocator {
    /// Builds the allocator from the multiboot2 info structure at `info_ptr`,
    /// with the reservations [`plan_memory`] makes.
    ///
    /// # Panics
    ///
    /// If the info structure is malformed: without a memory map there is no
    /// memory to hand out.
    ///
    /// # Safety
    ///
    /// `info_ptr` must be the multiboot2 info pointer grub passed to
    /// `kernel_main`.
    pub unsafe fn new(info_ptr: u32) -> Self {
        // SAFETY: forwarded to this function's contract.
        let (info, range) = unsafe { multiboot2::boot_information(info_ptr) }
            .expect("malformed multiboot2 info structure");
        Self::from_regions(plan_memory(info, range).free.as_slice())
    }

    /// Builds the allocator over `free`, page-aligned ranges no one else uses.
    #[must_use]
    pub fn from_regions(free: &[PhysRange]) -> Self {
        let mut regions = [PhysRange::default(); MAX_REGIONS];
        let count = free.len().min(MAX_REGIONS);
        regions[..count].copy_from_slice(&free[..count]);
        Self { regions, region_count: count, current: 0, next: regions[0].start }
    }

    /// Returns the memory not handed out yet: the rest of the current region
    /// and every region after it.
    pub fn remaining(&self) -> impl Iterator<Item = PhysRange> + '_ {
        let rest = (self.current < self.region_count)
            .then(|| PhysRange { start: self.next, end: self.regions[self.current].end });
        let later = self.regions[..self.region_count].iter().skip(self.current + 1).copied();
        rest.into_iter().chain(later).filter(|r| !r.is_empty())
    }
}

// SAFETY: every frame returned comes from a free range of the memory plan,
// which excludes the kernel, the boot page tables, the info structure, and the
// boot modules, and `next` only ever advances, so no frame is returned twice.
unsafe impl FrameAllocator<Size4KiB> for BootstrapFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        loop {
            if self.current >= self.region_count {
                return None;
            }
            if self.next + 0x1000 > self.regions[self.current].end {
                // exhausted this region; move to the next.
                self.current += 1;
                if self.current < self.region_count {
                    self.next = self.regions[self.current].start;
                }
                continue;
            }
            let addr = self.next;
            self.next += 0x1000;
            return Some(PhysFrame::containing_address(PhysAddr::new(addr)));
        }
    }
}
