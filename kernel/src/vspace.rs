//! Per-process address spaces: the retypeable `VSpace` object (cap slice 3c).
//!
//! A [`VSpace`] is a thread's virtual address space, rooted at an `x86_64`
//! `PML4` page table carved from untyped memory (a [`crate::cap::PageTable`]
//! object). It is the jos analogue of seL4's `VSpace` / a Zircon `VmAddress
//! Region` root: the object that `CR3` points at while the owning thread runs.
//!
//! # What this provides
//!
//! - [`VSpace::new`] carves a fresh `PML4` from untyped and clones the kernel's
//!   higher-half mappings into it, so the kernel stays mapped after a `CR3`
//!   switch (otherwise the instruction fetch right after `mov cr3` would fault).
//! - [`VSpace::map_page`] installs a 4 KiB user mapping by hand-walking
//!   `PML4 -> PDPT -> PD -> PT`, carving any missing intermediate table from
//!   untyped and writing entries through the Kani-verified [`jos_core::pte`]
//!   encoder. Every level gets the `USER` bit so the walk is reachable from
//!   ring 3.
//! - [`VSpace::activate`] loads the `PML4` into `CR3`.
//!
//! # Why the math is split out
//!
//! The address-to-index decomposition ([`jos_core::page_table::indices`]) and
//! the entry encoding ([`jos_core::pte::encode`]) are pure, Kani-proven logic
//! in `jos-core`. This module only does the unsafe parts that cannot run under
//! Kani/Miri: dereferencing real table frames and writing `CR3`. The walk
//! itself is therefore a thin, auditable shell over verified arithmetic.
//!
//! # Identity-map assumption
//!
//! Page-table frames are carved from an identity-mapped untyped region, so a
//! table's physical address equals its virtual address and the mapper can both
//! dereference a table (`&mut PageTable`) and install its physical address in a
//! parent entry without an extra translation. This is the same assumption the
//! rest of jos's memory code makes (see `memory.rs`).

use jos_core::page_table::indices;
use jos_core::pte::{self, PteFlags};
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::PhysFrame;
use x86_64::PhysAddr;

use crate::cap::{ObjectId, ObjectKind, PageTable, UntypedRegion};

/// The `PML4` index covering the boot identity map (the low 512 GiB).
///
/// jos's kernel image is loaded at 1 MiB and runs from the boot trampoline's
/// identity map, which lives in `PML4[0]`. The kernel stack, GDT/IDT/TSS, the
/// syscall stack, and the untyped regions all sit in this low range too. A
/// `VSpace` MUST clone this entry, or the instruction fetch immediately after
/// `mov cr3` would fault. The identity-map huge pages carry no `USER` bit, so
/// cloning `PML4[0]` does not expose kernel memory to ring 3.
const IDENTITY_PML4_INDEX: usize = 0;

/// The first `PML4` index belonging to the kernel's higher half.
///
/// `x86_64` canonical addresses split at bit 47; `PML4` indices `256..512`
/// cover the upper half (`0xFFFF_8000_0000_0000` and above), where jos places
/// the kernel heap. A fresh `VSpace` clones these entries (plus the low
/// identity entry above) from the kernel's current `PML4` so kernel code, data,
/// stack, and heap all stay mapped after a `CR3` switch. The lower-half user
/// slots in between (`1..256`, which includes the user window at index 64) are
/// left empty for [`VSpace::map_page`] to fill.
const KERNEL_HALF_START: usize = 256;

/// Errors from [`VSpace`] operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VSpaceError {
    /// The untyped region ran out of space for a page-table object.
    OutOfTables,
    /// A page-table object handle had the wrong kind (a bug: the mapper only
    /// ever stores `PageTable` handles).
    NotAPageTable,
    /// The walk hit an entry already mapped as a huge page, so a 4 KiB mapping
    /// cannot be installed beneath it.
    HugePagePresent,
}

/// A virtual address space rooted at a carved `PML4` page table.
pub struct VSpace {
    // the PML4 object handle. the mapper dereferences it (and the tables it
    // points at) exclusively; jos is single-threaded during these operations.
    pml4: ObjectId,
}

impl VSpace {
    /// Creates a new address space: carves a `PML4` from `untyped` and clones
    /// the kernel's higher-half entries into it.
    ///
    /// # Errors
    ///
    /// [`VSpaceError::OutOfTables`] if `untyped` cannot fit the `PML4`.
    ///
    /// # Safety
    ///
    /// The caller must ensure the kernel's current `PML4` (read from `CR3`) is
    /// the identity-mapped table established at boot, and that no other
    /// reference to the newly carved table aliases it. The cloned higher-half
    /// entries must remain valid for the lifetime of this `VSpace`.
    pub unsafe fn new(untyped: &mut UntypedRegion) -> Result<Self, VSpaceError> {
        let pml4_id = untyped.retype_page_table().ok_or(VSpaceError::OutOfTables)?;
        if pml4_id.kind() != ObjectKind::PageTable {
            return Err(VSpaceError::NotAPageTable);
        }

        // SAFETY: pml4_id was just carved as a PageTable and is not aliased; the
        // mapper is the sole owner. clone the kernel's higher-half entries so
        // kernel code/data/heap stay mapped once this PML4 is loaded into CR3.
        unsafe {
            let pml4 = pml4_id.as_page_table_mut();
            let (kernel_frame, _) = Cr3::read();
            let kernel_pml4 = kernel_frame.start_address().as_u64() as *const PageTable;
            // clone PML4[0] (the low identity map: kernel image, stacks, GDT/
            // IDT/TSS, untyped regions) so the kernel keeps executing across the
            // CR3 load, and PML4[256..512] (the higher-half heap). the lower-half
            // user slots in between start empty; map_page fills them on demand.
            // SAFETY: kernel_pml4 points at the live boot PML4 (identity mapped,
            // so phys == virt), readable for all 512 entries.
            pml4.entries[IDENTITY_PML4_INDEX] = (*kernel_pml4).entries[IDENTITY_PML4_INDEX];
            for i in KERNEL_HALF_START..512 {
                pml4.entries[i] = (*kernel_pml4).entries[i];
            }
        }

        Ok(Self { pml4: pml4_id })
    }

    /// Maps `virt` (a 4 KiB-aligned, lower-half user virtual address) to the
    /// physical frame `phys`, allocating intermediate tables from `untyped`.
    ///
    /// `flags` are the leaf-entry flags (for example `PRESENT | WRITABLE |
    /// USER`); the `PRESENT` and `USER` bits are forced on every intermediate
    /// table entry so the whole walk is present and ring-3 reachable, mirroring
    /// what the `x86_64` crate's `map_to` does for its parent tables.
    ///
    /// # Errors
    ///
    /// [`VSpaceError::OutOfTables`] if a needed table cannot be carved;
    /// [`VSpaceError::HugePagePresent`] if an intermediate entry is a huge page.
    ///
    /// # Safety
    ///
    /// `phys` must be a free physical frame not aliased by another mapping, and
    /// the caller must ensure mapping `virt` introduces no aliasing that breaks
    /// memory safety (the same contract as the `x86_64` crate's `map_to`).
    pub unsafe fn map_page(
        &mut self,
        untyped: &mut UntypedRegion,
        virt: u64,
        phys: u64,
        flags: PteFlags,
    ) -> Result<(), VSpaceError> {
        // verified decomposition: [pml4_idx, pdpt_idx, pd_idx, pt_idx].
        let idx = indices(virt);
        // intermediate entries must be present + writable + user so the walk is
        // reachable from ring 3 and writable pages beneath stay writable.
        let table_flags = PteFlags::PRESENT | PteFlags::WRITABLE | PteFlags::USER;

        // SAFETY: the VSpace owns its table tree exclusively (single-threaded
        // mapping), so taking &mut through the chain does not alias. each
        // next_table call returns a table carved as a PageTable object.
        unsafe {
            let pml4 = self.pml4.as_page_table_mut();
            let pdpt = next_table(&mut pml4.entries[idx[0]], untyped, table_flags)?;
            let pd = next_table(&mut pdpt.entries[idx[1]], untyped, table_flags)?;
            let pt = next_table(&mut pd.entries[idx[2]], untyped, table_flags)?;
            // leaf entry: map the target frame with the requested flags.
            pt.entries[idx[3]] = pte::encode_flags(phys, flags | PteFlags::PRESENT);
        }
        Ok(())
    }

    /// Loads this address space's `PML4` into `CR3`, making it the active
    /// address space.
    ///
    /// # Safety
    ///
    /// The caller must ensure this `VSpace` keeps the currently executing
    /// kernel code, stack, and data mapped (it does, via the higher-half clone
    /// in [`VSpace::new`], provided the kernel lives in the higher half and the
    /// identity-mapped low range is also cloned by the caller if needed). After
    /// this returns, translations use the new tables.
    pub unsafe fn activate(&self) {
        let frame = PhysFrame::containing_address(PhysAddr::new(self.pml4.phys_addr()));
        // SAFETY: frame is this VSpace's PML4, a valid 4 KiB-aligned table that
        // maps the kernel (higher half cloned) and any user pages mapped so far.
        // per this fn's contract the executing context stays mapped across the
        // load, so the next instruction fetch and stack access remain valid.
        unsafe {
            Cr3::write(frame, Cr3Flags::empty());
        }
    }

    /// Returns the physical address of this address space's `PML4` root (its
    /// `CR3` value), for storing in a `Tcb`'s `vspace_root`.
    #[must_use]
    pub fn root_phys(&self) -> u64 {
        self.pml4.phys_addr()
    }
}

/// Follows the page-table entry `entry` to the next-level table, carving a
/// fresh table from `untyped` and installing it if the entry is not present.
///
/// Returns an exclusive reference to the next-level table. `table_flags` are
/// OR-ed into a freshly installed entry (present + writable + user). An entry
/// that is present but a huge page is an error: there is no next-level table to
/// descend into.
///
/// # Safety
///
/// The caller must hold exclusive access to the table containing `entry` and to
/// the whole tree beneath it (jos maps single-threaded), so the returned `&mut`
/// does not alias. Carved tables are identity-mapped (phys == virt).
unsafe fn next_table(
    entry: &mut u64,
    untyped: &mut UntypedRegion,
    table_flags: PteFlags,
) -> Result<&'static mut PageTable, VSpaceError> {
    if pte::is_present(*entry) {
        // a present entry that is a huge page has no child table to walk into.
        if pte::pte_flags(*entry).contains(PteFlags::HUGE_PAGE) {
            return Err(VSpaceError::HugePagePresent);
        }
        let table_phys = pte::frame_addr(*entry);
        let ptr = core::ptr::with_exposed_provenance_mut::<PageTable>(table_phys as usize);
        // SAFETY: a present non-huge entry points at a 4 KiB table frame this
        // mapper carved earlier (identity mapped, so phys == virt), exclusive
        // per this fn's contract.
        return Ok(unsafe { &mut *ptr });
    }

    // not present: carve a new table and install it.
    let table_id = untyped.retype_page_table().ok_or(VSpaceError::OutOfTables)?;
    if table_id.kind() != ObjectKind::PageTable {
        return Err(VSpaceError::NotAPageTable);
    }
    *entry = pte::encode_flags(table_id.phys_addr(), table_flags | PteFlags::PRESENT);
    // SAFETY: table_id was just carved as a PageTable and is not aliased.
    Ok(unsafe { table_id.as_page_table_mut() })
}
