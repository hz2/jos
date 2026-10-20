//! Guard pages in the kernel's identity map.
//!
//! `boot.s` identity-maps the first 1 GiB with 2 MiB pages. Unmapping a single
//! 4 KiB page there, such as the guard page inside every TCB object, first
//! splits the 2 MiB page that holds it into a 4 KiB page table, using the
//! proven [`split_huge_entry`] so no other translation changes. Split tables
//! come from a small static pool, and a region is split at most once.
//!
//! Every address space shares the kernel's lower-half tables (a `VSpace`
//! clones the root entries, which point at the same directory), so a guard
//! page is absent from all of them at once.

use jos_core::page_table::{pd_index, pdpt_index, pml4_index, pt_index};
use jos_core::pte::{PteFlags, encode, flags, frame_addr, is_present, split_huge_entry};
use x86_64::registers::control::Cr3;

use crate::cap::IDENTITY_MAPPED_LIMIT;

/// How many 2 MiB regions of the identity map can be split, one table each.
const SPLIT_TABLES: usize = 16;

/// One page-aligned page table.
#[repr(C, align(4096))]
struct Table([u64; 512]);

/// Tables that replace split 2 MiB pages. Their virtual addresses are their
/// physical ones, since the kernel image is identity-mapped.
static mut POOL: [Table; SPLIT_TABLES] = [const { Table([0; 512]) }; SPLIT_TABLES];
/// How many tables of [`POOL`] are in use.
static mut POOL_USED: usize = 0;

/// Why a page could not be unmapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardError {
    /// The address is not page-aligned or not in the identity-mapped 1 GiB.
    BadAddress,
    /// The page is not mapped the way the identity map maps it.
    NotMapped,
    /// Every split table is in use.
    PoolExhausted,
}

/// Unmaps the 4 KiB page at `addr` from the kernel's identity map, splitting
/// the 2 MiB page that holds it first if needed. Any later access to the page
/// faults.
///
/// # Errors
///
/// [`GuardError::BadAddress`] for an unaligned or out-of-range address,
/// [`GuardError::NotMapped`] if the walk finds no mapping, and
/// [`GuardError::PoolExhausted`] if a split is needed and no table is left.
///
/// # Safety
///
/// Single-CPU with interrupts disabled, and nothing may use the page again.
pub unsafe fn unmap_identity_page(addr: u64) -> Result<(), GuardError> {
    if !addr.is_multiple_of(4096) || addr >= IDENTITY_MAPPED_LIMIT {
        return Err(GuardError::BadAddress);
    }
    let huge = PteFlags::HUGE_PAGE.bits();
    // SAFETY: every table on the walk is identity-mapped kernel memory (the
    // boot tables and the pool), read and written with interrupts disabled on
    // one CPU, per this function's contract.
    unsafe {
        // the active root may be any address space; its lower half is shared.
        let root = Cr3::read().0.start_address().as_u64() as *mut u64;
        let pml4e = *root.add(pml4_index(addr));
        if !is_present(pml4e) {
            return Err(GuardError::NotMapped);
        }
        let pdpte = *(frame_addr(pml4e) as *mut u64).add(pdpt_index(addr));
        if !is_present(pdpte) || pdpte & huge != 0 {
            return Err(GuardError::NotMapped);
        }
        let pde_ptr = (frame_addr(pdpte) as *mut u64).add(pd_index(addr));
        let pde = *pde_ptr;
        if !is_present(pde) {
            return Err(GuardError::NotMapped);
        }
        let table = if pde & huge == 0 {
            // already split (by boot.s for its stack guard, or an earlier call).
            frame_addr(pde) as *mut u64
        } else {
            if POOL_USED >= SPLIT_TABLES {
                return Err(GuardError::PoolExhausted);
            }
            let table = core::ptr::addr_of_mut!(POOL[POOL_USED]).cast::<u64>();
            POOL_USED += 1;
            for i in 0..512 {
                *table.add(i) = split_huge_entry(pde, i);
            }
            // a directory entry naming a table keeps only the access bits.
            let access = (PteFlags::PRESENT | PteFlags::WRITABLE | PteFlags::USER).bits();
            *pde_ptr = encode(table as u64, flags(pde) & access);
            table
        };
        let pte_ptr = table.add(pt_index(addr));
        if !is_present(*pte_ptr) {
            return Err(GuardError::NotMapped);
        }
        *pte_ptr = 0;
    }
    // the 2 MiB translation may be cached as one entry, so drop them all.
    x86_64::instructions::tlb::flush_all();
    Ok(())
}
