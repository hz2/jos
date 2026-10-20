//! Capability slots, objects, and mappings for a program that owns its
//! capability space and address space, as the root task does.
//!
//! The kernel never allocates: every object comes from retyping untyped memory
//! into an empty slot, and every page table on the way to a mapping is one the
//! program supplies. These helpers keep that bookkeeping out of programs: a
//! slot allocator over the empty slots the kernel reported, retyping from the
//! first untyped region with room, and mapping that installs missing tables.
//! The state is shared by every thread of the program and updated with atomics.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::abi::{
    BootInfo, IpcSyscallError, MAX_BOOT_UNTYPED, RetypeSyscallError, map_flags, root_slot,
};
use crate::sys::{self, Slot};
use jos_core::untyped::ObjectType;

/// Why a helper could not do what it was asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The capability space has no empty slot left.
    NoSlot,
    /// No untyped region has room for the object.
    NoMemory,
    /// A retype failed for another reason.
    Retype(RetypeSyscallError),
    /// A syscall refused.
    Ipc(IpcSyscallError),
}

impl From<IpcSyscallError> for Error {
    fn from(e: IpcSyscallError) -> Self {
        Self::Ipc(e)
    }
}

/// One bit per slot of the capability space: set when the slot is free.
static FREE_SLOTS: AtomicU64 = AtomicU64::new(0);

/// The untyped slots, from the boot information, plus one; zero ends the list.
static UNTYPED: [AtomicU64; MAX_BOOT_UNTYPED] = [const { AtomicU64::new(0) }; MAX_BOOT_UNTYPED];

/// Index of the untyped region retyping starts with: earlier ones are full.
static UNTYPED_CURSOR: AtomicUsize = AtomicUsize::new(0);

/// Records the empty slots and the untyped regions the kernel reported.
pub fn init(boot: &BootInfo) {
    let mut free = 0u64;
    for slot in boot.empty.start..boot.empty.end.min(64) {
        free |= 1 << slot;
    }
    FREE_SLOTS.store(free, Ordering::Relaxed);
    for (entry, untyped) in UNTYPED.iter().zip(boot.untyped()) {
        entry.store(untyped.slot + 1, Ordering::Relaxed);
    }
}

/// Takes an empty slot.
///
/// # Errors
///
/// [`Error::NoSlot`] if every slot is in use.
pub fn alloc_slot() -> Result<Slot, Error> {
    let mut free = FREE_SLOTS.load(Ordering::Relaxed);
    loop {
        if free == 0 {
            return Err(Error::NoSlot);
        }
        let slot = u64::from(free.trailing_zeros());
        match FREE_SLOTS.compare_exchange_weak(free, free & !(1 << slot), Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Ok(slot),
            Err(now) => free = now,
        }
    }
}

/// Returns `slot`, now empty, to the allocator.
pub fn free_slot(slot: Slot) {
    if slot < 64 {
        FREE_SLOTS.fetch_or(1 << slot, Ordering::Relaxed);
    }
}

/// Retypes an object of type `ty` into a fresh slot, from the first untyped
/// region with room, and returns the slot.
///
/// # Errors
///
/// [`Error::NoSlot`], [`Error::NoMemory`] once every region is full, or the
/// retype error otherwise.
pub fn retype(ty: ObjectType) -> Result<Slot, Error> {
    let slot = alloc_slot()?;
    let mut index = UNTYPED_CURSOR.load(Ordering::Relaxed);
    while let Some(untyped) = UNTYPED.get(index).and_then(|u| u.load(Ordering::Relaxed).checked_sub(1)) {
        match sys::retype(untyped, ty, slot) {
            Ok(()) => return Ok(slot),
            Err(RetypeSyscallError::NoRoom) => {
                // regions only fill up, so later retypes can skip this one.
                index += 1;
                UNTYPED_CURSOR.fetch_max(index, Ordering::Relaxed);
            }
            Err(e) => {
                free_slot(slot);
                return Err(Error::Retype(e));
            }
        }
    }
    free_slot(slot);
    Err(Error::NoMemory)
}

/// Revokes the capability in `slot` and returns the slot to the allocator.
///
/// # Errors
///
/// Why the revoke was refused.
pub fn release(slot: Slot) -> Result<(), Error> {
    sys::revoke(slot)?;
    free_slot(slot);
    Ok(())
}

/// Maps the frame in `frame` at `vaddr` in this program's address space with
/// `flags` ([`map_flags`]), retyping and installing whatever page tables the
/// path is missing. The tables stay installed for later mappings.
///
/// # Errors
///
/// Why a retype or a mapping was refused.
pub fn map(frame: Slot, vaddr: u64, flags: u64) -> Result<(), Error> {
    // at most one table per level is missing: a PDPT, a PD, and a PT.
    for _ in 0..4 {
        match sys::map_frame(root_slot::VSPACE, frame, vaddr, flags) {
            Err(IpcSyscallError::MissingTable) => {
                let table = retype(ObjectType::PageTable)?;
                sys::map_page_table(root_slot::VSPACE, table, vaddr)?;
            }
            done => return done.map_err(Error::Ipc),
        }
    }
    Err(Error::Ipc(IpcSyscallError::MissingTable))
}

/// Retypes a fresh frame and maps it writable at `vaddr`, returning its slot.
///
/// # Errors
///
/// As [`retype`] and [`map`].
pub fn map_new_page(vaddr: u64) -> Result<Slot, Error> {
    let frame = retype(ObjectType::Frame)?;
    if let Err(e) = map(frame, vaddr, map_flags::WRITE) {
        let _ = release(frame);
        return Err(e);
    }
    Ok(frame)
}
