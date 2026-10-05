//! Mapping page tables and frames into address spaces on behalf of userspace.
//!
//! Userspace builds an address space from capabilities, the seL4 way: it maps
//! page tables into a `VSpace` one level at a time, then maps frames at the
//! leaves. The kernel never allocates a table itself. Every mapping is recorded
//! in the verified [`MappingTable`], which keeps each object mapped at most once
//! and tells revocation exactly which entries to clear.
//!
//! The syscall layer checks capabilities and rights; this module checks
//! addresses, walks the tables, and keeps the hardware entries and the registry
//! in step.

use jos_core::mapping::{Level, Mapping, MappingTable, RecordError};
use jos_core::page_table::indices;
use jos_core::pte::{self, PteFlags};
use spin::Mutex;
use x86_64::registers::control::Cr3;

use crate::cap::{ObjectId, ObjectKind, PageTable};

/// How many mappings the kernel records at once.
pub const MAX_MAPPINGS: usize = 128;

/// Mapping flags a caller passes in the low bits of a page-aligned address.
pub mod map_flags {
    /// Map the frame writable (the capability must carry `WRITE`).
    pub const WRITE: u64 = 1 << 0;
    /// Map the frame executable (never together with [`WRITE`]).
    pub const EXECUTE: u64 = 1 << 1;
}

/// Every mapping userspace has made, at most one per object.
static MAPPINGS: Mutex<MappingTable<MAX_MAPPINGS>> = Mutex::new(MappingTable::new());

/// Root entries userspace may build under: entry 0 is the kernel's identity
/// map and entries 256 and up are the kernel half, both cloned into every
/// `VSpace` and never touched here.
const USER_ROOT_ENTRIES: core::ops::Range<usize> = 1..256;

/// Flags for an entry that points at a page table: present, writable, and
/// user, so the leaf flags alone decide what ring 3 may do.
const TABLE_FLAGS: PteFlags =
    PteFlags::PRESENT.union(PteFlags::WRITABLE).union(PteFlags::USER);

/// Why a mapping request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    /// The handles do not name a `VSpace` and a table or frame.
    WrongKind,
    /// The address is outside the user half, or has unknown flag bits.
    BadAddress,
    /// A frame's path is missing a page table; map one first.
    MissingTable,
    /// The object is already mapped somewhere.
    AlreadyMapped,
    /// Every level on the path is already present (for a table), or the leaf
    /// is already occupied (for a frame).
    AlreadyPresent,
    /// The path runs into a huge page, which this mapper never creates.
    HugePage,
    /// A frame was asked to be both writable and executable.
    WritableExecutable,
    /// The mapping registry is full.
    Full,
}

impl From<RecordError> for MapError {
    fn from(e: RecordError) -> Self {
        match e {
            RecordError::AlreadyMapped => MapError::AlreadyMapped,
            RecordError::Full => MapError::Full,
        }
    }
}

/// How far a walk got before stopping.
enum Walk {
    /// A table on the path is not mapped yet.
    Missing,
    /// A huge page sits on the path.
    HugePage,
}

/// Returns the table level that the entry at `depth` holds (0 for a root
/// entry, 3 for a last-level entry).
const fn level_at(depth: usize) -> Level {
    match depth {
        0 => Level::Pdpt,
        1 => Level::Pd,
        2 => Level::Pt,
        _ => Level::Frame,
    }
}

/// Returns the depth of the entry that holds an object at `level`.
const fn depth_of(level: Level) -> usize {
    match level {
        Level::Pdpt => 0,
        Level::Pd => 1,
        Level::Pt => 2,
        Level::Frame => 3,
    }
}

/// Walks from the root table at physical address `root` toward `vaddr` and
/// returns the entry at `depth`, without changing anything.
///
/// # Safety
///
/// `root` must be the physical address of a live root table, every present
/// non-huge entry beneath it must point at a live page table, and no other
/// reference into those tables may be live (single-CPU syscall or revoke path).
unsafe fn walk(root: u64, vaddr: u64, depth: usize) -> Result<&'static mut u64, Walk> {
    let idx = indices(vaddr);
    let mut table_addr = root;
    for index in idx.iter().take(depth) {
        // SAFETY: table_addr is a live, identity-mapped page table (the root,
        // or a table a present entry pointed at), per this function's contract.
        let entry = unsafe { table(table_addr) }.entries[*index];
        if !pte::is_present(entry) {
            return Err(Walk::Missing);
        }
        if pte::pte_flags(entry).contains(PteFlags::HUGE_PAGE) {
            return Err(Walk::HugePage);
        }
        table_addr = pte::frame_addr(entry);
    }
    // SAFETY: as above; the reference is the only one into this entry.
    Ok(unsafe { &mut table(table_addr).entries[idx[depth]] })
}

/// Returns the page table at physical address `addr` through the identity map.
///
/// # Safety
///
/// `addr` must be the identity-mapped address of a live page table that no
/// other live reference aliases.
unsafe fn table(addr: u64) -> &'static mut PageTable {
    let ptr = core::ptr::with_exposed_provenance_mut::<PageTable>(addr as usize);
    // SAFETY: per this function's contract.
    unsafe { &mut *ptr }
}

/// Splits a page-aligned address with flag bits into the address and flags,
/// checking it falls in the user half and carries no unknown flags.
fn split(vaddr_flags: u64) -> Result<(u64, u64), MapError> {
    let vaddr = vaddr_flags & !0xfff;
    let flags = vaddr_flags & 0xfff;
    if flags & !(map_flags::WRITE | map_flags::EXECUTE) != 0 {
        return Err(MapError::BadAddress);
    }
    if !USER_ROOT_ENTRIES.contains(&indices(vaddr)[0]) {
        return Err(MapError::BadAddress);
    }
    Ok((vaddr, flags))
}

/// Installs the page table `table` at the first missing level on the path to
/// `vaddr` in the address space `root`.
///
/// # Errors
///
/// See [`MapError`].
pub fn map_table(root: ObjectId, table: ObjectId, vaddr: u64) -> Result<(), MapError> {
    if root.kind() != ObjectKind::VSpace || table.kind() != ObjectKind::PageTable {
        return Err(MapError::WrongKind);
    }
    let (vaddr, flags) = split(vaddr)?;
    if flags != 0 {
        return Err(MapError::BadAddress);
    }
    let mut mappings = MAPPINGS.lock();
    if mappings.find(table.phys_addr()).is_some() {
        return Err(MapError::AlreadyMapped);
    }
    for depth in 0..3 {
        // SAFETY: root is a live VSpace (kind checked); the tables beneath it
        // were installed by this module or carved by the kernel; the registry
        // lock serializes every walk and update on the single-CPU syscall path.
        let entry = match unsafe { walk(root.phys_addr(), vaddr, depth) } {
            Ok(entry) => entry,
            Err(Walk::HugePage) => return Err(MapError::HugePage),
            Err(Walk::Missing) => unreachable!("levels above are present"),
        };
        if pte::is_present(*entry) {
            continue;
        }
        let level = level_at(depth);
        mappings.record(Mapping {
            object: table.phys_addr(),
            vspace: root.phys_addr(),
            vaddr: vaddr & !(level.span() - 1),
            level,
        })?;
        *entry = pte::encode_flags(table.phys_addr(), TABLE_FLAGS);
        return Ok(());
    }
    Err(MapError::AlreadyPresent)
}

/// Maps the frame `frame` at `vaddr` in the address space `root`. The low bits
/// of `vaddr_flags` carry [`map_flags`].
///
/// # Errors
///
/// See [`MapError`].
pub fn map_frame(root: ObjectId, frame: ObjectId, vaddr_flags: u64) -> Result<(), MapError> {
    if root.kind() != ObjectKind::VSpace || frame.kind() != ObjectKind::Frame {
        return Err(MapError::WrongKind);
    }
    let (vaddr, flags) = split(vaddr_flags)?;
    if flags & map_flags::WRITE != 0 && flags & map_flags::EXECUTE != 0 {
        return Err(MapError::WritableExecutable);
    }
    let mut mappings = MAPPINGS.lock();
    if mappings.find(frame.phys_addr()).is_some() {
        return Err(MapError::AlreadyMapped);
    }
    // SAFETY: as in map_table.
    let entry = match unsafe { walk(root.phys_addr(), vaddr, 3) } {
        Ok(entry) => entry,
        Err(Walk::Missing) => return Err(MapError::MissingTable),
        Err(Walk::HugePage) => return Err(MapError::HugePage),
    };
    if pte::is_present(*entry) {
        return Err(MapError::AlreadyPresent);
    }
    mappings.record(Mapping {
        object: frame.phys_addr(),
        vspace: root.phys_addr(),
        vaddr,
        level: Level::Frame,
    })?;
    let mut leaf = PteFlags::PRESENT | PteFlags::USER;
    if flags & map_flags::WRITE != 0 {
        leaf = leaf | PteFlags::WRITABLE;
    }
    if flags & map_flags::EXECUTE == 0 {
        leaf = leaf | PteFlags::NO_EXECUTE;
    }
    *entry = pte::encode_flags(frame.phys_addr(), leaf);
    Ok(())
}

/// Removes the mapping of the object at physical address `object`, if it is
/// mapped, and everything mapped beneath it, returning whether it was mapped.
/// Called by the `Unmap` syscall and when a capability to a frame or page
/// table is revoked, so revocation takes away the access too.
pub fn unmap_object(object: u64) -> bool {
    let mut mappings = MAPPINGS.lock();
    let Some(mapping) = mappings.forget(object) else {
        return false;
    };
    let mut beneath = [None; MAX_MAPPINGS];
    let mut count = 0;
    if mapping.level != Level::Frame {
        mappings.forget_beneath(&mapping, |m| {
            beneath[count] = Some(m);
            count += 1;
        });
    }
    // clear the deepest entries first, so every walk still reaches its entry
    // and no table is left holding a stale entry for when it is mapped again.
    for level in [Level::Frame, Level::Pt, Level::Pd] {
        for m in beneath.iter().flatten().filter(|m| m.level == level) {
            clear(m);
        }
    }
    clear(&mapping);
    // a table's entries may be cached for the active address space.
    if Cr3::read().0.start_address().as_u64() == mapping.vspace {
        x86_64::instructions::tlb::flush_all();
    }
    true
}

/// Clears the entry that holds `mapping`, if its path is still reachable.
fn clear(mapping: &Mapping) {
    // SAFETY: the mapping was recorded against a live VSpace; the registry lock
    // is held by the caller, serializing every walk on the single-CPU path.
    if let Ok(entry) = unsafe { walk(mapping.vspace, mapping.vaddr, depth_of(mapping.level)) } {
        *entry = 0;
    }
}

/// Returns the physical address `vaddr` translates to in the address space
/// `root`, if a frame is mapped there. Used by tests to observe mappings.
#[must_use]
pub fn translate(root: ObjectId, vaddr: u64) -> Option<u64> {
    let _guard = MAPPINGS.lock();
    // SAFETY: as in map_table; the lock is held for the walk.
    let entry = unsafe { walk(root.phys_addr(), vaddr, 3) }.ok()?;
    pte::is_present(*entry).then(|| pte::frame_addr(*entry))
}
