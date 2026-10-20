//! Address-space syscalls: mapping page tables and frames, and unmapping.

use super::*;

/// Maps a [`mapping::MapError`] to its syscall error code.
fn map_errno(e: mapping::MapError) -> u64 {
    use mapping::MapError;
    let code = match e {
        MapError::WrongKind => IpcSyscallError::NotPageTable,
        MapError::BadAddress | MapError::HugePage => IpcSyscallError::BadAddress,
        MapError::MissingTable => IpcSyscallError::MissingTable,
        MapError::AlreadyMapped => IpcSyscallError::AlreadyMapped,
        MapError::AlreadyPresent => IpcSyscallError::AlreadyPresent,
        MapError::WritableExecutable => IpcSyscallError::WritableExecutable,
        MapError::Full => IpcSyscallError::MappingsFull,
    };
    code as u64
}

/// Implements [`Syscall::MapPageTable`].
pub(super) fn sys_map_page_table(vspace_slot: u64, table_slot: u64, vaddr: u64) -> u64 {
    let root = match resolve_vspace(vspace_slot) {
        Ok(root) => root,
        Err(e) => return e as u64,
    };
    let table = match resolve_object(
        table_slot,
        ObjectKind::PageTable,
        Rights::WRITE,
        IpcSyscallError::NotPageTable,
    ) {
        Ok(table) => table,
        Err(e) => return e as u64,
    };
    mapping::map_table(root, table, vaddr).map_or_else(map_errno, |()| 0)
}

/// Implements [`Syscall::MapFrame`].
pub(super) fn sys_map_frame(vspace_slot: u64, frame_slot: u64, vaddr_flags: u64) -> u64 {
    let root = match resolve_vspace(vspace_slot) {
        Ok(root) => root,
        Err(e) => return e as u64,
    };
    // a writable mapping needs WRITE on the frame as well as READ.
    let rights = if vaddr_flags & mapping::map_flags::WRITE == 0 {
        Rights::READ
    } else {
        Rights::READ_WRITE
    };
    let frame = match resolve_object(frame_slot, ObjectKind::Frame, rights, IpcSyscallError::NotFrame) {
        Ok(frame) => frame,
        Err(e) => return e as u64,
    };
    mapping::map_frame(root, frame, vaddr_flags).map_or_else(map_errno, |()| 0)
}

/// Implements [`Syscall::Unmap`].
pub(super) fn sys_unmap(object_slot: u64) -> u64 {
    let Some(cap) = current_cap(object_slot) else {
        return IpcSyscallError::BadCap as u64;
    };
    if !matches!(cap.object.kind(), ObjectKind::Frame | ObjectKind::PageTable) {
        return IpcSyscallError::NotPageTable as u64;
    }
    if !cap.rights.contains(Rights::WRITE) {
        return IpcSyscallError::Denied as u64;
    }
    if mapping::unmap_object(cap.object.phys_addr()) {
        0
    } else {
        IpcSyscallError::NotMapped as u64
    }
}

