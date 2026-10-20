//! Object and capability syscalls: retype, mint, copy, revoke, invoke.

use super::*;

/// Implements [`Syscall::Mint`]: derives a capability from `src_slot` into the
/// lowest free slot, with rights attenuated by the low byte of `rights` and an
/// optional badge. Returns the new slot index so userspace can hand it out.
pub(super) fn sys_mint(src_slot: u64, rights: u64, badge: u64) -> u64 {
    let err = |e: MintSyscallError| e as u64 | IPC_ERR_FLAG;
    let Some(space) = current_cspace_mut() else {
        return err(MintSyscallError::BadCap);
    };
    let Ok(slot) = usize::try_from(src_slot) else {
        return err(MintSyscallError::BadCap);
    };
    let Some(src) = space.ref_at(slot) else {
        return err(MintSyscallError::BadCap);
    };
    // the low byte carries the mask; truncate drops any undefined bits.
    let mask = Rights::from_bits_truncate(rights.to_le_bytes()[0]);
    let minted = if badge == 0 {
        space.mint(src, mask)
    } else {
        space.mint_badged(src, mask, Badge(badge))
    };
    match minted {
        Ok(r) => r.slot() as u64,
        Err(MintError::InvalidSource) => err(MintSyscallError::BadCap),
        Err(MintError::AlreadyBadged) => err(MintSyscallError::AlreadyBadged),
        Err(MintError::SpaceFull) => err(MintSyscallError::SpaceFull),
    }
}

/// Retype: carve a typed object from the untyped cap in `untyped_slot` and
/// install a full-rights capability to it at `dest_slot`. The seL4 Retype, with
/// the source untyped and the destination both named by CSpace slots (resolved
/// per call), so userspace can only create objects from untyped it was handed.
pub(super) fn sys_retype(untyped_slot: u64, type_word: u64, dest_slot: u64) -> u64 {
    use crate::cap::CSPACE_SLOTS;
    let err = |e: RetypeSyscallError| e as u64;

    // decode the requested object type before touching the CSpace.
    let Some(ty) = decode_object_type(type_word) else {
        return err(RetypeSyscallError::BadArgs);
    };
    let (Ok(uslot), Ok(dslot)) = (usize::try_from(untyped_slot), usize::try_from(dest_slot)) else {
        return err(RetypeSyscallError::BadCap);
    };
    if dslot >= CSPACE_SLOTS {
        return err(RetypeSyscallError::DestOutOfRange);
    }

    let Some(space) = current_cspace_mut() else {
        return err(RetypeSyscallError::BadCap);
    };
    // resolve the untyped source: must be a live cap naming an untyped region.
    let Some(usource) = space.ref_at(uslot) else {
        return err(RetypeSyscallError::BadCap);
    };
    let untyped_obj = match space.lookup(usource) {
        Some(cap) if cap.object.kind() == ObjectKind::Untyped => cap.object,
        Some(_) => return err(RetypeSyscallError::NotUntyped),
        None => return err(RetypeSyscallError::BadCap),
    };
    // the destination must be free BEFORE we carve, so a failure leaves the
    // untyped watermark untouched (no half-done carve into an occupied slot).
    if space.ref_at(dslot).is_some() {
        return err(RetypeSyscallError::DestOccupied);
    }

    // carve the object from the untyped region.
    // SAFETY: untyped_obj is a live cap of kind Untyped (checked); the region is
    // a 'static kernel object; single-threaded syscall path, so no aliasing &mut
    // to it exists. retype_object mutates only the region's own watermark.
    let region = unsafe { untyped_obj.as_untyped_mut() };
    let new_obj = match region.retype_object(ty) {
        Ok(id) => id,
        Err(RetypeError::NoRoom) => return err(RetypeSyscallError::NoRoom),
        Err(RetypeError::BadAlign) => return err(RetypeSyscallError::BadAlign),
        Err(RetypeError::BadType) => return err(RetypeSyscallError::BadType),
    };

    // install a full-rights capability to the new object at the dest slot.
    match space.insert_at(dslot, new_obj, Rights::all()) {
        Ok(_) => 0,
        // the dest was free a moment ago and nothing else runs concurrently, so
        // these are not expected; map them faithfully rather than unwrap.
        Err(InsertAtError::Occupied) => err(RetypeSyscallError::DestOccupied),
        Err(InsertAtError::OutOfRange) => err(RetypeSyscallError::DestOutOfRange),
    }
}

/// Implements [`Syscall::Revoke`].
pub(super) fn sys_revoke(slot: u64) -> u64 {
    let Some(space) = current_cspace_mut() else {
        return IpcSyscallError::BadCap as u64 | IPC_ERR_FLAG;
    };
    let Some(cap_ref) = usize::try_from(slot).ok().and_then(|s| space.ref_at(s)) else {
        return IpcSyscallError::BadCap as u64 | IPC_ERR_FLAG;
    };
    cap::revoke_and_wake(space, cap_ref) as u64
}

/// Implements [`Syscall::CNodeCopy`].
pub(super) fn sys_cnode_copy(dest_cnode_slot: u64, src_slot: u64, packed: u64) -> u64 {
    use jos_core::cap_space::CopyError;
    let Some((dest_slot, rights)) = jos_core::abi::unpack_cnode_copy(packed) else {
        return IpcSyscallError::BadAddress as u64;
    };
    let dest = match resolve_object(
        dest_cnode_slot,
        ObjectKind::CNode,
        Rights::WRITE,
        IpcSyscallError::NotCNode,
    ) {
        Ok(dest) => dest,
        Err(e) => return e as u64,
    };
    let Some(space) = current_cspace() else {
        return IpcSyscallError::BadCap as u64;
    };
    let Some(src) = usize::try_from(src_slot).ok().and_then(|s| space.ref_at(s)) else {
        return IpcSyscallError::BadCap as u64;
    };
    let dest_slot = usize::from(dest_slot);
    let mask = Rights::from_bits_truncate(rights);
    // SAFETY: dest names a live CNode (kind checked above) in a static untyped
    // region; single-CPU syscall path.
    let dest_space = unsafe { dest.as_cnode_mut() };
    if core::ptr::eq(dest_space, space) {
        // an exclusive reference to the caller's own space would alias `space`.
        return IpcSyscallError::SameSpace as u64;
    }
    match space.copy_into(src, dest_space, dest_slot, mask) {
        Ok(_) => 0,
        Err(CopyError::InvalidSource) => IpcSyscallError::BadCap as u64,
        Err(CopyError::OutOfRange) => IpcSyscallError::SlotOutOfRange as u64,
        Err(CopyError::Occupied) => IpcSyscallError::SlotOccupied as u64,
        Err(CopyError::SameSpace) => IpcSyscallError::SameSpace as u64,
    }
}

/// Invoke: a generic capability invocation routed by the named object's kind.
/// Today only Endpoint methods (Send/Recv) are defined; they reuse the IPC
/// primitives, so SYS_INVOKE(Endpoint, Send/Recv) is equivalent to the dedicated
/// IPC syscalls, proving the generic dispatch path.
pub(super) fn sys_invoke(cap_slot: u64, method: u64, arg0: u64) -> u64 {
    use jos_core::abi::invoke_method::{ENDPOINT_RECV, ENDPOINT_SEND};
    let err = |e: InvokeError| e as u64 | IPC_ERR_FLAG;

    let Some(space) = current_cspace() else {
        return err(InvokeError::BadCap);
    };
    let Ok(slot) = usize::try_from(cap_slot) else {
        return err(InvokeError::BadCap);
    };
    let Some(cap_ref) = space.ref_at(slot) else {
        return err(InvokeError::BadCap);
    };
    let Some(cap) = space.lookup(cap_ref) else {
        return err(InvokeError::BadCap);
    };
    match cap.object.kind() {
        ObjectKind::Endpoint => match method {
            ENDPOINT_SEND => {
                let message = Message::new(0, [arg0, 0, 0, 0]);
                match cap_send(space, cap_ref, message) {
                    Ok(()) => 0,
                    Err(e) => invoke_errno(e),
                }
            }
            ENDPOINT_RECV => match cap_recv(space, cap_ref) {
                Ok(message) => message.words[0],
                Err(e) => invoke_errno(e),
            },
            _ => err(InvokeError::BadMethod),
        },
        // no methods defined for the other object kinds yet.
        _ => err(InvokeError::BadMethod),
    }
}

/// Maps an IpcError to an Invoke return value (errno OR'd with IPC_ERR_FLAG).
fn invoke_errno(e: IpcError) -> u64 {
    let code = match e {
        IpcError::InvalidCap => InvokeError::BadCap,
        IpcError::InsufficientRights => InvokeError::Denied,
        IpcError::NotAnEndpoint => InvokeError::BadMethod,
        IpcError::EndpointBusy | IpcError::EndpointEmpty => InvokeError::WouldBlock,
    };
    code as u64 | IPC_ERR_FLAG
}

