//! Thread syscalls: configuring and starting a TCB.

use super::*;

/// Resolves `slot` to a thread the capability grants `WRITE` on and that has
/// not started yet.
///
/// # Errors
///
/// [`IpcSyscallError::BadCap`], [`NotTcb`](IpcSyscallError::NotTcb),
/// [`Denied`](IpcSyscallError::Denied), or
/// [`AlreadyStarted`](IpcSyscallError::AlreadyStarted).
fn resolve_new_thread(slot: u64) -> Result<&'static mut Tcb, IpcSyscallError> {
    let tcb = resolve_object(slot, ObjectKind::Tcb, Rights::WRITE, IpcSyscallError::NotTcb)?;
    // SAFETY: the capability names a live TCB (kind checked above) in a static
    // untyped region; single-CPU syscall path, so no other reference is live.
    let tcb = unsafe { tcb.as_tcb_mut() };
    if tcb.state != TcbState::Inactive {
        return Err(IpcSyscallError::AlreadyStarted);
    }
    Ok(tcb)
}

/// Implements [`Syscall::TcbConfigure`].
pub(super) fn sys_tcb_configure(tcb_slot: u64, cnode_slot: u64, vspace_slot: u64) -> u64 {
    let configured = (|| {
        let tcb = resolve_new_thread(tcb_slot)?;
        let cnode =
            resolve_object(cnode_slot, ObjectKind::CNode, Rights::WRITE, IpcSyscallError::NotCNode)?;
        let root = resolve_vspace(vspace_slot)?;
        // SAFETY: the capability names a live CNode (kind checked above); the
        // thread keeps a pointer to its capability space, which lives as long as
        // the static untyped region it was carved from.
        let space = unsafe { cnode.as_cnode_mut() };
        tcb.cspace_ptr = core::ptr::from_mut(space);
        tcb.cspace_root = Some(cnode);
        tcb.vspace_root = root.phys_addr();
        Ok(())
    })();
    configured.map_or_else(|e: IpcSyscallError| e as u64, |()| 0)
}

/// Implements [`Syscall::TcbSetIpcBuffer`].
pub(super) fn sys_tcb_set_ipc_buffer(tcb_slot: u64, frame_slot: u64) -> u64 {
    let set = (|| {
        let tcb = resolve_new_thread(tcb_slot)?;
        let frame =
            resolve_object(frame_slot, ObjectKind::Frame, Rights::READ_WRITE, IpcSyscallError::NotFrame)?;
        tcb.ipc_buffer = frame.phys_addr();
        Ok(())
    })();
    set.map_or_else(|e: IpcSyscallError| e as u64, |()| 0)
}

/// Implements [`Syscall::TcbStart`].
pub(super) fn sys_tcb_start(tcb_slot: u64, entry: u64, stack_top: u64) -> u64 {
    // user code and stacks live in the lower (user) half.
    const USER_LIMIT: u64 = 0x0000_8000_0000_0000;
    let started = (|| {
        let tcb = resolve_new_thread(tcb_slot)?;
        if tcb.cspace_ptr.is_null() || tcb.vspace_root == 0 {
            return Err(IpcSyscallError::NotConfigured);
        }
        if entry == 0 || entry >= USER_LIMIT || stack_top == 0 || stack_top >= USER_LIMIT {
            return Err(IpcSyscallError::BadAddress);
        }
        let sel = gdt::selectors();
        tcb.context = crate::cap::SavedContext {
            rip: entry,
            rsp: stack_top,
            // IF=1 so the timer can preempt it, plus the always-one bit 1.
            rflags: 0x0000_0202,
            cs: u64::from(sel.user_code.0),
            ss: u64::from(sel.user_data.0),
            ..crate::cap::SavedContext::default()
        };
        let ptr = core::ptr::from_mut(tcb);
        // SAFETY: the TCB is live for the kernel lifetime; interrupts are off on
        // the syscall path, as register requires.
        let id = unsafe { crate::sched::try_register_thread(ptr) }.ok_or(IpcSyscallError::ThreadsFull)?;
        tcb.state = TcbState::Running;
        crate::sched::mark_ready(id);
        Ok(())
    })();
    started.map_or_else(|e: IpcSyscallError| e as u64, |()| 0)
}

