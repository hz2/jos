//! Platform syscalls: the console and the machine.
//!
//! Both objects are singletons the kernel hands only to the root task at boot,
//! so printing and halting are capabilities like everything else: a thread can
//! do either only if it holds (a copy of) the right capability.

use super::*;
use jos_core::abi::NO_TIMEOUT;

/// Implements [`Syscall::ConsoleWrite`].
pub(super) fn sys_console_write(console_slot: u64, len: u64) -> u64 {
    if let Err(e) = resolve_object(console_slot, ObjectKind::Console, Rights::WRITE, IpcSyscallError::NotConsole) {
        return e as u64;
    }
    let len = match usize::try_from(len) {
        Ok(len) if len <= ipc_buffer::DATA_LEN => len,
        _ => return IpcSyscallError::TooLong as u64,
    };
    // SAFETY: the per-CPU block is read on the single-CPU syscall path.
    let tcb = unsafe { (*cpu_local::cpu_local_ptr()).current_tcb };
    if tcb.is_null() {
        return IpcSyscallError::NoThread as u64;
    }
    // SAFETY: switch_to installed a live Tcb as current; nothing else touches it
    // during this syscall.
    let Some(buffer) = (unsafe { (*tcb).ipc_buffer_ptr() }) else {
        return IpcSyscallError::NoIpcBuffer as u64;
    };
    // SAFETY: the buffer is a whole registered frame reached through the
    // identity map, so the data area [DATA_OFFSET, DATA_OFFSET + len) lies
    // inside it; no other reference to the frame is live on this single-CPU
    // path, and u8 has no invalid values whatever userspace wrote there.
    let bytes = unsafe {
        let data = buffer.cast::<u8>().add(ipc_buffer::DATA_OFFSET);
        core::slice::from_raw_parts(data, len)
    };
    crate::serial::write_bytes(bytes);
    0
}

/// Implements [`Syscall::ConsoleRead`]: waiting input goes into the caller's
/// IPC-buffer data area now; with none, the caller waits for some as `ms`
/// says (see [`ipc::park_console_reader`]).
pub(super) fn sys_console_read(console_slot: u64, max: u64, ms: u64) -> SyscallRet {
    let err = |e: IpcSyscallError| SyscallRet::from(e as u64 | IPC_ERR_FLAG);
    if let Err(e) = resolve_object(console_slot, ObjectKind::Console, Rights::READ, IpcSyscallError::NotConsole) {
        return err(e);
    }
    let max = match usize::try_from(max) {
        Ok(max) if max <= ipc_buffer::DATA_LEN => max,
        _ => return err(IpcSyscallError::TooLong),
    };
    // SAFETY: the per-CPU block is read on the single-CPU syscall path.
    let tcb = unsafe { (*cpu_local::cpu_local_ptr()).current_tcb };
    if tcb.is_null() {
        return err(IpcSyscallError::NoThread);
    }
    // SAFETY: switch_to installed a live Tcb as current; nothing else touches
    // it during this syscall.
    let Some(buffer) = (unsafe { (*tcb).ipc_buffer_ptr() }) else {
        return err(IpcSyscallError::NoIpcBuffer);
    };
    // SAFETY: as in sys_console_write: the data area of a whole registered
    // frame, reached through the identity map, with no other live reference.
    let data = unsafe {
        let start = buffer.cast::<u8>().add(ipc_buffer::DATA_OFFSET);
        core::slice::from_raw_parts_mut(start, max)
    };
    let count = crate::console::take(data);
    if count > 0 || max == 0 {
        return SyscallRet::from(count as u64);
    }
    if ms == 0 {
        return err(IpcSyscallError::WouldBlock);
    }
    let deadline = (ms != NO_TIMEOUT).then(|| ipc::deadline_after(ms));
    ipc::park_console_reader(max, deadline)
}

/// Implements [`Syscall::MachineHalt`]. Returns only when the capability is
/// refused.
pub(super) fn sys_machine_halt(machine_slot: u64, code: u64) -> u64 {
    if let Err(e) = resolve_object(machine_slot, ObjectKind::Machine, Rights::WRITE, IpcSyscallError::NotMachine) {
        return e as u64;
    }
    crate::trace::record(Syscall::MachineHalt as u64, [machine_slot, code, 0], code);
    crate::serial_println!("jos: machine halted by userspace (code {:#x})", code);
    crate::exit_qemu(if code == 0 {
        crate::QemuExitCode::Success
    } else {
        crate::QemuExitCode::Failed
    });
    // without the debug-exit device (real hardware), stop here for good: the
    // syscall path runs with interrupts off, so hlt never wakes.
    crate::hlt_loop()
}
