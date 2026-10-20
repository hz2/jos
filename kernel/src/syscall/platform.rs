//! Platform syscalls: the console and the machine.
//!
//! Both objects are singletons the kernel hands only to the root task at boot,
//! so printing and halting are capabilities like everything else: a thread can
//! do either only if it holds (a copy of) the right capability.

use super::*;

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
