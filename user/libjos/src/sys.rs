//! One typed function per syscall.
//!
//! Each wrapper packs its arguments the way `jos_core::abi` documents and
//! decodes the result into a `Result` over that call's error enum. A code the
//! kernel should never return means the two sides disagree about the ABI, so
//! it panics instead of being passed off as an ordinary error.

use crate::abi::{
    IPC_ERR_FLAG, InvokeError, IpcSyscallError, MintSyscallError, RetypeSyscallError, Syscall,
    encode_object_type, pack_cnode_copy,
};
use crate::syscall::{syscall1, syscall2, syscall3};
use jos_core::cap_rights::Rights;
use jos_core::untyped::ObjectType;

/// A capability slot number in the calling thread's capability space.
pub type Slot = u64;

/// Decodes an [`IpcSyscallError`] code.
fn ipc_error(code: u64) -> IpcSyscallError {
    IpcSyscallError::from_code(code)
        .unwrap_or_else(|| panic!("kernel returned an unknown error code {code:#x}"))
}

/// Decodes a call that returns 0 or an [`IpcSyscallError`] code.
fn status(rax: u64) -> Result<(), IpcSyscallError> {
    if rax == 0 { Ok(()) } else { Err(ipc_error(rax)) }
}

/// Decodes a call that returns a value, or an [`IpcSyscallError`] code with
/// [`IPC_ERR_FLAG`] set.
fn flagged(rax: u64) -> Result<u64, IpcSyscallError> {
    if rax & IPC_ERR_FLAG == 0 { Ok(rax) } else { Err(ipc_error(rax & !IPC_ERR_FLAG)) }
}

/// Issues a syscall that takes up to three arguments and returns a status.
fn status_call(nr: Syscall, a0: u64, a1: u64, a2: u64) -> Result<(), IpcSyscallError> {
    status(syscall3(nr as u64, a0, a1, a2).0)
}

/// Issues a receive-style syscall: a word (flagged on error) and a badge.
fn receive_call(nr: Syscall, a0: u64, a1: u64, a2: u64) -> Result<(u64, u64), IpcSyscallError> {
    let (rax, rdx) = syscall3(nr as u64, a0, a1, a2);
    flagged(rax).map(|word| (word, rdx))
}

/// `add(a, b)`: the arithmetic probe, `a + b` wrapping.
#[must_use]
pub fn add(a: u64, b: u64) -> u64 {
    syscall2(Syscall::Add as u64, a, b).0
}

/// `exit(code)`: the test probe that ends a qemu run (`0x10` passes). Prefer
/// [`machine_halt`], which needs a capability.
pub fn exit(code: u64) -> ! {
    let _ = syscall1(Syscall::Exit as u64, code);
    loop {
        core::hint::spin_loop();
    }
}

/// `ipc_send(ep, word)`: sends without blocking.
///
/// # Errors
///
/// [`IpcSyscallError::WouldBlock`] if the endpoint is full, or why the
/// capability was refused.
pub fn send(ep: Slot, word: u64) -> Result<(), IpcSyscallError> {
    status_call(Syscall::IpcSend, ep, word, 0)
}

/// `ipc_recv(ep)`: receives without blocking; returns the word and the
/// sender's badge.
///
/// # Errors
///
/// [`IpcSyscallError::WouldBlock`] if nothing is waiting, or why the
/// capability was refused.
pub fn recv(ep: Slot) -> Result<(u64, u64), IpcSyscallError> {
    receive_call(Syscall::IpcRecv, ep, 0, 0)
}

/// `retype(untyped, type, dest)`: carves an object from untyped memory into
/// the empty slot `dest`.
///
/// # Errors
///
/// See [`RetypeSyscallError`].
///
/// # Panics
///
/// If the kernel returns an error code the abi does not define.
pub fn retype(untyped: Slot, ty: ObjectType, dest: Slot) -> Result<(), RetypeSyscallError> {
    let rax = syscall3(Syscall::Retype as u64, untyped, encode_object_type(ty), dest).0;
    if rax == 0 {
        return Ok(());
    }
    Err(RetypeSyscallError::from_code(rax)
        .unwrap_or_else(|| panic!("kernel returned an unknown retype error {rax:#x}")))
}

/// `invoke(slot, method, arg)`: invokes a method on the object `slot` names.
///
/// # Errors
///
/// See [`InvokeError`].
///
/// # Panics
///
/// If the kernel returns an error code the abi does not define.
pub fn invoke(slot: Slot, method: u64, arg: u64) -> Result<u64, InvokeError> {
    let rax = syscall3(Syscall::Invoke as u64, slot, method, arg).0;
    if rax & IPC_ERR_FLAG == 0 {
        return Ok(rax);
    }
    let code = rax & !IPC_ERR_FLAG;
    Err(InvokeError::from_code(code)
        .unwrap_or_else(|| panic!("kernel returned an unknown invoke error {code:#x}")))
}

/// `ipc_send_blocking(ep, word)`: sends, waiting for a receiver.
///
/// # Errors
///
/// Why the capability was refused, or why the wait ended without delivery.
pub fn send_blocking(ep: Slot, word: u64) -> Result<(), IpcSyscallError> {
    status_call(Syscall::IpcSendBlocking, ep, word, 0)
}

/// `ipc_recv_blocking(ep)`: receives, waiting for a sender; returns the word
/// and the sender's badge.
///
/// # Errors
///
/// Why the capability was refused, or why the wait ended without a message.
pub fn recv_blocking(ep: Slot) -> Result<(u64, u64), IpcSyscallError> {
    receive_call(Syscall::IpcRecvBlocking, ep, 0, 0)
}

/// `mint(src, rights, badge)`: derives an attenuated, optionally badged copy
/// of `src` into the lowest free slot, and returns that slot.
///
/// # Errors
///
/// See [`MintSyscallError`].
///
/// # Panics
///
/// If the kernel returns an error code the abi does not define.
pub fn mint(src: Slot, rights: Rights, badge: u64) -> Result<Slot, MintSyscallError> {
    let rax = syscall3(Syscall::Mint as u64, src, u64::from(rights.bits()), badge).0;
    if rax & IPC_ERR_FLAG == 0 {
        return Ok(rax);
    }
    let code = rax & !IPC_ERR_FLAG;
    Err(MintSyscallError::from_code(code)
        .unwrap_or_else(|| panic!("kernel returned an unknown mint error {code:#x}")))
}

/// `call(ep, word)`: sends and waits for the server's answer, which it
/// returns.
///
/// # Errors
///
/// [`IpcSyscallError::NoReply`] if the call can never be answered, or why the
/// capability was refused.
pub fn call(ep: Slot, word: u64) -> Result<u64, IpcSyscallError> {
    flagged(syscall2(Syscall::Call as u64, ep, word).0)
}

/// `recv_reply(ep, reply)`: receives, binding `reply` to the caller if the
/// message came from a [`call`]; returns the word and badge.
///
/// # Errors
///
/// Why either capability was refused.
pub fn recv_reply(ep: Slot, reply: Slot) -> Result<(u64, u64), IpcSyscallError> {
    receive_call(Syscall::RecvReply, ep, reply, 0)
}

/// `reply(reply, word)`: answers the caller bound to `reply`.
///
/// # Errors
///
/// [`IpcSyscallError::NoCaller`] if nobody is waiting, or why the capability
/// was refused.
pub fn reply(reply: Slot, word: u64) -> Result<(), IpcSyscallError> {
    status_call(Syscall::Reply, reply, word, 0)
}

/// `set_ipc_buffer(frame)`: registers the frame as this thread's IPC buffer.
///
/// # Errors
///
/// Why the capability was refused.
pub fn set_ipc_buffer(frame: Slot) -> Result<(), IpcSyscallError> {
    status_call(Syscall::SetIpcBuffer, frame, 0, 0)
}

/// `reply_recv(ep, reply, word)`: answers the bound caller, if any, then
/// receives like [`recv_reply`].
///
/// # Errors
///
/// Why either capability was refused.
pub fn reply_recv(ep: Slot, reply: Slot, word: u64) -> Result<(u64, u64), IpcSyscallError> {
    receive_call(Syscall::ReplyRecv, ep, reply, word)
}

/// `map_page_table(vspace, table, vaddr)`: installs `table` at the first
/// missing level on the path to `vaddr`.
///
/// # Errors
///
/// See the mapping errors of [`IpcSyscallError`].
pub fn map_page_table(vspace: Slot, table: Slot, vaddr: u64) -> Result<(), IpcSyscallError> {
    status_call(Syscall::MapPageTable, vspace, table, vaddr)
}

/// `map_frame(vspace, frame, vaddr | flags)`: maps `frame` at the page-aligned
/// `vaddr`; `flags` is a combination of [`crate::abi::map_flags`].
///
/// # Errors
///
/// See the mapping errors of [`IpcSyscallError`].
pub fn map_frame(vspace: Slot, frame: Slot, vaddr: u64, flags: u64) -> Result<(), IpcSyscallError> {
    status_call(Syscall::MapFrame, vspace, frame, vaddr | flags)
}

/// `unmap(slot)`: unmaps the frame or table `slot` names (and everything
/// beneath a table).
///
/// # Errors
///
/// [`IpcSyscallError::NotMapped`], or why the capability was refused.
pub fn unmap(slot: Slot) -> Result<(), IpcSyscallError> {
    status_call(Syscall::Unmap, slot, 0, 0)
}

/// `tcb_configure(tcb, cnode, vspace)`: gives a thread that has not started
/// its capability space and address space.
///
/// # Errors
///
/// Why a capability was refused, or [`IpcSyscallError::AlreadyStarted`].
pub fn tcb_configure(tcb: Slot, cnode: Slot, vspace: Slot) -> Result<(), IpcSyscallError> {
    status_call(Syscall::TcbConfigure, tcb, cnode, vspace)
}

/// `tcb_set_ipc_buffer(tcb, frame)`: registers another thread's IPC buffer.
///
/// # Errors
///
/// Why a capability was refused, or [`IpcSyscallError::AlreadyStarted`].
pub fn tcb_set_ipc_buffer(tcb: Slot, frame: Slot) -> Result<(), IpcSyscallError> {
    status_call(Syscall::TcbSetIpcBuffer, tcb, frame, 0)
}

/// `tcb_start(tcb, entry, stack_top)`: starts a configured thread in ring 3.
///
/// # Errors
///
/// Why the capability was refused, [`IpcSyscallError::NotConfigured`],
/// [`IpcSyscallError::BadAddress`], or [`IpcSyscallError::ThreadsFull`].
pub fn tcb_start(tcb: Slot, entry: u64, stack_top: u64) -> Result<(), IpcSyscallError> {
    status_call(Syscall::TcbStart, tcb, entry, stack_top)
}

/// `cnode_copy(dest_cnode, src, dest_slot | rights << 16)`: copies `src` into
/// slot `dest_slot` of another capability space, attenuated to `rights`.
///
/// # Errors
///
/// Why a capability was refused, or why the destination slot cannot take it.
pub fn cnode_copy(dest_cnode: Slot, src: Slot, dest_slot: u16, rights: Rights) -> Result<(), IpcSyscallError> {
    status_call(Syscall::CNodeCopy, dest_cnode, src, pack_cnode_copy(dest_slot, rights.bits()))
}

/// `revoke(slot)`: removes the capability and everything derived from it, in
/// every space, and returns how many capabilities were removed.
///
/// # Errors
///
/// [`IpcSyscallError::BadCap`] if the slot is empty.
pub fn revoke(slot: Slot) -> Result<u64, IpcSyscallError> {
    flagged(syscall1(Syscall::Revoke as u64, slot).0)
}

/// `console_write(console, len)`: prints the first `len` bytes of this
/// thread's IPC-buffer data area. [`crate::console`] fills the buffer first.
///
/// # Errors
///
/// Why the capability was refused, [`IpcSyscallError::NoIpcBuffer`], or
/// [`IpcSyscallError::TooLong`].
pub fn console_write(console: Slot, len: usize) -> Result<(), IpcSyscallError> {
    status_call(Syscall::ConsoleWrite, console, len as u64, 0)
}

/// `machine_halt(machine, code)`: stops the machine; code 0 reports success.
/// Returns only if the capability is refused, with the reason.
///
/// # Panics
///
/// If the kernel reports success, which a halt never returns with.
#[must_use]
pub fn machine_halt(machine: Slot, code: u64) -> IpcSyscallError {
    match status_call(Syscall::MachineHalt, machine, code, 0) {
        Err(e) => e,
        Ok(()) => panic!("machine_halt returned success"),
    }
}

/// `thread_exit()`: stops the calling thread for good.
pub fn thread_exit() -> ! {
    let _ = syscall1(Syscall::ThreadExit as u64, 0);
    // the kernel never returns to a thread that exited.
    loop {
        core::hint::spin_loop();
    }
}
