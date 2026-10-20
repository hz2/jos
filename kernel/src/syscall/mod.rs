//! The SYSCALL/SYSRET system-call boundary (capability slice 3b).
//!
//! Slice 3a reached ring 3 and could only return to the kernel through a fault.
//! This slice adds the real ring-3 -> ring-0 -> ring-3 path via the `syscall`
//! and `sysret` instructions, the fast system-call mechanism on `x86_64`.
//!
//! # What `syscall` does in hardware (and what we must do by hand)
//!
//! `syscall` is deliberately minimal. On execution the cpu:
//!
//! - saves the return address (`RIP` of the next user instruction) into `RCX`,
//! - saves `RFLAGS` into `R11`, then clears the bits set in the `SFMASK` MSR,
//! - loads `CS`/`SS` from the `STAR` MSR's syscall selectors (entering ring 0),
//! - jumps to the entry point in the `LSTAR` MSR.
//!
//! Crucially it does **not** switch the stack pointer: on entry `RSP` is still
//! the user stack. So the entry stub ([`syscall_entry`]) must switch to a
//! kernel stack itself before doing anything that pushes. It saves the user
//! `RSP`, loads the kernel stack, preserves the caller-saved registers the ABI
//! and the cpu rely on (`RCX` = return RIP, `R11` = saved RFLAGS), calls the
//! Rust dispatcher, then restores and executes `sysretq`, which reloads `CS`/
//! `SS` from `STAR`'s sysret selectors (returning to ring 3), restores `RFLAGS`
//! from `R11`, and jumps to `RCX`.
//!
//! # jos system-call ABI
//!
//! | Register | Meaning |
//! |----------|---------|
//! | `rax`    | syscall number ([`Syscall`]) on entry, result on exit |
//! | `rdi`    | argument 0 |
//! | `rsi`    | argument 1 |
//! | `rdx`    | argument 2 on entry; a second result (a badge) on exit |
//!
//! `rcx` and `r11` are reserved by the `syscall` instruction itself and must
//! not be used to pass arguments. Message words 1 to 3 and any capability sent
//! with a message travel through the thread's IPC buffer. `docs/syscalls.md`
//! lists every call with its arguments, results, and error codes.
//!
//! # Kernel stacks
//!
//! Each thread has its own kernel stack (inside its TCB object, above a guard
//! page). [`switch_to`](crate::cpu_local::switch_to) records the current
//! thread's stack top in the per-CPU block, and the entry stub loads it after
//! `swapgs`.
//!
//! # Layout
//!
//! This module holds the ABI (the [`Syscall`] numbers and error codes), the
//! entry stub, the dispatcher, and the helpers that resolve a slot to a
//! capability. The calls themselves live by subsystem:
//!
//! | module | calls |
//! |---|---|
//! | `ipc` | send, receive, blocking rendezvous, call and reply, IPC buffers |
//! | `objects` | retype, mint, cnode copy, revoke, invoke |
//! | `vm` | map page tables and frames, unmap |
//! | `thread` | configure, set the buffer of, and start a TCB |
//! | `platform` | write to the console, halt the machine |

use x86_64::VirtAddr;
use x86_64::registers::model_specific::{Efer, EferFlags, GsBase, KernelGsBase, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;

use crate::cap::{
    self, Badge, cap_recv_badged, cap_recv, cap_send, IpcError, KernelCapSpace, Message, ObjectId,
    ObjectKind, RetypeError, Tcb, TcbState,
};
use crate::mapping;
use crate::cpu_local::{
    self, OFF_KERNEL_RSP, OFF_NEED_YIELD, OFF_SAVED_USER_RFLAGS, OFF_SAVED_USER_RBP,
    OFF_SAVED_USER_RBX, OFF_SAVED_USER_RIP, OFF_SAVED_USER_R12, OFF_SAVED_USER_R13,
    OFF_SAVED_USER_R14, OFF_SAVED_USER_R15, OFF_USER_RSP_SCRATCH,
};
use crate::gdt;
use jos_core::cap_rights::Rights;
use jos_core::cap_space::{CapLink, Capability, InsertAtError, MintError, SpaceId};
use jos_core::ipc_buffer::{self, IpcBuffer};

mod ipc;
mod objects;
mod platform;
mod thread;
mod vm;

pub use ipc::{
    abort_call, cancel_waits_on, console_input_arrived, deliver_fault, expire_timed_waits, fault_endpoint,
    forget_ipc_buffer, retire_threads,
};

pub use jos_core::abi::{
    ENOSYS, IPC_ERR_FLAG, InvokeError, IpcSyscallError, MintSyscallError, RetypeSyscallError,
    Syscall, object_type_id,
};
use jos_core::abi::decode_object_type;

// The kernel stack and current capability space the syscall path uses now live
// in the per-CPU block ([`crate::cpu_local`]), selected per thread on a context
// switch via `swapgs`. The two setters below remain as compat shims so the
// single-thread tests (slices 3b/3d/retype) keep working unchanged; multi-
// thread code uses `cpu_local::switch_to` instead.

/// Records the kernel stack the next `syscall` entry switches to, by writing the
/// per-CPU block directly.
///
/// Compat shim for single-thread setup (call before [`crate::usermode::
/// enter_user_mode`]); prefer [`crate::cpu_local::switch_to`] once TCBs drive
/// scheduling.
pub fn set_kernel_stack(rsp: VirtAddr) {
    // SAFETY: single-threaded setup; the per-CPU block is not concurrently
    // accessed (interrupts disabled / no other thread running yet).
    unsafe {
        (*cpu_local::cpu_local_ptr()).kernel_rsp = rsp.as_u64();
    }
}

/// Installs `cspace` as the current task's capability space for IPC syscalls, by
/// writing the per-CPU block directly.
///
/// Compat shim for single-thread setup; prefer [`crate::cpu_local::switch_to`].
///
/// # Safety
///
/// `cspace` must point to a `KernelCapSpace` that outlives every syscall made
/// while it is installed (in practice a `'static` kernel object), and must not
/// be mutated concurrently (jos is single-threaded across the syscall path).
pub unsafe fn set_current_cspace(cspace: *mut KernelCapSpace) {
    // SAFETY: single-threaded setup, as above.
    unsafe {
        (*cpu_local::cpu_local_ptr()).current_cspace = cspace;
    }
}

/// Programs the syscall MSRs so `syscall`/`sysret` work. Call once during
/// kernel init, after [`gdt::init_gdt`] (it needs the segment selectors).
///
/// # Panics
///
/// Panics if the GDT selectors are laid out such that `STAR` cannot be
/// programmed (they are, by construction in [`gdt`]; this would be a bug).
pub fn init_syscall() {
    let sel = gdt::selectors();

    // STAR holds the syscall/sysret segment bases. The x86_64 crate validates
    // the seL4-style layout for us: sysret CS = base + 16, SS = base + 8;
    // syscall CS = base, SS = base + 8. Our gdt order (kernel_code, kernel_data,
    // user_data, user_code) is exactly what makes this consistent:
    //   syscall: cs = kernel_code, ss = kernel_data (= kernel_code + 8)
    //   sysret:  the base is user_data, so cs = user_data + 16 = user_code,
    //            ss = user_data + 8 = ... the crate computes ss_sysret = base,
    //            i.e. user_data, and cs_sysret = base + 16 = user_code.
    Star::write(sel.user_code, sel.user_data, sel.kernel_code, sel.kernel_data)
        .expect("STAR selectors must satisfy the syscall/sysret layout");

    // LSTAR is the entry point the cpu jumps to on syscall.
    LStar::write(VirtAddr::new(syscall_entry as *const () as usize as u64));

    // SFMASK: the RFLAGS bits cleared on syscall entry. Clearing IF means
    // interrupts are masked inside the entry stub until we choose otherwise,
    // so the half-built kernel frame (before the stack switch completes) cannot
    // be interrupted. Also clear the direction and trap flags for a sane kernel
    // entry state, and AC so ring 3 cannot enter with the SMAP window open.
    SFMask::write(
        RFlags::INTERRUPT_FLAG
            | RFlags::DIRECTION_FLAG
            | RFlags::TRAP_FLAG
            | RFlags::ALIGNMENT_CHECK,
    );

    // per-CPU data for the swapgs-based entry stub. KernelGsBase holds the
    // CpuLocal pointer while userspace runs; the entry stub's `swapgs` moves it
    // into GsBase so `gs:` addresses the block. GsBase itself is 0 (jos has no
    // userspace TLS), so after the exit `swapgs` GsBase is back to 0 in ring 3.
    GsBase::write(VirtAddr::new(0));
    KernelGsBase::write(VirtAddr::new(cpu_local::cpu_local_ptr() as u64));

    // finally enable the syscall/sysret instructions in EFER.
    // SAFETY: we set only the SYSTEM_CALL_EXTENSIONS bit; Efer::write preserves
    // the reserved bits and the existing long-mode flags, so this cannot
    // disable long mode or otherwise break memory safety. LSTAR/STAR/SFMASK are
    // already programmed above, so the first syscall has a valid target.
    unsafe {
        Efer::write(Efer::read() | EferFlags::SYSTEM_CALL_EXTENSIONS);
    }
}

/// Invokes the syscall dispatcher directly, for in-kernel tests.
///
/// Drives the exact path a real `syscall` instruction reaches (including the
/// trace tap), so a test can verify dispatch behaviour and tracing without
/// assembling a ring-3 program. Hidden from the public API: this is a test
/// seam, not a kernel interface (userspace reaches the dispatcher only through
/// the `syscall` instruction). Avoid `Syscall::Exit` through it, which diverges.
#[doc(hidden)]
#[must_use]
pub fn dispatch_for_test(nr: u64, arg0: u64, arg1: u64, arg2: u64) -> u64 {
    dispatch_syscall(nr, arg0, arg1, arg2).rax
}

/// The two return registers of a syscall.
///
/// The System V ABI returns a two-`u64` `repr(C)` struct in `rax:rdx`, so the
/// entry stub hands both back to user mode with no extra assembly.
#[repr(C)]
struct SyscallRet {
    /// Primary result, or an error code.
    rax: u64,
    /// Secondary result: the sender badge on a receive, otherwise 0.
    rdx: u64,
}

impl From<u64> for SyscallRet {
    fn from(rax: u64) -> Self {
        Self { rax, rdx: 0 }
    }
}

/// The Rust system-call dispatcher, called by [`syscall_entry`] with the user
/// arguments already in C-ABI registers.
///
/// Returns the values to place in the user's `rax` and `rdx`. `Syscall::Exit`
/// does not return (it ends the qemu session).
///
/// `extern "C"` so the assembly stub can call it with the standard argument
/// registers (`rdi`, `rsi`, `rdx`, `rcx`) holding (nr, arg0, arg1, arg2).
extern "C" fn dispatch_syscall(nr: u64, arg0: u64, arg1: u64, arg2: u64) -> SyscallRet {
    let result: SyscallRet = match Syscall::from_u64(nr) {
        Some(Syscall::Add) => arg0.wrapping_add(arg1).into(),
        Some(Syscall::Exit) => {
            // Exit never returns, so record it BEFORE diverging: the trace must
            // capture the final syscall too. its "result" is the exit code it
            // was asked for (arg0), since no value flows back to userspace.
            crate::trace::record(nr, [arg0, arg1, arg2], arg0);
            // arg0 is the exit code; map the two known codes, default to Failed.
            let code = match arg0 {
                0x10 => crate::QemuExitCode::Success,
                _ => crate::QemuExitCode::Failed,
            };
            crate::exit_qemu(code);
            // exit_qemu returns if the debug-exit device is absent; halt so we
            // never fall back into user mode with a bogus result.
            crate::hlt_loop();
        }
        // ipc_send(cap_slot = arg0, word = arg1) -> 0 | errno.
        Some(Syscall::IpcSend) => ipc::sys_ipc_send(arg0, arg1).into(),
        // ipc_recv(cap_slot = arg0) -> word | (errno | IPC_ERR_FLAG), badge in rdx.
        Some(Syscall::IpcRecv) => ipc::sys_ipc_recv(arg0),
        // retype(untyped_slot = arg0, type_word = arg1, dest_slot = arg2).
        Some(Syscall::Retype) => objects::sys_retype(arg0, arg1, arg2).into(),
        // invoke(cap_slot = arg0, method = arg1, arg0_word = arg2).
        Some(Syscall::Invoke) => objects::sys_invoke(arg0, arg1, arg2).into(),
        // ipc_send_blocking(cap_slot = arg0, word = arg1).
        Some(Syscall::IpcSendBlocking) => ipc::sys_ipc_send_blocking(arg0, arg1).into(),
        // ipc_recv_blocking(cap_slot = arg0).
        Some(Syscall::IpcRecvBlocking) => ipc::sys_ipc_recv_blocking(arg0),
        // mint(src_slot = arg0, rights = arg1, badge = arg2) -> new slot.
        Some(Syscall::Mint) => objects::sys_mint(arg0, arg1, arg2).into(),
        // call(cap_slot = arg0, word = arg1) -> reply word.
        Some(Syscall::Call) => ipc::sys_call(arg0, arg1).into(),
        // recv_reply(ep_slot = arg0, reply_slot = arg1) -> word, badge in rdx.
        Some(Syscall::RecvReply) => ipc::sys_recv_reply(arg0, arg1),
        // reply(reply_slot = arg0, word = arg1) -> 0 | errno.
        Some(Syscall::Reply) => ipc::sys_reply(arg0, arg1).into(),
        // set_ipc_buffer(frame_slot = arg0) -> 0 | errno.
        Some(Syscall::SetIpcBuffer) => ipc::sys_set_ipc_buffer(arg0).into(),
        // reply_recv(ep_slot = arg0, reply_slot = arg1, word = arg2).
        Some(Syscall::ReplyRecv) => ipc::sys_reply_recv(arg0, arg1, arg2),
        // map_page_table(vspace_slot = arg0, table_slot = arg1, vaddr = arg2).
        Some(Syscall::MapPageTable) => vm::sys_map_page_table(arg0, arg1, arg2).into(),
        // map_frame(vspace_slot = arg0, frame_slot = arg1, vaddr | flags = arg2).
        Some(Syscall::MapFrame) => vm::sys_map_frame(arg0, arg1, arg2).into(),
        // unmap(object_slot = arg0) -> 0 | errno.
        Some(Syscall::Unmap) => vm::sys_unmap(arg0).into(),
        // tcb_configure(tcb_slot = arg0, cnode_slot = arg1, vspace_slot = arg2).
        Some(Syscall::TcbConfigure) => thread::sys_tcb_configure(arg0, arg1, arg2).into(),
        // tcb_set_ipc_buffer(tcb_slot = arg0, frame_slot = arg1).
        Some(Syscall::TcbSetIpcBuffer) => thread::sys_tcb_set_ipc_buffer(arg0, arg1).into(),
        // tcb_start(tcb_slot = arg0, entry = arg1, stack_top = arg2).
        Some(Syscall::TcbStart) => thread::sys_tcb_start(arg0, arg1, arg2).into(),
        // cnode_copy(dest_cnode_slot = arg0, src_slot = arg1, packed = arg2).
        Some(Syscall::CNodeCopy) => objects::sys_cnode_copy(arg0, arg1, arg2).into(),
        // revoke(slot = arg0) -> count removed.
        Some(Syscall::Revoke) => objects::sys_revoke(arg0).into(),
        // console_write(console_slot = arg0, len = arg1) -> 0 | errno.
        Some(Syscall::ConsoleWrite) => platform::sys_console_write(arg0, arg1).into(),
        // machine_halt(machine_slot = arg0, code = arg1); returns only if refused.
        Some(Syscall::MachineHalt) => platform::sys_machine_halt(arg0, arg1).into(),
        // thread_exit(): the stub switches away for good.
        Some(Syscall::ThreadExit) => thread::sys_thread_exit().into(),
        // tcb_set_fault_handler(tcb_slot = arg0, fault_slot = arg1) -> 0 | errno.
        Some(Syscall::TcbSetFaultHandler) => thread::sys_tcb_set_fault_handler(arg0, arg1).into(),
        // recv_timeout(ep_slot = arg0, reply_slot = arg1, ms = arg2) -> word, badge in rdx.
        Some(Syscall::RecvTimeout) => ipc::sys_recv_timeout(arg0, arg1, arg2),
        // console_read(console_slot = arg0, max = arg1, ms = arg2) -> byte count.
        Some(Syscall::ConsoleRead) => platform::sys_console_read(arg0, arg1, arg2),
        None => ENOSYS.into(),
    };
    // tap the chokepoint: every returning syscall is recorded with the value it
    // hands back to userspace, the structured trace event of VISION star 5.
    // (Exit recorded itself above, since it does not reach here.)
    crate::trace::record(nr, [arg0, arg1, arg2], result.rax);
    result
}

/// The current task's CSpace pointer, read from the per-CPU block. This is the
/// thread the entry stub's swapgs + switch_to selected; it is the heart of
/// per-thread isolation (each thread resolves capabilities in ITS OWN space).
fn current_cspace_ptr() -> *mut KernelCapSpace {
    // SAFETY: single-CPU, interrupts disabled on the syscall path; reading the
    // per-CPU block does not alias another access.
    unsafe { (*cpu_local::cpu_local_ptr()).current_cspace }
}

/// Resolves the current task's CSpace for MUTATION (retype installs a capability
/// via insert_at). Same pointer as current_cspace, but exclusive.
///
/// SAFETY note: returns an exclusive reference to the kernel-owned CapSpace the
/// per-CPU block points at; sound on the single-threaded syscall path where the
/// pointer is live and unaliased, and no other reference is taken for the call.
fn current_cspace_mut() -> Option<&'static mut KernelCapSpace> {
    let ptr = current_cspace_ptr();
    if ptr.is_null() {
        return None;
    }
    // SAFETY: as current_cspace, but exclusive; single-threaded syscall path, no
    // aliasing reference is live across this call.
    Some(unsafe { &mut *ptr })
}

/// Resolves the current task's CSpace, the one IPC syscalls address capabilities
/// in. Returns None if no CSpace is installed (a kernel setup bug).
///
/// SAFETY note: the returned reference borrows the kernel-owned CapSpace the
/// per-CPU block points at; the caller (an IPC syscall handler) uses it only
/// within the single-threaded syscall path, where the pointer is live and
/// unaliased.
fn current_cspace() -> Option<&'static KernelCapSpace> {
    let ptr = current_cspace_ptr();
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the pointer was installed via switch_to / set_current_cspace,
    // pointing at a live, 'static, non-concurrently-mutated KernelCapSpace. jos
    // is single-threaded across syscalls, so no aliasing &mut exists.
    Some(unsafe { &*ptr })
}


/// Returns a copy of the live capability at `cap_slot` of the current `CSpace`.
fn current_cap(cap_slot: u64) -> Option<Capability<ObjectId>> {
    let space = current_cspace()?;
    let cap_ref = space.ref_at(usize::try_from(cap_slot).ok()?)?;
    space.lookup(cap_ref).copied()
}

/// Resolves `slot` to a capability of `kind` carrying `rights`.
///
/// # Errors
///
/// [`IpcSyscallError::BadCap`] if the slot is empty, `wrong_kind` if it names
/// another kind of object, or [`IpcSyscallError::Denied`] if a right is missing.
fn resolve_object(
    slot: u64,
    kind: ObjectKind,
    rights: Rights,
    wrong_kind: IpcSyscallError,
) -> Result<ObjectId, IpcSyscallError> {
    let cap = current_cap(slot).ok_or(IpcSyscallError::BadCap)?;
    if cap.object.kind() != kind {
        return Err(wrong_kind);
    }
    if !cap.rights.contains(rights) {
        return Err(IpcSyscallError::Denied);
    }
    Ok(cap.object)
}

/// Resolves `slot` to an address space the capability grants `WRITE` on.
fn resolve_vspace(slot: u64) -> Result<ObjectId, IpcSyscallError> {
    resolve_object(slot, ObjectKind::VSpace, Rights::WRITE, IpcSyscallError::NotVSpace)
}

// the raw syscall entry point installed in LSTAR. it runs in ring 0 with the
// USER stack still in rsp (syscall does not switch stacks) and with GS still the
// user's, so it must swapgs to reach the per-CPU block and switch to the kernel
// stack before touching memory through the stack.
//
// written as a global_asm symbol (not a naked fn) so the compiler emits no
// stack frame of its own: rsp is still the user stack on entry, so any
// compiler-generated prologue would push onto user memory. the whole body is
// one assembly block.
//
// register discipline (jos syscall ABI):
//   on entry  rcx = user return RIP, r11 = user RFLAGS (both set by `syscall`);
//             rax = syscall nr; rdi/rsi/rdx = args 0/1/2.
//   a syscall is treated like a C call: caller-saved registers may be clobbered
//   by the dispatcher; rcx and r11 are reserved by the instruction; rax holds
//   the return value on the way out.
//
// swapgs discipline: exactly one swapgs on entry, one on exit. After the entry
// swapgs, GS base = the CpuLocal pointer (KernelGsBase held it while in ring 3),
// so `gs:[OFF_*]` addresses the per-CPU block; the exit swapgs restores the user
// GS and parks the CpuLocal pointer back in KernelGsBase. The kernel_rsp loaded
// is THIS thread's (switch_to set it), which is what makes the stack per-thread.
//
// stack alignment: the SysV C ABI requires rsp % 16 == 0 at a `call`. kernel_rsp
// is 16-aligned, so three 8-byte pushes leave rsp % 16 == 8; an explicit 8-byte
// pad restores 16 before the call and is undone after.
core::arch::global_asm!(
    ".global syscall_entry",
    "syscall_entry:",
    // swapgs: KernelGsBase (CpuLocal ptr) <-> GsBase. now gs: = CpuLocal.
    "swapgs",
    // stash user rsp before the stack switch.
    "mov gs:[{user_rsp_scratch}], rsp",
    // save user-return registers to CpuLocal BEFORE anything clobbers them.
    // rcx = user RIP (set by syscall), r11 = user RFLAGS (set by syscall).
    // callee-saved GPRs (rbx, rbp, r12-r15) must be preserved across the
    // syscall ABI; for blocking IPC the thread is resumed via iretq rather
    // than sysretq, so we capture them here for the resume context.
    "mov gs:[{saved_rip}], rcx",
    "mov gs:[{saved_rflags}], r11",
    "mov gs:[{saved_rbx}], rbx",
    "mov gs:[{saved_rbp}], rbp",
    "mov gs:[{saved_r12}], r12",
    "mov gs:[{saved_r13}], r13",
    "mov gs:[{saved_r14}], r14",
    "mov gs:[{saved_r15}], r15",
    // clear need_yield before dispatch (a blocking syscall sets it to 1).
    "mov qword ptr gs:[{need_yield}], 0",
    // switch to this thread's kernel stack.
    "mov rsp, gs:[{kernel_rsp}]",
    // push user return state for the sysretq path.
    "push gs:[{user_rsp_scratch}]", // [+24] user rsp
    "push rcx",                     // [+16] user rip
    "push r11",                     // [+8]  user rflags
    "sub rsp, 8",                   // [+0]  align to 16 for call
    // rotate jos ABI args into C ABI registers.
    "mov rcx, rdx",                 // arg2 -> 4th C arg
    "mov rdx, rsi",                 // arg1 -> 3rd C arg
    "mov rsi, rdi",                 // arg0 -> 2nd C arg
    "mov rdi, rax",                 // nr   -> 1st C arg
    "call {dispatch}",
    "add rsp, 8",                   // drop alignment pad
    // check need_yield: if a blocking syscall parked this thread, jump to the
    // idle entry (sets CURRENT=NO_THREAD, resets rsp, enters sti;hlt loop).
    "cmp qword ptr gs:[{need_yield}], 0",
    "je 1f",
    "call {idle}",                  // -> ! (never returns)
    "ud2",                          // unreachable
    // normal sysretq path.
    "1:",
    "pop r11",
    "pop rcx",
    "pop rsp",
    "swapgs",
    "sysretq",
    user_rsp_scratch = const OFF_USER_RSP_SCRATCH,
    kernel_rsp = const OFF_KERNEL_RSP,
    saved_rip = const OFF_SAVED_USER_RIP,
    saved_rflags = const OFF_SAVED_USER_RFLAGS,
    need_yield = const OFF_NEED_YIELD,
    saved_rbx = const OFF_SAVED_USER_RBX,
    saved_rbp = const OFF_SAVED_USER_RBP,
    saved_r12 = const OFF_SAVED_USER_R12,
    saved_r13 = const OFF_SAVED_USER_R13,
    saved_r14 = const OFF_SAVED_USER_R14,
    saved_r15 = const OFF_SAVED_USER_R15,
    dispatch = sym dispatch_syscall,
    idle = sym crate::sched::enter_idle_from_syscall,
);

unsafe extern "C" {
    /// The assembly syscall entry point (defined in the `global_asm!` above).
    /// Its address is written to `LSTAR`.
    fn syscall_entry();
}
