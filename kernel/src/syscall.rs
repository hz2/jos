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
//! # jos system-call ABI (slice 3b)
//!
//! Register-only, no IPC buffer yet (that arrives with the cap IPC syscall,
//! slice 3d). Mirrors the SysV-ish convention the user code already uses:
//!
//! | Register | Meaning |
//! |----------|---------|
//! | `rax`    | syscall number ([`Syscall`]) on entry, return value on exit |
//! | `rdi`    | argument 0 |
//! | `rsi`    | argument 1 |
//! | `rdx`    | argument 2 |
//!
//! `rcx` and `r11` are reserved by the `syscall` instruction itself and must
//! not be used to pass arguments.
//!
//! # Single-thread kernel stack (for now)
//!
//! The kernel stack the entry stub switches to is held in one static
//! ([`KERNEL_RSP`]). That is correct while jos runs a single userspace thread
//! at a time; the per-TCB version (a kernel stack per thread, swapped via
//! `KernelGsBase`/`swapgs` on entry) arrives with the retypeable `Tcb` object
//! in slice 3c.

use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::VirtAddr;
use x86_64::registers::model_specific::{Efer, EferFlags, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;

use crate::gdt;

/// The system calls jos understands in slice 3b.
///
/// Deliberately tiny: just enough to prove the boundary works end to end. The
/// capability operations (retype, invoke, IPC send/recv) become syscalls in
/// later sub-slices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum Syscall {
    /// `add(a, b) -> a + b` (wrapping). A pure, side-effect-free probe that
    /// proves arguments flow in and a result flows back out across the boundary.
    Add = 0,
    /// `exit(code)`: write `code` to the qemu isa-debug-exit port. Lets a
    /// ring-3 program end the test with a pass/fail verdict. Does not return.
    Exit = 1,
}

impl Syscall {
    // maps a raw syscall number to its enum form, or None if unknown.
    fn from_u64(n: u64) -> Option<Self> {
        match n {
            0 => Some(Self::Add),
            1 => Some(Self::Exit),
            _ => None,
        }
    }
}

/// Sentinel returned in `rax` when the syscall number is not recognized.
pub const ENOSYS: u64 = u64::MAX;

/// The kernel stack pointer the syscall entry stub switches to on entry.
///
/// Set by [`set_kernel_stack`] before dropping to user mode. A single slot
/// suffices for one userspace thread; slice 3c replaces it with a per-thread
/// stack selected via `KernelGsBase`.
static KERNEL_RSP: AtomicU64 = AtomicU64::new(0);

/// Records the kernel stack pointer the next syscall entry will switch to.
///
/// Call with the top of a valid kernel stack before [`crate::usermode::
/// enter_user_mode`]. The value is read by the assembly entry stub.
pub fn set_kernel_stack(rsp: VirtAddr) {
    KERNEL_RSP.store(rsp.as_u64(), Ordering::SeqCst);
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
    // entry state.
    SFMask::write(RFlags::INTERRUPT_FLAG | RFlags::DIRECTION_FLAG | RFlags::TRAP_FLAG);

    // finally enable the syscall/sysret instructions in EFER.
    // SAFETY: we set only the SYSTEM_CALL_EXTENSIONS bit; Efer::write preserves
    // the reserved bits and the existing long-mode flags, so this cannot
    // disable long mode or otherwise break memory safety. LSTAR/STAR/SFMASK are
    // already programmed above, so the first syscall has a valid target.
    unsafe {
        Efer::write(Efer::read() | EferFlags::SYSTEM_CALL_EXTENSIONS);
    }
}

/// The Rust system-call dispatcher, called by [`syscall_entry`] with the user
/// arguments already in C-ABI registers.
///
/// Returns the value to place in the user's `rax`. `Syscall::Exit` does not
/// return (it ends the qemu session); every other call returns a `u64`.
///
/// `extern "C"` so the assembly stub can call it with the standard argument
/// registers (`rdi`, `rsi`, `rdx`, `rcx`) holding (nr, arg0, arg1, arg2).
extern "C" fn dispatch_syscall(nr: u64, arg0: u64, arg1: u64, _arg2: u64) -> u64 {
    match Syscall::from_u64(nr) {
        Some(Syscall::Add) => arg0.wrapping_add(arg1),
        Some(Syscall::Exit) => {
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
        None => ENOSYS,
    }
}

// the raw syscall entry point installed in LSTAR. it runs in ring 0 with the
// USER stack still in rsp (syscall does not switch stacks), so it must switch
// to the kernel stack before touching memory through the stack.
//
// written as a global_asm symbol (not a naked fn) so the compiler emits no
// stack frame of its own: rsp is still the user stack on entry, so any
// compiler-generated prologue would push onto user memory. the whole body is
// one assembly block.
//
// register discipline (jos syscall ABI, slice 3b):
//   on entry  rcx = user return RIP, r11 = user RFLAGS (both set by `syscall`);
//             rax = syscall nr; rdi/rsi/rdx = args 0/1/2.
//   a syscall is treated like a C call: caller-saved registers may be clobbered
//   by the dispatcher; rcx and r11 are reserved by the instruction; rax holds
//   the return value on the way out.
//
// stack alignment: the SysV C ABI requires rsp % 16 == 0 at a `call`. KERNEL_RSP
// is 16-aligned (see set_kernel_stack), so three 8-byte pushes leave rsp % 16
// == 8; an explicit 8-byte pad restores 16 before the call and is undone after.
core::arch::global_asm!(
    ".global syscall_entry",
    "syscall_entry:",
    // save the user stack pointer into a scratch register the SysV ABI lets us
    // clobber (r10 is caller-saved and untouched by `syscall`), then switch to
    // the kernel stack loaded from KERNEL_RSP.
    "mov r10, rsp",                 // r10 = user rsp
    "mov rsp, [rip + {kernel_rsp}]",// rsp = kernel stack top (16-aligned)
    // preserve the values sysretq depends on, plus the user rsp, on the kernel
    // stack across the dispatcher call.
    "push r10",                     // [kernel stack] user rsp        rsp%16=8
    "push rcx",                     // user return RIP (sysretq uses)  rsp%16=0
    "push r11",                     // user RFLAGS (sysretq uses)      rsp%16=8
    "sub rsp, 8",                   // align to 16 for the call        rsp%16=0
    // marshal the jos ABI (nr in rax, args in rdi/rsi/rdx) into the C ABI the
    // dispatcher expects: dispatch_syscall(nr, arg0, arg1, arg2) lands in
    // rdi, rsi, rdx, rcx. this is a register rotation; the move order is chosen
    // so each source is read before it is overwritten, and it runs AFTER the
    // pushes so rcx's user value is already safe on the stack.
    "mov rcx, rdx",                 // arg2 -> 4th C arg (rcx)
    "mov rdx, rsi",                 // arg1 -> 3rd C arg (rdx)
    "mov rsi, rdi",                 // arg0 -> 2nd C arg (rsi)
    "mov rdi, rax",                 // nr   -> 1st C arg (rdi)
    "call {dispatch}",              // rax = return value
    // tear down: drop the alignment pad, restore the syscall-return state and
    // the user stack, then return to ring 3.
    "add rsp, 8",                   // drop alignment pad
    "pop r11",                      // user RFLAGS
    "pop rcx",                      // user return RIP
    "pop r10",                      // user rsp
    "mov rsp, r10",                 // back onto the user stack
    "sysretq",                      // -> ring 3 at rcx, RFLAGS = r11
    kernel_rsp = sym KERNEL_RSP,
    dispatch = sym dispatch_syscall,
);

unsafe extern "C" {
    /// The assembly syscall entry point (defined in the `global_asm!` above).
    /// Its address is written to `LSTAR`.
    fn syscall_entry();
}
