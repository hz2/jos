//! Per-CPU kernel data, reached through the `GS` segment base (`swapgs`).
//!
//! This is the seam for running more than one userspace thread (Phase-2
//! follow-up). On `x86_64` the kernel keeps a pointer to its per-CPU data block
//! in the `KernelGsBase` MSR while userspace runs; the `syscall` entry stub
//! executes `swapgs` to make `GS` point at it, then loads the current thread's
//! kernel stack and capability space from `gs`-relative offsets, and `swapgs`
//! back before `sysretq`. Switching threads is then just updating this block
//! ([`switch_to`]) rather than rewriting globals.
//!
//! # Why this replaces the single globals
//!
//! Slices 3b/3d used a single `KERNEL_RSP` and `CURRENT_CSPACE` static: correct
//! for one userspace thread, but every thread would share one kernel stack and
//! one capability space. Selecting them per-thread on kernel entry is what lets
//! distinct threads have distinct stacks and CSpaces. The values now live in
//! [`CpuLocal`]; [`switch_to`] points them at a thread before it runs.
//!
//! # Single CPU for now
//!
//! There is one [`CpuLocal`] (the bootstrap CPU's). SMP would make this an array
//! indexed by APIC id, or give each CPU its own block in per-CPU memory; the
//! seam is that callers go through [`cpu_local_ptr`], not the static directly.
//!
//! # `swapgs` discipline (load-bearing)
//!
//! Every ring-3 -> ring-0 transition must `swapgs` exactly once on entry and
//! once on exit; an unpaired `swapgs` permanently corrupts `GS` until the next
//! one. The `syscall` path swaps unconditionally (only reachable from ring 3).
//! IDT handlers swap conditionally: they check the saved `CS` `RPL` field and
//! swap only when `RPL == 3`. Today ring 3 runs with `IF=0` so IDT handlers are
//! ring-0-only in practice, but the conditional `swapgs` is already wired. See
//! `interrupts.rs`.

use crate::cap::{KernelCapSpace, Tcb};
use x86_64::PhysAddr;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::PhysFrame;

/// Per-CPU kernel data, addressed via `gs:` after the entry stub's `swapgs`.
///
/// `repr(C)` so the field offsets are stable and match the assembly-visible
/// `OFF_*` constants (compile-time asserted below).
#[repr(C)]
pub struct CpuLocal {
    /// Top of the kernel stack the running thread switches to on `syscall`
    /// entry. The entry stub loads `rsp` from here (offset 0).
    pub kernel_rsp: u64,
    /// Scratch slot where the entry stub stashes the user `rsp` before it has
    /// switched to the kernel stack. Offset 8.
    pub user_rsp_scratch: u64,
    /// Pointer to the current thread's capability space. Null until [`switch_to`]
    /// installs one.
    pub current_cspace: *mut KernelCapSpace,
    /// Pointer to the currently-scheduled TCB, or null.
    pub current_tcb: *mut Tcb,
    // --- user context saved at syscall entry (for blocking IPC resume) ---
    /// User RIP (rcx on syscall entry, before argument marshaling clobbers it).
    pub saved_user_rip: u64,
    /// User RFLAGS (r11 on syscall entry).
    pub saved_user_rflags: u64,
    /// Set to 1 by a blocking syscall to signal the entry stub to yield the CPU
    /// instead of returning via sysretq.
    pub need_yield: u64,
    /// User callee-saved registers -- the SYSCALL ABI requires these are
    /// preserved across syscalls; when a syscall blocks and the thread is
    /// later resumed via iretq, these are loaded from the saved TCB context.
    pub saved_user_rbx: u64,
    pub saved_user_rbp: u64,
    pub saved_user_r12: u64,
    pub saved_user_r13: u64,
    pub saved_user_r14: u64,
    pub saved_user_r15: u64,
}

/// Offsets of [`CpuLocal`] fields, for the `gs:`-relative assembly stubs.
pub const OFF_KERNEL_RSP: usize = 0;
pub const OFF_USER_RSP_SCRATCH: usize = 8;
pub const OFF_SAVED_USER_RIP: usize = 32;
pub const OFF_SAVED_USER_RFLAGS: usize = 40;
pub const OFF_NEED_YIELD: usize = 48;
pub const OFF_SAVED_USER_RBX: usize = 56;
pub const OFF_SAVED_USER_RBP: usize = 64;
pub const OFF_SAVED_USER_R12: usize = 72;
pub const OFF_SAVED_USER_R13: usize = 80;
pub const OFF_SAVED_USER_R14: usize = 88;
pub const OFF_SAVED_USER_R15: usize = 96;

// the assembly hard-codes these offsets via `const` operands; assert they match
// the actual field layout so a field reorder fails the build rather than
// silently corrupting the stack switch.
const _: () = assert!(core::mem::offset_of!(CpuLocal, kernel_rsp) == OFF_KERNEL_RSP);
const _: () = assert!(core::mem::offset_of!(CpuLocal, user_rsp_scratch) == OFF_USER_RSP_SCRATCH);
const _: () = assert!(core::mem::offset_of!(CpuLocal, saved_user_rip) == OFF_SAVED_USER_RIP);
const _: () = assert!(core::mem::offset_of!(CpuLocal, saved_user_rflags) == OFF_SAVED_USER_RFLAGS);
const _: () = assert!(core::mem::offset_of!(CpuLocal, need_yield) == OFF_NEED_YIELD);
const _: () = assert!(core::mem::offset_of!(CpuLocal, saved_user_rbx) == OFF_SAVED_USER_RBX);
const _: () = assert!(core::mem::offset_of!(CpuLocal, saved_user_rbp) == OFF_SAVED_USER_RBP);
const _: () = assert!(core::mem::offset_of!(CpuLocal, saved_user_r12) == OFF_SAVED_USER_R12);
const _: () = assert!(core::mem::offset_of!(CpuLocal, saved_user_r13) == OFF_SAVED_USER_R13);
const _: () = assert!(core::mem::offset_of!(CpuLocal, saved_user_r14) == OFF_SAVED_USER_R14);
const _: () = assert!(core::mem::offset_of!(CpuLocal, saved_user_r15) == OFF_SAVED_USER_R15);

// SAFETY: CpuLocal holds raw pointers, so it is not Sync/Send by default. It is
// only ever accessed from ring-0 code with interrupts disabled (SFMASK clears
// IF on syscall entry), on a single CPU, so there is no concurrent access. The
// impl is required to hold it in a `static mut`.
unsafe impl Sync for CpuLocal {}
// SAFETY: as the Sync impl above: single-CPU, ring-0, interrupts-disabled
// access only, so no cross-thread sharing hazard despite the raw pointers.
unsafe impl Send for CpuLocal {}

/// The bootstrap CPU's per-CPU block. SMP would index this by APIC id.
static mut CPU_LOCAL: CpuLocal = CpuLocal {
    kernel_rsp: 0,
    user_rsp_scratch: 0,
    current_cspace: core::ptr::null_mut(),
    current_tcb: core::ptr::null_mut(),
    saved_user_rip: 0,
    saved_user_rflags: 0,
    need_yield: 0,
    saved_user_rbx: 0,
    saved_user_rbp: 0,
    saved_user_r12: 0,
    saved_user_r13: 0,
    saved_user_r14: 0,
    saved_user_r15: 0,
};

/// Returns a raw pointer to the bootstrap CPU's [`CpuLocal`] block.
///
/// Used to initialize `KernelGsBase` and by the compat setters and the syscall
/// dispatcher. Single-CPU; SMP would resolve the running CPU's block.
#[must_use]
pub fn cpu_local_ptr() -> *mut CpuLocal {
    // SAFETY: returns the address of the static; the pointer is only
    // dereferenced from ring 0 with interrupts disabled (single-CPU, no
    // concurrent access).
    core::ptr::addr_of_mut!(CPU_LOCAL)
}

/// Points the per-CPU block at `tcb`: the next `syscall` entry switches to
/// `tcb`'s kernel stack and resolves capabilities in its capability space, and
/// `tcb`'s address space (if it has one) becomes the active one.
///
/// Does not save the outgoing thread's context (that is a preemption concern);
/// it just selects which thread the kernel serves next.
///
/// # Safety
///
/// `tcb` must point to a live, initialized [`Tcb`] whose `kernel_stack_top` is
/// the top of a valid kernel stack and whose `cspace_ptr` is a live, `'static`
/// [`KernelCapSpace`] (or null). Its `vspace_root`, if non-zero, must be a
/// `VSpace` root with the kernel entries copied in. Must be called from ring 0
/// with interrupts disabled.
pub unsafe fn switch_to(tcb: *mut Tcb) {
    // SAFETY: per this fn's contract tcb is live; single-CPU, interrupts
    // disabled, so the &mut CpuLocal does not alias another access.
    unsafe {
        let tcb_ref = &mut *tcb;
        let local = &mut *cpu_local_ptr();
        local.kernel_rsp = tcb_ref.kernel_stack_top;
        local.current_cspace = tcb_ref.cspace_ptr;
        local.current_tcb = tcb;
        // load the thread's address space. every VSpace carries the kernel's
        // identity map and higher half, so the kernel keeps running across the
        // switch; skipping an unchanged root avoids a needless TLB flush.
        let root = tcb_ref.vspace_root;
        if root != 0 && root != Cr3::read().0.start_address().as_u64() {
            // SAFETY: root is the physical address of a VSpace the thread was
            // given (a page-aligned root with the kernel entries copied in), so
            // the code, stack, and data running this switch stay mapped.
            Cr3::write(
                PhysFrame::containing_address(PhysAddr::new(root)),
                Cr3Flags::empty(),
            );
        }
        // keep TSS rsp0 in sync so ring-3 interrupts also land on this thread's
        // kernel stack, not the shared boot-time PRIVILEGE_STACK. the CPU reads
        // privilege_stack_table[0] from memory on every ring-3 -> ring-0
        // transition, so this takes effect at the next such transition.
        if tcb_ref.kernel_stack_top != 0 {
            // SAFETY: ring 0, interrupts disabled (this fn's contract); init_gdt
            // has run (required before any switch_to call).
            crate::gdt::set_rsp0(x86_64::VirtAddr::new(tcb_ref.kernel_stack_top));
        }
    }
}
