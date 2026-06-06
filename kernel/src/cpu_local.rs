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
//! one. Today only the `syscall` path needs it (interrupts are masked while in
//! ring 3 during the deterministic bring-up). When ring 3 becomes
//! interruptible, every IDT entry reachable from ring 3 must gain a
//! conditional `swapgs` (gated on the saved `CS` `RPL`); that is deferred with
//! preemption. See `interrupts.rs`.

use crate::cap::{KernelCapSpace, Tcb};

/// Per-CPU kernel data, addressed via `gs:` after the entry stub's `swapgs`.
///
/// `repr(C)` so the field offsets are stable and match the assembly-visible
/// [`OFF_KERNEL_RSP`] / [`OFF_USER_RSP_SCRATCH`] constants (compile-time
/// asserted below).
#[repr(C)]
pub struct CpuLocal {
    /// Top of the kernel stack the running thread switches to on `syscall`
    /// entry. The entry stub loads `rsp` from here (offset 0).
    pub kernel_rsp: u64,
    /// Scratch slot where the entry stub stashes the user `rsp` before it has
    /// switched to the kernel stack (it cannot push to the user stack from ring
    /// 0). Offset 8.
    pub user_rsp_scratch: u64,
    /// Pointer to the current thread's capability space, resolved per IPC
    /// syscall. Null until [`switch_to`] (or the compat setter) installs one.
    pub current_cspace: *mut KernelCapSpace,
    /// Pointer to the currently-scheduled TCB, or null. Bookkeeping for a future
    /// preemptive scheduler; not read by the syscall dispatch itself.
    pub current_tcb: *mut Tcb,
}

/// Offset of [`CpuLocal::kernel_rsp`], for the `gs:`-relative entry stub.
pub const OFF_KERNEL_RSP: usize = 0;
/// Offset of [`CpuLocal::user_rsp_scratch`], for the entry stub.
pub const OFF_USER_RSP_SCRATCH: usize = 8;

// the assembly hard-codes these offsets via `const` operands; assert they match
// the actual field layout so a field reorder fails the build rather than
// silently corrupting the stack switch.
const _: () = assert!(core::mem::offset_of!(CpuLocal, kernel_rsp) == OFF_KERNEL_RSP);
const _: () = assert!(core::mem::offset_of!(CpuLocal, user_rsp_scratch) == OFF_USER_RSP_SCRATCH);

// SAFETY: CpuLocal holds raw pointers, so it is not Sync/Send by default. It is
// only ever accessed from ring-0 code with interrupts disabled (SFMASK clears
// IF on syscall entry), on a single CPU, so there is no concurrent access. The
// impl is required to hold it in a `static mut`.
unsafe impl Sync for CpuLocal {}
// SAFETY: as the Sync impl above: single-CPU, ring-0, interrupts-disabled
// access only, so no cross-thread sharing hazard despite the raw pointers.
unsafe impl Send for CpuLocal {}

// the bootstrap CPU's per-CPU block. SMP would index this by APIC id.
static mut CPU_LOCAL: CpuLocal = CpuLocal {
    kernel_rsp: 0,
    user_rsp_scratch: 0,
    current_cspace: core::ptr::null_mut(),
    current_tcb: core::ptr::null_mut(),
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
/// `tcb`'s kernel stack and resolves capabilities in its capability space.
///
/// Does not save the outgoing thread's context (that is a preemption concern);
/// it just selects which thread the kernel serves next.
///
/// # Safety
///
/// `tcb` must point to a live, initialized [`Tcb`] whose `kernel_stack_top` is
/// the top of a valid kernel stack and whose `cspace_ptr` is a live, `'static`
/// [`KernelCapSpace`] (or null). Must be called from ring 0 with interrupts
/// disabled.
pub unsafe fn switch_to(tcb: *mut Tcb) {
    // SAFETY: per this fn's contract tcb is live; single-CPU, interrupts
    // disabled, so the &mut CpuLocal does not alias another access.
    unsafe {
        let tcb_ref = &mut *tcb;
        let local = &mut *cpu_local_ptr();
        local.kernel_rsp = tcb_ref.kernel_stack_top;
        local.current_cspace = tcb_ref.cspace_ptr;
        local.current_tcb = tcb;
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
