//! Global Descriptor Table and Task State Segment.
//!
//! This started as blog_os post 06: give the double-fault handler a known-good
//! stack via the Interrupt Stack Table (IST), so a kernel stack overflow is
//! caught cleanly instead of escalating to a triple fault that resets the
//! machine.
//!
//! When a stack overflow occurs, the cpu tries to push the exception stack
//! frame onto the (already exhausted) stack, which faults again. Without an IST
//! the double-fault handler would itself fault on the bad stack, triple-fault,
//! and reset. The IST mechanism makes the cpu switch to a separate, valid stack
//! before running the handler.
//!
//! Slice 3 (userspace) extends this in two ways:
//!
//! - user code and data segments (DPL 3) so the cpu can run ring-3 code and so
//!   `iretq` / `sysretq` have valid user selectors to restore.
//! - the TSS privilege-stack-table entry `rsp0`: the stack the cpu switches to
//!   on a ring-3 -> ring-0 transition (an interrupt or a stack-switching
//!   syscall path). Without it a ring-3 interrupt would keep using the user
//!   stack in kernel mode.
//!
//! ## Segment order is load-bearing
//!
//! The entries are laid out null, kernel-code, kernel-data, user-data,
//! user-code, TSS. The user-data-before-user-code order is not arbitrary: the
//! `SYSRET` instruction (slice 3b) derives the user CS and SS from a single
//! `STAR` base selector, requiring user-data at `base` (`+0x08` from the
//! sysret base) and user-code at `base + 0x10`. Fixing the order now means the
//! syscall slice does not have to renumber selectors.
//!
//! The trampoline in boot.s already loaded a minimal GDT to enter long mode;
//! here we install the fuller GDT, load the task register, and reload the
//! segment registers so the cpu uses this GDT's descriptors.

use x86_64::VirtAddr;
use x86_64::instructions::segmentation::{CS, DS, ES, FS, GS, SS, Segment};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;

/// IST index used for the double-fault handler's dedicated stack.
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

// size of the double-fault stack. 5 pages (20 KiB) is plenty for the handler;
// it never needs to be large because the handler does minimal work.
const STACK_SIZE: usize = 4096 * 5;

// the double-fault stack itself. it lives in .bss as a mutable static byte
// array; the TSS IST entry points at its top (stacks grow downward on x86).
static mut DOUBLE_FAULT_STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];

// the ring-0 stack the cpu switches to when a ring-3 thread enters the kernel
// via an interrupt (the TSS rsp0 / privilege_stack_table[0] entry). it must be
// distinct from the boot stack and from the IST stack: an interrupt taken in
// ring 3 pushes its stack frame here, and the handler then runs on it. 20 KiB
// matches the IST stack and is ample for the handlers we install.
//
// this is a single shared rsp0 because jos runs one userspace thread at a time
// for now; a per-TCB rsp0 (reprogrammed on context switch) arrives with the
// scheduler's userspace thread support (slice 3c).
static mut PRIVILEGE_STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];

// the TSS holds the IST and the privilege stack table. like the IDT it must
// outlive the load (the cpu keeps a pointer after ltr), so it is a static built
// once during init.
static mut TSS: TaskStateSegment = TaskStateSegment::new();

// the GDT, populated and loaded by init().
static mut GDT: GlobalDescriptorTable = GlobalDescriptorTable::new();

/// The segment selectors this GDT defines, captured at load time so callers
/// (the userspace entry path, the syscall MSR setup) can reference them by name
/// instead of hard-coding selector indices.
#[derive(Debug, Clone, Copy)]
pub struct Selectors {
    /// Ring-0 code selector (`CS` in kernel mode).
    pub kernel_code: SegmentSelector,
    /// Ring-0 data selector (`SS`/`DS`/`ES` in kernel mode).
    pub kernel_data: SegmentSelector,
    /// Ring-3 data selector (`SS`/`DS` in user mode), RPL 3.
    pub user_data: SegmentSelector,
    /// Ring-3 code selector (`CS` in user mode), RPL 3.
    pub user_code: SegmentSelector,
    /// The TSS selector loaded into the task register.
    pub tss: SegmentSelector,
}

// the loaded selectors, filled in by init_gdt. None until init runs.
static mut SELECTORS: Option<Selectors> = None;

/// Returns the segment selectors established by [`init_gdt`].
///
/// # Panics
///
/// Panics if called before [`init_gdt`].
#[must_use]
pub fn selectors() -> Selectors {
    // SAFETY: SELECTORS is written once in init_gdt before any reader runs, and
    // the kernel is single-threaded during the boot path that calls this. we
    // copy the value out (Selectors is Copy) rather than hand out a reference.
    unsafe { (*core::ptr::addr_of!(SELECTORS)).expect("init_gdt must run before selectors()") }
}

/// Installs the GDT and TSS and loads the task register, making the
/// double-fault IST stack and the ring-0 privilege stack available. Call once
/// during early kernel init, before the IDT registers the double-fault handler.
pub fn init_gdt() {
    // SAFETY: single-threaded boot context. nothing else references TSS, GDT,
    // SELECTORS, DOUBLE_FAULT_STACK, or PRIVILEGE_STACK yet, and init runs
    // exactly once before interrupts are enabled, so there is no aliasing or
    // concurrent access.
    unsafe {
        let tss = &mut *core::ptr::addr_of_mut!(TSS);
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            let stack_start = VirtAddr::from_ptr(core::ptr::addr_of!(DOUBLE_FAULT_STACK));
            // ist entry points at the TOP of the stack (it grows downward).
            stack_start + STACK_SIZE as u64
        };
        // rsp0: the stack the cpu loads on a ring-3 -> ring-0 transition. points
        // at the top of PRIVILEGE_STACK (grows downward), same as the IST entry.
        tss.privilege_stack_table[0] = {
            let stack_start = VirtAddr::from_ptr(core::ptr::addr_of!(PRIVILEGE_STACK));
            stack_start + STACK_SIZE as u64
        };

        // gdt layout: null (auto), kernel code, kernel data, user data, user
        // code, then the TSS (a 16-byte system descriptor occupying two slots).
        // the user-data-before-user-code order matters for SYSRET (see the
        // module docs). a real kernel-data segment lets us give ss/ds/es a
        // valid non-null selector, which the production rust kernels (redox,
        // theseus) do, rather than relying on null ss (whose iretq behavior
        // across privilege levels is implementation-defined and bites once we
        // add userspace).
        let gdt = &mut *core::ptr::addr_of_mut!(GDT);
        let kernel_code = gdt.add_entry(Descriptor::kernel_code_segment());
        let kernel_data = gdt.add_entry(Descriptor::kernel_data_segment());
        let user_data = gdt.add_entry(Descriptor::user_data_segment());
        let user_code = gdt.add_entry(Descriptor::user_code_segment());
        let tss_selector = gdt.add_entry(Descriptor::tss_segment(&*core::ptr::addr_of!(TSS)));
        gdt.load();

        // gdt.load() sets GDTR but does NOT touch the segment registers; the
        // cpu keeps using each register's cached descriptor until the register
        // is reloaded. our trampoline left ss/ds/es/fs/gs = 0x10 (its data
        // segment); in this gdt 0x10 is now the kernel data segment, so the
        // first iretq would re-validate the stale selector against this gdt and
        // could #GP. reload every segment register we are now responsible for.

        // reload cs with our 64-bit code selector (via retfq).
        CS::set_reg(kernel_code);

        // give ss/ds/es a valid kernel data selector. ss in particular must be
        // a writable data segment for iretq to restore it cleanly when we later
        // return from a privilege transition.
        SS::set_reg(kernel_data);
        DS::set_reg(kernel_data);
        ES::set_reg(kernel_data);
        // fs/gs are null for now; their bases are programmed via MSR (gs holds
        // per-cpu data later), so the selector itself does not need a descriptor.
        FS::set_reg(SegmentSelector::NULL);
        GS::set_reg(SegmentSelector::NULL);

        // load the task register so the cpu knows about the IST + rsp0 stacks.
        load_tss(tss_selector);

        // publish the selectors for the userspace entry and syscall paths.
        *core::ptr::addr_of_mut!(SELECTORS) = Some(Selectors {
            kernel_code,
            kernel_data,
            user_data,
            user_code,
            tss: tss_selector,
        });
    }
}
