//! Global Descriptor Table and Task State Segment.
//!
//! this is blog_os post 06. its purpose is to give the double-fault handler a
//! known-good stack via the Interrupt Stack Table (IST), so a kernel stack
//! overflow is caught cleanly instead of escalating to a triple fault that
//! resets the machine.
//!
//! when a stack overflow occurs, the cpu tries to push the exception stack
//! frame onto the (already exhausted) stack, which faults again. without an IST
//! the double-fault handler would itself fault on the bad stack, triple-fault,
//! and reset. the IST mechanism makes the cpu switch to a separate, valid stack
//! before running the handler.
//!
//! the trampoline in boot.s already loaded a minimal GDT to enter long mode.
//! here we install a fuller GDT that also contains a TSS descriptor, then load
//! the task register, so the IST stack is available to the IDT.

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

// the TSS holds the IST. like the IDT it must outlive the load (the cpu keeps a
// pointer after ltr), so it is a static built once during init.
static mut TSS: TaskStateSegment = TaskStateSegment::new();

// the GDT, populated and loaded by init().
static mut GDT: GlobalDescriptorTable = GlobalDescriptorTable::new();

/// Installs the GDT and TSS and loads the task register, making the
/// double-fault IST stack available. Call once during early kernel init,
/// before the IDT registers the double-fault handler.
pub fn init_gdt() {
    // SAFETY: single-threaded boot context. nothing else references TSS, GDT,
    // SELECTORS, or DOUBLE_FAULT_STACK yet, and init runs exactly once before
    // interrupts are enabled, so there is no aliasing or concurrent access.
    unsafe {
        let tss = &mut *core::ptr::addr_of_mut!(TSS);
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            let stack_start = VirtAddr::from_ptr(core::ptr::addr_of!(DOUBLE_FAULT_STACK));
            // ist entry points at the TOP of the stack (it grows downward).
            stack_start + STACK_SIZE as u64
        };

        // gdt layout: null (auto), kernel code, kernel data, then the TSS
        // (a 16-byte system descriptor occupying two slots). including a real
        // data segment lets us give ss/ds/es a valid non-null selector, which
        // the production rust kernels (redox, theseus) do, rather than relying
        // on null ss (whose iretq behavior across privilege levels is
        // implementation-defined and would bite once we add userspace).
        let gdt = &mut *core::ptr::addr_of_mut!(GDT);
        let code_selector = gdt.add_entry(Descriptor::kernel_code_segment());
        let data_selector = gdt.add_entry(Descriptor::kernel_data_segment());
        let tss_selector = gdt.add_entry(Descriptor::tss_segment(&*core::ptr::addr_of!(TSS)));
        gdt.load();

        // gdt.load() sets GDTR but does NOT touch the segment registers; the
        // cpu keeps using each register's cached descriptor until the register
        // is reloaded. our trampoline left ss/ds/es/fs/gs = 0x10 (its data
        // segment), but in this gdt 0x10 is now the data segment too, then the
        // TSS follows. without reloading, the first iretq would re-validate the
        // stale selector against this gdt and could #GP. so reload every
        // segment register we are now responsible for.

        // reload cs with our 64-bit code selector (via retfq).
        CS::set_reg(code_selector);

        // give ss/ds/es a valid kernel data selector. ss in particular must be
        // a writable data segment for iretq to restore it cleanly when we later
        // return from a privilege transition.
        SS::set_reg(data_selector);
        DS::set_reg(data_selector);
        ES::set_reg(data_selector);
        // fs/gs are null for now; their bases are programmed via MSR (gs holds
        // per-cpu data later), so the selector itself does not need a descriptor.
        FS::set_reg(SegmentSelector::NULL);
        GS::set_reg(SegmentSelector::NULL);

        // load the task register so the cpu knows about the IST stacks.
        load_tss(tss_selector);
    }
}
