//! Interrupt Descriptor Table and CPU exception handlers.
//!
//! this is blog_os post 05: we install an IDT with the x86-interrupt calling
//! convention and a handler for the breakpoint exception (#BP / int3). the IDT
//! is the dispatch table the cpu consults when an exception or interrupt fires;
//! it is the foundation for hardware interrupts (timer, keyboard) and, later,
//! the syscall/IPC trap path of the capability kernel.
//!
//! the double-fault handler needs a separate known-good stack (an IST entry in
//! the TSS) to survive a kernel stack overflow; that arrives with the GDT in
//! post 06. for now a breakpoint handler is enough to prove the IDT works.

use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

use crate::serial_println;

// the idt must outlive the call to load() (the cpu keeps a pointer to it after
// lidt), so it is a static. we use a mutable static guarded by a one-time init
// rather than lazy_static: the runtime initializer pattern is simpler to reason
// about and avoids a spin-lock first-access path in the boot sequence.
static mut IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();

/// Builds and loads the IDT into the cpu. Call once during early kernel init.
///
/// # Safety note
///
/// This touches a mutable static. It is sound because kernel init runs once,
/// single-threaded, before any interrupts are enabled, so there is no aliasing
/// or concurrent access to the IDT.
pub fn init_idt() {
    // SAFETY: single-threaded boot context; nothing else references IDT yet.
    unsafe {
        let idt = &mut *core::ptr::addr_of_mut!(IDT);
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.load();
    }
}

// breakpoint (#BP) is a trap: the cpu resumes at the instruction after int3
// once the handler returns, so we just log and continue. the x86-interrupt abi
// makes the compiler emit the correct prologue/epilogue (it preserves all
// registers and uses iretq), so the handler is an ordinary safe fn.
extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    // pass stack_frame as an explicit arg: serial_println! expands through
    // concat!, which blocks inline {var} capture in the format string.
    serial_println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

#[cfg(test)]
mod tests {
    // triggering int3 must return cleanly: if the breakpoint handler is wired
    // correctly the cpu resumes after the instruction and the test completes.
    // a missing or broken handler would instead escalate to a double/triple
    // fault and reset the machine, failing the test.
    #[test_case]
    fn breakpoint_exception_returns() {
        super::init_idt();
        x86_64::instructions::interrupts::int3();
        // reaching this line means the handler returned and execution resumed.
    }
}
