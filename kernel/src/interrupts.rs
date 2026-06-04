//! Interrupt Descriptor Table, CPU exception handlers, and the 8259 PIC.
//!
//! post 05 installed an IDT with the x86-interrupt calling convention and a
//! breakpoint handler. post 06 added the double-fault handler on an IST stack.
//! post 07 (here) adds the legacy 8259 PIC and hardware interrupt handlers for
//! the timer (IRQ0) and keyboard (IRQ1).
//!
//! we start with the 8259 PIC rather than the APIC: qemu's q35 emulates it, it
//! needs no ACPI/MADT parsing, and single-core does not need the APIC yet. the
//! APIC is a later upgrade (alongside SMP).
//!
//! the IDT is also the future syscall/IPC trap path of the capability kernel.

use core::sync::atomic::{AtomicUsize, Ordering};

use pic8259::ChainedPics;
use spin::Mutex;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

use crate::serial_println;

/// First vector the primary PIC is remapped to. Vectors 0x00..0x20 are CPU
/// exceptions, so the 16 PIC IRQs are mapped to 0x20..0x30.
pub const PIC_1_OFFSET: u8 = 32;
/// First vector the secondary PIC is remapped to (`PIC_1_OFFSET` + 8).
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

/// The chained 8259 PICs. `ChainedPics::new` is a const fn, so this is a
/// compile-time static (no `lazy_static`); the mutex gives the interior
/// mutability needed for `initialize` and `notify_end_of_interrupt`.
pub static PICS: Mutex<ChainedPics> =
    // SAFETY: PIC_1_OFFSET / PIC_2_OFFSET (32 / 40) sit above the 32 CPU
    // exception vectors and below any vectors we assign later. this is the
    // canonical remapping; constructing the PICs has no effect until initialize.
    Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

/// Monotonic timer tick counter, incremented by the timer interrupt handler.
/// Relaxed ordering suffices: readers only need a lower bound (did the timer
/// fire), not ordering against other memory operations.
pub static TICK_COUNT: AtomicUsize = AtomicUsize::new(0);

/// IDT vector indices for the hardware interrupt lines we handle.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    /// PIT timer on IRQ0, remapped to vector 32.
    Timer = PIC_1_OFFSET,
    /// PS/2 keyboard on IRQ1, remapped to vector 33.
    Keyboard,
}

impl InterruptIndex {
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub fn as_usize(self) -> usize {
        usize::from(self.as_u8())
    }
}

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
        // route the double-fault handler onto its own IST stack so a kernel
        // stack overflow is handled instead of triple-faulting. the gdt module
        // must have installed the TSS (init_gdt) before this runs.
        idt.double_fault
            .set_handler_fn(double_fault_handler)
            .set_stack_index(crate::gdt::DOUBLE_FAULT_IST_INDEX);
        idt.page_fault.set_handler_fn(page_fault_handler);
        // hardware interrupt handlers (post 07).
        idt[InterruptIndex::Timer.as_usize()].set_handler_fn(timer_interrupt_handler);
        idt[InterruptIndex::Keyboard.as_usize()].set_handler_fn(keyboard_interrupt_handler);
        idt.load();
    }
}

/// Initializes the 8259 PIC (remaps the IRQs to vectors 32..48). Call once
/// during kernel init, after `init_idt` so the timer/keyboard vectors already
/// have handlers before the first IRQ can arrive.
pub fn init_pics() {
    // SAFETY: called once during single-threaded init; the offsets do not
    // overlap the CPU exception vectors, and the IDT entries for the remapped
    // vectors are installed by the time interrupts are enabled.
    unsafe {
        PICS.lock().initialize();
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

// double fault (#DF) fires when handling one exception triggers another (the
// classic case: a stack overflow whose page fault then faults again). it is not
// recoverable, so the handler is diverging; the x86_64 crate types the error
// code as u64 and requires a `-> !` return. running on the IST stack set up in
// the gdt module is what keeps this handler from itself faulting.
extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    panic!("EXCEPTION: DOUBLE FAULT\n{stack_frame:#?}");
}

// page fault (#PF). cr2 holds the faulting address and the error code says why
// (present/write/user bits). we report and halt rather than recover; this is a
// diagnostic so paging bugs show the faulting address instead of escalating to
// an opaque double fault.
extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: x86_64::structures::idt::PageFaultErrorCode,
) {
    let addr = x86_64::registers::control::Cr2::read();
    serial_println!("EXCEPTION: PAGE FAULT");
    serial_println!("  accessed address: {:?}", addr);
    serial_println!("  error code: {:?}", error_code);
    serial_println!("{:#?}", stack_frame);
    crate::hlt_loop();
}

// timer (IRQ0, vector 32). the PIT fires continuously (~18.2 Hz) once the PIC
// is initialized. we bump the tick counter and MUST send EOI, or the PIC will
// never deliver another timer interrupt.
extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    TICK_COUNT.fetch_add(1, Ordering::Relaxed);
    // SAFETY: Timer is the correct vector for IRQ0; signaling EOI for the wrong
    // line could leave an unrelated interrupt masked.
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Timer.as_u8());
    }
}

// keyboard (IRQ1, vector 33). the handler does the minimum bounded work:
// consume the scancode from the PS/2 data port and hand it to the keyboard
// module, which pushes it onto a lock-free queue and wakes the decoder task. the
// pc-keyboard decode + printing happens later on the executor (the async
// ScancodeStream pattern), not in interrupt context. the handler runs with
// interrupts disabled (the cpu clears IF on entry), so add_scancode's queue push
// is uncontended here.
extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    use x86_64::instructions::port::Port;

    // always drain the PS/2 data register (port 0x60), or the controller will
    // not raise further keyboard interrupts.
    let mut port: Port<u8> = Port::new(0x60);
    // SAFETY: 0x60 is the PS/2 data port; reading it is the defined way to
    // consume the scancode that caused this IRQ.
    let scancode: u8 = unsafe { port.read() };

    // enqueue + wake; no decoding here.
    crate::keyboard::add_scancode(scancode);

    // SAFETY: Keyboard is the correct vector for IRQ1.
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Keyboard.as_u8());
    }
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
