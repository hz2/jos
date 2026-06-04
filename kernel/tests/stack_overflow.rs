// tests/stack_overflow.rs
//
// verifies the post 06 payoff: a kernel stack overflow is caught by the
// double-fault handler running on its dedicated IST stack, instead of
// triple-faulting and resetting the machine.
//
// the test installs the gdt/tss (for the IST stack) and an IDT whose
// double-fault entry both uses that IST stack AND, for this test only, reports
// success via the qemu exit port. then it overflows the stack with infinite
// recursion. if the IST mechanism works, the double-fault handler runs and we
// exit Success; if it did not, the cpu would triple-fault and qemu would reset
// (the test would time out / fail).
#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

use core::panic::PanicInfo;
use jos::{QemuExitCode, exit_qemu, gdt, serial_print, serial_println};
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

// the trampoline (in the jos library) calls kernel_main in long mode.
#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, _info_ptr: u32) -> ! {
    serial_print!("stack_overflow::stack_overflow...\t");

    // install the gdt/tss (gives us the IST stack) and our test idt.
    gdt::init_gdt();
    init_test_idt();

    // trigger the overflow. each call pushes a return address, eventually
    // running off the end of the kernel stack into the guard region.
    stack_overflow();

    // reaching here means no fault occurred, which is a failure.
    serial_println!("[test did not overflow]");
    exit_qemu(QemuExitCode::Failed);
    jos::hlt_loop()
}

#[allow(unconditional_recursion)]
fn stack_overflow() {
    // recurse forever. the volatile read prevents the compiler from optimizing
    // the recursion into a loop (which would never touch the stack).
    stack_overflow();
    let _ = core::hint::black_box(0);
}

// a test-local idt whose double-fault handler exits qemu with Success, using
// the same IST index the gdt module reserves for double faults.
static mut TEST_IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();

fn init_test_idt() {
    // SAFETY: single-threaded test boot context; nothing else touches TEST_IDT,
    // and the gdt IST stack was installed by init_gdt() above.
    unsafe {
        let idt = &mut *core::ptr::addr_of_mut!(TEST_IDT);
        idt.double_fault
            .set_handler_fn(test_double_fault_handler)
            .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
        idt.load();
    }
}

extern "x86-interrupt" fn test_double_fault_handler(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    // the handler ran on its IST stack, so the overflow was caught: success.
    serial_println!("[ok]");
    exit_qemu(QemuExitCode::Success);
    jos::hlt_loop()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}
