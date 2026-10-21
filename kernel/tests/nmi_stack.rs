// tests/nmi_stack.rs
//
// the non-maskable interrupt runs on its own IST stack. an NMI can arrive in
// the few instructions where the syscall exit path has already loaded the
// user's stack pointer, so without a stack switch of its own the cpu would
// push the interrupt frame onto the user's stack. `int 2` goes through the
// same gate (and so the same IST entry) as a real NMI: the handler must run,
// once per interrupt, with its stack pointer inside the NMI stack, and return.
// without the IST entry it runs on the boot stack and the range check fails.
#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;
use core::sync::atomic::Ordering;

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, _info_ptr: u32) -> ! {
    test_main();
    jos::hlt_loop()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}

#[test_case]
fn nmis_run_on_their_own_stack() {
    jos::init();
    for _ in 0..2 {
        // SAFETY: vector 2 has a handler that returns, and it touches nothing
        // this code relies on.
        unsafe { core::arch::asm!("int 2") };
    }
    assert_eq!(jos::interrupts::NMI_COUNT.load(Ordering::Relaxed), 2, "the NMI handler did not run twice");
    let rsp = jos::interrupts::NMI_LAST_RSP.load(Ordering::Relaxed);
    let (bottom, top) = jos::gdt::nmi_stack_range();
    assert!((bottom..top).contains(&rsp), "the NMI handler ran on {rsp:#x}, outside its stack {bottom:#x}..{top:#x}");
}
