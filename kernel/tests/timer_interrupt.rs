// tests/timer_interrupt.rs
//
// verifies the post 07 timer path end to end: after jos::init() remaps and
// enables the 8259 PIC, the PIT timer interrupt fires repeatedly, the handler
// runs, sends EOI, and the kernel does not deadlock while printing with
// interrupts live.
//
// if the PIC/idt setup were wrong the first timer IRQ would triple-fault and
// reset (this test would time out). if EOI were missing the tick count would
// stop at 1. if the print path were not interrupt-safe the kernel would
// deadlock. observing the tick count climb past a few ticks rules all of these
// out at once.
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
fn timer_ticks_advance() {
    // jos::init() loads the gdt/idt, remaps the PIC, and enables interrupts, so
    // the PIT starts firing immediately after this returns.
    jos::init();

    // wait for several ticks. hlt parks the core until the next interrupt, so
    // each wakeup is (at least) a timer tick. requiring >= 3 confirms EOI works
    // (the PIC keeps delivering), not just that a single IRQ arrived.
    let target = 3;
    for _ in 0..10_000 {
        if jos::interrupts::TICK_COUNT.load(Ordering::Relaxed) >= target {
            return; // success: the test runner reports [ok] and exits Success.
        }
        x86_64::instructions::hlt();
    }

    panic!("timer did not reach {target} ticks (PIC/timer not firing?)");
}
