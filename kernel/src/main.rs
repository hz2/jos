#![no_std]
#![no_main] // we provide our own entry (_start32) via the multiboot trampoline
#![feature(custom_test_frameworks)]
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;
use jos::println;

// the multiboot2 header + long-mode trampoline live in the jos library so all
// binaries share one boot entry. it calls kernel_main below in 64-bit mode.
// magic should be 0x36d76289 (the multiboot2 loader magic); info_ptr points at
// the multiboot2 info struct.
#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, _info_ptr: u32) -> ! {
    // 0xb8000 vga text mode is live at entry, so println! works immediately.
    println!("Hello World{}", "!");

    // load the idt so cpu exceptions are handled instead of triple-faulting.
    jos::init();

    #[cfg(test)]
    test_main();

    jos::hlt_loop()
}

// panic handler for normal (non-test) builds.
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{info}");
    jos::hlt_loop()
}

// panic handler for test builds routes through the serial test reporter.
#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}
