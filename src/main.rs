#![no_std]
#![no_main] // specifying that we are overwriting the os entry point with our own `_start` function
#![feature(custom_test_frameworks)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;

mod vga_buffer;

/// This function is called on panic.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}

#[cfg(test)]
pub fn test_runner(tests: &[&dyn Fn()]) {
    // &[&dyn Fn()] is a slice of trait object references of the Fn trait
    println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // this is where the program starts executing
    vga_buffer::print_something();
    println!("hello world{}", "!");
    loop {}
}
