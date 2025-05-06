#![no_std]
#![no_main] // specifying that we are overwriting the os entry point with our own `_start` function
#![feature(custom_test_frameworks)] // enabling custom test frameworks which have no external libs
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"] // result of issue: https://github.com/rust-lang/cargo/issues/7359

use core::panic::PanicInfo;
use jos::println;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("Hello World{}", "!");

    #[cfg(test)]
    test_main();

    loop {}
}

/// This function is called on panic.
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}

#[test_case]
fn trivial_assertion() {
    assert_eq!(1, 1);
}
