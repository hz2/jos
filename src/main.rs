#![no_std]
#![no_main] // specifying that we are overwriting the os entry point with our own `_start` function
#![feature(custom_test_frameworks)] // enabling custom test frameworks which have no external libs
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"] // result of issue: https://github.com/rust-lang/cargo/issues/7359

use core::panic::PanicInfo;

mod vga_buffer;
mod serial;
#[cfg(target_arch = "aarch64")]
mod pl011;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

pub fn exit_qemu(exit_code : QemuExitCode) {
    use x86_64::instructions::port::Port;

    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut port = Port::new(0xf4);
        port.write(exit_code as u32);
    }

    #[cfg(target_arch = "aarch64")]
    {
        // TODO: invoke PSCI
    }
}


/// This function is called on panic.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info);
}

#[cfg(test)]
pub fn test_runner(tests: &[&dyn Fn()]) {
    println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }

    exit_qemu(QemuExitCode::Success);
}

#[test_case]
fn trivial_assertion() {
    print!("trivial assertion... ");
    assert_eq!(1, 1);
    println!("[ok]");
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // this is where the program starts executing
    // vga_buffer::print_something();
    println!("hello world{}", "!");

    #[cfg(test)]
    test_main(); // run tests if we are in test mode

    loop {}
}
