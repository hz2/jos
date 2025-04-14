#![no_std]
#![no_main] // specifying that we are overwriting the os entry point with our own `_start` function

use core::panic::PanicInfo;

mod vga_buffer;

/// This function is called on panic.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // this is where the program starts executing
    vga_buffer::print_something();
    println!("hello world{}", "!");
    loop {}
}
