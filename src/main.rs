#![no_std]
#![no_main] // specifying that we are overwriting the os entry point with our own `_start` function

use core::panic::PanicInfo;

mod vga_buffer;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // this is where the program starts executing
    vga_buffer::print_something();
    loop {}
}
