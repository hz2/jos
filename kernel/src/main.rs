#![no_std]
#![no_main] // we provide our own entry (_start32) via the multiboot trampoline
#![feature(custom_test_frameworks)]
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use alloc::vec::Vec;
use core::panic::PanicInfo;
use jos::println;

// the multiboot2 header + long-mode trampoline live in the jos library so all
// binaries share one boot entry. it calls kernel_main below in 64-bit mode.
// magic should be 0x36d76289 (the multiboot2 loader magic); info_ptr points at
// the multiboot2 info struct.
#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    // 0xb8000 vga text mode is live at entry, so println! works immediately.
    println!("Hello World{}", "!");

    // load gdt/idt, init the pic, enable interrupts.
    jos::init();

    // set up paging + the heap so alloc works.
    // SAFETY: boot.s identity-maps the first 1 GiB, and we call these once.
    let mut mapper = unsafe { jos::memory::init_mapper() };
    let mut frame_allocator = unsafe { jos::memory::BootstrapFrameAllocator::new(info_ptr) };
    jos::allocator::init_heap(&mut mapper, &mut frame_allocator).expect("heap init failed");

    // prove the heap works.
    let v: Vec<u32> = (0..16).collect();
    println!("heap ok: sum(0..16) = {}", v.iter().sum::<u32>());

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
