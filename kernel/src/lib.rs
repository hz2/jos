#![no_std]
#![cfg_attr(test, no_main)]
#![feature(custom_test_frameworks)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]
#[cfg(target_arch = "aarch64")]
mod pl011;

extern crate alloc;

use core::panic::PanicInfo;

pub mod serial;
pub mod vga_buffer;

// the multiboot2 header + 32->64 bit long-mode trampoline. it lives in the
// library so every binary that links jos (the kernel and each test binary)
// gets a valid boot entry. the linker script's ENTRY(_start32) pulls this
// object in and keeps the .multiboot_header section. the trampoline ends by
// calling kernel_main(magic, info_ptr), which each binary defines for itself.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("arch/x86_64/boot.s"), options(att_syntax));

// a global allocator is required now that alloc is pulled into the build (the
// async executor deps reference it). the heap starts empty; a real heap region
// is mapped during kernel init (blog_os post 10, see the roadmap). allocating
// before that region is installed faults loudly, which is intended pre-heap.
#[global_allocator]
static ALLOCATOR: linked_list_allocator::LockedHeap = linked_list_allocator::LockedHeap::empty();

pub trait Testable {
    fn run(&self) -> ();
}

impl<T> Testable for T
where
    T: Fn(),
{
    fn run(&self) {
        serial_print!("{}...\t", core::any::type_name::<T>());
        self();
        serial_println!("[ok]");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

pub fn exit_qemu(exit_code: QemuExitCode) {
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

pub fn test_runner(tests: &[&dyn Testable]) {
    serial_println!("Running {} tests", tests.len());
    for test in tests {
        test.run();
    }
    exit_qemu(QemuExitCode::Success);
}

pub fn test_panic_handler(info: &PanicInfo) -> ! {
    serial_println!("[failed]\n");
    serial_println!("Error: {}\n", info);
    exit_qemu(QemuExitCode::Failed);
    loop {}
}

// entry for the library's own `cargo test` binary. the trampoline calls
// kernel_main; for the test build we just run the generated test harness.
#[cfg(test)]
#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, _info_ptr: u32) -> ! {
    test_main();
    loop {}
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}
