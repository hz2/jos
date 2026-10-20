#![no_std]
#![no_main] // we provide our own entry (_start32) via the multiboot trampoline
#![feature(custom_test_frameworks)]
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use alloc::vec::Vec;
use core::panic::PanicInfo;
// only the non-test kernel_main enters the executor; the test build runs the
// harness and exits instead, so these would be unused there.
#[cfg(not(test))]
use jos::executor::{Executor, Task};
use jos::arch::x86_64::multiboot2;
use jos::{println, serial_println};

/// The multiboot2 header + long-mode trampoline live in the jos library so all
/// binaries share one boot entry. It calls kernel_main below in 64-bit mode,
/// with the loader's magic (0x36d76289 for multiboot2) and the physical
/// address of the multiboot2 info structure.
#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(magic: u32, info_ptr: u32) -> ! {
    // 0xb8000 vga text mode is live at entry, so println! works immediately.
    println!("jos {}", env!("CARGO_PKG_VERSION"));

    // load gdt/idt, init the pic, enable interrupts.
    jos::init();
    serial_println!("jos: booting");
    assert!(
        magic == multiboot2::BOOTLOADER_MAGIC,
        "not started by a multiboot2 loader (magic {magic:#x})"
    );
    jos::syscall::init_syscall();

    // SAFETY: grub passed info_ptr, and low memory is identity mapped.
    let (info, info_range) = unsafe { multiboot2::boot_information(info_ptr) }
        .expect("malformed multiboot2 info structure");
    let plan = jos::memory::plan_memory(info, info_range);

    // set up paging + the heap so alloc works.
    // SAFETY: boot.s identity-maps the first 1 GiB, and we call these once.
    let mut mapper = unsafe { jos::memory::init_mapper() };
    let mut frames = jos::memory::BootstrapFrameAllocator::from_regions(plan.free.as_slice());
    jos::allocator::init_heap(&mut mapper, &mut frames).expect("heap init failed");

    // prove the heap works.
    let v: Vec<u32> = (0..16).collect();
    println!("heap ok: sum(0..16) = {}", v.iter().sum::<u32>());

    // in the test build, run the harness and exit via the test runner rather
    // than entering the root task or the never-returning executor loop below.
    #[cfg(test)]
    {
        test_main();
        jos::hlt_loop()
    }

    // hand the machine to the root task: from here the kernel only enforces.
    #[cfg(not(test))]
    if let Some(root) = jos::rootserver::find_root(info) {
        serial_println!("jos: starting the root task ({} bytes)", root.image.len());
        // SAFETY: called once at boot after init_syscall; the frames the boot
        // allocator has not handed out are free, and nothing allocates them
        // from here on.
        unsafe { jos::rootserver::start(&root, info, frames.remaining(), plan.ignored) }
    }

    // no root task: bring up the async executor as the kernel's scheduler and
    // hand it the keyboard decoder task, so the machine is still interactive.
    #[cfg(not(test))]
    {
        serial_println!("jos: no root module; running the kernel console");
        jos::keyboard::init();
        let mut executor = Executor::new();
        executor
            .spawn(Task::new(jos::keyboard::print_keypresses()))
            .expect("spawn print_keypresses");
        executor.run()
    }
}

/// Panic handler for normal (non-test) builds: serial first, since a headless
/// run never shows the VGA screen.
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("kernel panic: {}", info);
    println!("{info}");
    jos::hlt_loop()
}

/// Panic handler for test builds routes through the serial test reporter.
#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}
