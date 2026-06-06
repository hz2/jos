#![no_std]
#![cfg_attr(test, no_main)]
#![feature(custom_test_frameworks)]
// the x86-interrupt calling convention used by exception/interrupt handlers is
// still unstable, so it needs a feature gate.
#![cfg_attr(target_arch = "x86_64", feature(abi_x86_interrupt))]
// machine-check the safety discipline: every unsafe block needs a SAFETY:
// comment, and no SAFETY: comment may sit on safe code. enforced in CI via
// clippy -D warnings.
#![warn(clippy::undocumented_unsafe_blocks)]
#![warn(clippy::unnecessary_safety_comment)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]
#[cfg(target_arch = "aarch64")]
mod pl011;

extern crate alloc;

use core::panic::PanicInfo;

#[cfg(target_arch = "x86_64")]
pub mod allocator;
pub mod arch;
pub mod cap;
#[cfg(target_arch = "x86_64")]
pub mod clock;
#[cfg(target_arch = "x86_64")]
pub mod cpu_local;
#[cfg(target_arch = "x86_64")]
pub mod executor;
#[cfg(target_arch = "x86_64")]
pub mod gdt;
#[cfg(target_arch = "x86_64")]
pub mod interrupts;
#[cfg(target_arch = "x86_64")]
pub mod keyboard;
#[cfg(target_arch = "x86_64")]
pub mod memory;
pub mod serial;
#[cfg(target_arch = "x86_64")]
pub mod syscall;
pub mod trace;
#[cfg(target_arch = "x86_64")]
pub mod usermode;
pub mod vga_buffer;
#[cfg(target_arch = "x86_64")]
pub mod vspace;

/// Runs the architecture-specific early kernel initialization.
///
/// Initializes the serial port and loads the IDT so cpu exceptions are handled.
/// More init (GDT/TSS, PIC/APIC, paging) is added as the kernel grows.
pub fn init() {
    serial::init_serial();
    // gdt/tss before the idt: the idt's double-fault entry references the IST
    // stack the gdt installs.
    #[cfg(target_arch = "x86_64")]
    {
        gdt::init_gdt();
        interrupts::init_idt();
        // remap + init the PIC after the idt has timer/keyboard handlers, then
        // enable interrupts. order matters: an IRQ arriving before its idt
        // entry exists would fault.
        interrupts::init_pics();
        x86_64::instructions::interrupts::enable();
    }
}

// NOTE: the multiboot2 header + long-mode trampoline now live in
// arch::x86_64 (it includes boot.s via global_asm).

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
    #[cfg(target_arch = "x86_64")]
    {
        use x86_64::instructions::port::Port;
        // SAFETY: 0xf4 is the isa-debug-exit device's i/o port, configured on
        // the qemu command line. writing the exit code is its only effect; it
        // touches no memory and races with nothing.
        unsafe {
            let mut port = Port::new(0xf4);
            port.write(exit_code as u32);
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        // TODO: invoke psci to power off under aarch64.
    }
}

/// Halts the cpu in a low-power loop forever.
///
/// Used as the terminal state of diverging entry points and the panic handler:
/// `hlt` parks the core until the next interrupt instead of spinning hot.
pub fn hlt_loop() -> ! {
    loop {
        #[cfg(target_arch = "x86_64")]
        x86_64::instructions::hlt();
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
    hlt_loop()
}

// entry for the library's own `cargo test` binary. the trampoline calls
// kernel_main; for the test build we init the kernel (so the idt is loaded)
// then run the generated test harness.
#[cfg(test)]
#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, _info_ptr: u32) -> ! {
    init();
    test_main();
    hlt_loop()
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}
