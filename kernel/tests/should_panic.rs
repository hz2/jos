// tests/should_panic.rs
#![no_std]
#![no_main]

use jos::{QemuExitCode, exit_qemu, serial_print, serial_println};
use core::panic::PanicInfo;

// the trampoline in the jos library calls kernel_main; this test expects the
// inner assertion to panic, which the panic handler turns into a success exit.
#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, _info_ptr: u32) -> ! {
    should_fail();
    serial_println!("[test did not panic]");
    exit_qemu(QemuExitCode::Failed);
    jos::hlt_loop()
}

fn should_fail() {
    serial_print!("should_panic::should_fail...\t");
    assert_eq!(0, 1);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    serial_println!("[ok]");
    exit_qemu(QemuExitCode::Success);
    jos::hlt_loop()
}
