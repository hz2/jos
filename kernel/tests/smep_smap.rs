// tests/smep_smap.rs
//
// jos::init turns on SMEP and SMAP when the cpu has them. the qemu runner uses
// `-cpu max`, which emulates both, so they must be live after init; the rest
// of the suite then runs with ring 0 barred from executing or touching user
// pages.
#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;
use x86_64::registers::control::{Cr4, Cr4Flags};

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, _info_ptr: u32) -> ! {
    jos::init();
    test_main();
    jos::hlt_loop()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}

#[test_case]
fn smep_and_smap_enabled() {
    let cr4 = Cr4::read();
    assert!(cr4.contains(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION));
    assert!(cr4.contains(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION));
}

#[test_case]
fn enable_is_idempotent() {
    // a second call reports the same support and leaves the bits set.
    assert_eq!(jos::arch::x86_64::enable_smep_smap(), (true, true));
    assert!(Cr4::read().contains(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION));
}

#[test_case]
fn nx_enabled() {
    // W^X user mappings set bit 63; without NXE that bit is reserved.
    use x86_64::registers::model_specific::{Efer, EferFlags};
    assert!(Efer::read().contains(EferFlags::NO_EXECUTE_ENABLE));
}
