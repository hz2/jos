//! Revoking a Frame capability unregisters it as an IPC buffer.
//!
//! A thread must not keep a buffer it no longer has the capability for, so
//! `revoke_and_wake` on a Frame clears it from every thread that registered it,
//! and leaves threads using a different frame alone.
#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;

use jos::cap::{KernelCapSpace, Tcb, UntypedRegion, revoke_and_wake};
use jos::sched;
use jos_core::cap_rights::Rights;

/// Page-aligned backing so the region can hold frames.
#[repr(align(4096))]
struct Backing([u8; 4 * 4096]);
static mut BACKING: Backing = Backing([0; 4 * 4096]);
static mut THREAD_A: Tcb = Tcb::new();
static mut THREAD_B: Tcb = Tcb::new();

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, _info_ptr: u32) -> ! {
    test_main();
    jos::hlt_loop()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}

#[test_case]
fn revoking_a_frame_unregisters_only_its_buffer() {
    // SAFETY: the backing is a page-aligned static handed out once, and the TCB
    // statics are touched only by this single-threaded test with interrupts off.
    unsafe {
        let mut untyped = UntypedRegion::new(&mut (*core::ptr::addr_of_mut!(BACKING)).0);
        let frame_a = untyped.retype_frame().expect("frame a");
        let frame_b = untyped.retype_frame().expect("frame b");

        let mut space = KernelCapSpace::new();
        let cap_a = space.insert(frame_a, Rights::READ_WRITE).expect("cap a");
        space.insert(frame_b, Rights::READ_WRITE).expect("cap b");

        let a = core::ptr::addr_of_mut!(THREAD_A);
        let b = core::ptr::addr_of_mut!(THREAD_B);
        (*a).ipc_buffer = frame_a.phys_addr();
        (*b).ipc_buffer = frame_b.phys_addr();
        x86_64::instructions::interrupts::without_interrupts(|| {
            sched::register_thread(a);
            sched::register_thread(b);
        });

        revoke_and_wake(&mut space, cap_a);

        assert_eq!((*a).ipc_buffer, 0, "revoked frame must be unregistered");
        assert_eq!((*b).ipc_buffer, frame_b.phys_addr(), "other frames are untouched");
    }
}
