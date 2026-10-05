//! Revoking a page table capability unmaps it and everything beneath it.
//!
//! Maps three tables and a frame, then revokes the middle table's capability.
//! The frame must stop translating, its registry record must be freed, and the
//! surviving last-level table must come back clean: re-attached under a fresh
//! middle table, it must not resurrect the old frame mapping.
#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;

use jos::cap::{KernelCapSpace, UntypedRegion, revoke_and_wake};
use jos::mapping::{MapError, map_flags, map_frame, map_table, translate};
use jos::vspace::VSpace;
use jos_core::cap_rights::Rights;

/// Page-aligned backing for the root, the tables, and the frame.
#[repr(align(4096))]
struct Backing([u8; 16 * 4096]);
static mut BACKING: Backing = Backing([0; 16 * 4096]);

/// A user-half address under root entry 65.
const VADDR: u64 = 0x2080_0000_0000;

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
fn revoking_a_table_unmaps_everything_beneath_it() {
    // SAFETY: the backing is a page-aligned static handed out once; CR3 holds
    // the boot root that VSpace::new copies from; single-threaded test.
    let mut untyped = unsafe { UntypedRegion::new(&mut (*core::ptr::addr_of_mut!(BACKING)).0) };
    // SAFETY: as above.
    let vspace = unsafe { VSpace::new(&mut untyped).expect("vspace") };
    let root = vspace.root();
    let pdpt = untyped.retype_page_table().expect("pdpt");
    let pd = untyped.retype_page_table().expect("pd");
    let pt = untyped.retype_page_table().expect("pt");
    let frame = untyped.retype_frame().expect("frame");

    map_table(root, pdpt, VADDR).expect("map pdpt");
    map_table(root, pd, VADDR).expect("map pd");
    map_table(root, pt, VADDR).expect("map pt");
    map_frame(root, frame, VADDR | map_flags::WRITE).expect("map frame");
    assert_eq!(translate(root, VADDR), Some(frame.phys_addr()));

    let mut space = KernelCapSpace::new();
    let pd_cap = space.insert(pd, Rights::all()).expect("pd cap");
    revoke_and_wake(&mut space, pd_cap);

    // the frame is gone, and its record is free: mapping it again now fails
    // for the missing path, not because it is still recorded as mapped.
    assert_eq!(translate(root, VADDR), None);
    assert_eq!(map_frame(root, frame, VADDR), Err(MapError::MissingTable));

    // a fresh middle table, then the surviving last-level table: the old frame
    // entry must have been cleared from it, not carried back in.
    let new_pd = untyped.retype_page_table().expect("new pd");
    map_table(root, new_pd, VADDR).expect("map new pd");
    map_table(root, pt, VADDR).expect("re-map pt");
    assert_eq!(translate(root, VADDR), None, "a re-attached table must come back clean");

    map_frame(root, frame, VADDR).expect("map frame again");
    assert_eq!(translate(root, VADDR), Some(frame.phys_addr()));
}
