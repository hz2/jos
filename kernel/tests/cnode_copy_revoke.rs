//! Revoking a capability reaches its copies in other capability spaces.
//!
//! Two CNodes are retyped from untyped memory (each registered on creation). An
//! endpoint capability in the first is copied into the second, and the copy is
//! minted again there. Revoking the original must remove both, while an
//! unrelated capability in the second space survives.
#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;

use jos::cap::{UntypedRegion, revoke_and_wake};
use jos_core::cap_rights::Rights;

/// Page-aligned backing for two CNodes and two endpoints.
#[repr(align(4096))]
struct Backing([u8; 4 * 4096]);
static mut BACKING: Backing = Backing([0; 4 * 4096]);

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
fn revoke_reaches_copies_in_other_spaces() {
    // SAFETY: the backing is a page-aligned static handed out once; the test is
    // single-threaded, and each CNode reference below is the only one into it.
    let (a, b, endpoint, other) = unsafe {
        let mut untyped = UntypedRegion::new(&mut (*core::ptr::addr_of_mut!(BACKING)).0);
        let a = untyped.retype_cnode().expect("cnode a").as_cnode_mut();
        let b = untyped.retype_cnode().expect("cnode b").as_cnode_mut();
        let endpoint = untyped.retype_endpoint().expect("endpoint");
        let other = untyped.retype_endpoint().expect("other endpoint");
        (a, b, endpoint, other)
    };
    assert_ne!(a.id(), b.id(), "registered spaces get distinct ids");

    let root = a.insert(endpoint, Rights::all()).expect("root cap");
    let copy = a.copy_into(root, b, 0, Rights::READ_WRITE).expect("copy into b");
    let grandchild = b.mint(copy, Rights::READ).expect("mint in b");
    let unrelated = b.insert(other, Rights::all()).expect("unrelated cap");

    assert_eq!(revoke_and_wake(a, root), 3);
    assert!(a.lookup(root).is_none());
    assert!(b.lookup(copy).is_none(), "the copy in the other space is gone");
    assert!(b.lookup(grandchild).is_none(), "and so is what was minted from it");
    assert!(b.lookup(unrelated).is_some(), "unrelated capabilities survive");
}
