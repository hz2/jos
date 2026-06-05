// tests/cap_cnode.rs
//
// the CNode-as-a-retypeable-object payoff (Phase-2 follow-up), headless: a
// capability space (CNode) is carved from untyped memory like any other kernel
// object, capabilities are inserted and minted into it, a Tcb names it as its
// CSpace root, and the space is operated on THROUGH that Tcb handle. This is
// what turns Tcb.cspace_root from a placeholder into a real, operable object.
//
// uses the custom test framework (harness = true): each #[test_case] runs in
// the same boot, sequentially. no ring 3 needed; this exercises the kernel
// object plumbing directly.
#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::cell::UnsafeCell;
use core::panic::PanicInfo;

use jos::cap::{ObjectKind, UntypedRegion};
use jos_core::cap_rights::Rights;
use jos_core::untyped::CNODE_SIZE;

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

// a page-aligned static untyped region (CNodes need 4096-byte alignment). 32 KiB
// holds several CNodes + endpoints + a tcb. one shared region across the tests;
// each test carves fresh objects so the watermark only advances.
#[repr(align(4096))]
struct UntypedBacking {
    bytes: UnsafeCell<[u8; 32 * 1024]>,
}
// SAFETY: single-threaded ring-0 kernel; handed out exactly once below.
unsafe impl Sync for UntypedBacking {}
static UNTYPED: UntypedBacking = UntypedBacking {
    bytes: UnsafeCell::new([0u8; 32 * 1024]),
};

// the tests run sequentially in one boot; a single UntypedRegion is shared so
// the watermark is monotonic and no object is double-carved. built on first use.
static mut REGION: Option<UntypedRegion> = None;

fn region() -> &'static mut UntypedRegion {
    // SAFETY: tests run single-threaded and sequentially; REGION is initialized
    // on first call (before any concurrent access, of which there is none) and
    // the &mut handed out is not aliased across calls.
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(REGION);
        if slot.is_none() {
            // SAFETY: UNTYPED is handed out exactly once here; 4096-aligned.
            let bytes = &mut *UNTYPED.bytes.get();
            *slot = Some(UntypedRegion::new(bytes));
        }
        slot.as_mut().unwrap()
    }
}

#[test_case]
fn cnode_carves_from_untyped() {
    let before = region().used();
    let id = region().retype_cnode().expect("untyped should fit a CNode");
    assert_eq!(id.kind(), ObjectKind::CNode);
    // the watermark advanced by at least one CNode (4096 bytes), accounting for
    // any alignment padding.
    assert!(region().used() - before >= CNODE_SIZE);
}

#[test_case]
fn cnode_space_insert_mint_check() {
    // carve a CNode and an endpoint, then operate on the CNode's space.
    let cnode_id = region().retype_cnode().expect("CNode fits");
    let endpoint = region().retype_endpoint().expect("endpoint fits");

    // SAFETY: cnode_id was just carved as a CNode and is not aliased here.
    let space = unsafe { cnode_id.as_cnode_mut() };
    let full = space.insert(endpoint, Rights::all()).expect("insert full cap");
    // mint a read-only child and confirm rights are enforced in this space.
    let ro = space.mint(full, Rights::READ).expect("mint read-only");
    assert!(space.check(ro, Rights::READ));
    assert!(!space.check(ro, Rights::WRITE));
    // the full cap still resolves to the endpoint object.
    assert_eq!(space.lookup(full).unwrap().object.kind(), ObjectKind::Endpoint);
}

#[test_case]
fn tcb_cspace_root_names_a_real_cnode() {
    // the key proof: a Tcb's cspace_root names a CNode we can then operate on.
    let cnode_id = region().retype_cnode().expect("CNode fits");
    let endpoint = region().retype_endpoint().expect("endpoint fits");
    let tcb_id = region().retype_tcb().expect("Tcb fits");

    // assign the CNode as the Tcb's CSpace root, then read the root back out as
    // a Copy ObjectId and end the Tcb borrow before touching the CNode object.
    let root = {
        // SAFETY: tcb_id just carved as a Tcb, not aliased; this &mut is scoped
        // to this block and dropped before we derive the CNode reference below.
        let tcb = unsafe { tcb_id.as_tcb_mut() };
        tcb.cspace_root = Some(cnode_id);
        tcb.cspace_root.expect("cspace_root set")
    };
    assert_eq!(root.kind(), ObjectKind::CNode);

    // resolve the CSpace THROUGH the root handle and operate on it. `root` and
    // `tcb_id` name distinct objects, so this does not alias the (now-dropped)
    // Tcb borrow.
    // SAFETY: root names the CNode carved above; not aliased.
    let space = unsafe { root.as_cnode_mut() };
    let cap = space.insert(endpoint, Rights::all()).expect("insert via tcb cspace");
    assert!(space.check(cap, Rights::WRITE));
}

#[test_case]
fn revoke_in_cnode_makes_ref_stale() {
    // revocation works through the retypeable CNode object (negative direction:
    // a revoked cap must NOT resolve).
    let cnode_id = region().retype_cnode().expect("CNode fits");
    let endpoint = region().retype_endpoint().expect("endpoint fits");
    // SAFETY: freshly carved CNode, not aliased.
    let space = unsafe { cnode_id.as_cnode_mut() };
    let full = space.insert(endpoint, Rights::all()).unwrap();
    let child = space.mint(full, Rights::READ_WRITE).unwrap();
    let removed = space.revoke(full);
    assert_eq!(removed, 2); // full + child
    assert!(space.lookup(full).is_none());
    assert!(space.lookup(child).is_none());
}

#[test_case]
fn cnode_does_not_fit_when_region_exhausted() {
    // negative control: a fresh tiny region cannot hold a CNode.
    #[repr(align(4096))]
    struct Tiny {
        bytes: UnsafeCell<[u8; 256]>,
    }
    // SAFETY: single-threaded; handed out once within this test.
    unsafe impl Sync for Tiny {}
    static TINY: Tiny = Tiny {
        bytes: UnsafeCell::new([0u8; 256]),
    };
    // SAFETY: called once; 4096-aligned backing, but only 256 bytes long.
    let bytes = unsafe { &mut *TINY.bytes.get() };
    let mut tiny = UntypedRegion::new(bytes);
    // a CNode is 4096 bytes; a 256-byte region cannot hold one.
    assert!(tiny.retype_cnode().is_none());
}
