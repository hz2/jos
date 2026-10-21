// tests/cnode_collect.rs
//
// a CNode nothing can reach any more is released: its capabilities are
// dropped, what was derived from them elsewhere is relinked past them, and its
// registry entry goes to the next CNode under a new id. two CNodes that are
// each other's only name reach nothing, so they go too, where a count of
// capabilities would keep them forever. a chain of CNodes that fills the
// registry makes the next retype fail without carving anything, until the
// chain is cut and collected.
#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::panic::PanicInfo;

use jos::cap::{self, KernelCapSpace, MAX_CSPACES, ObjectId, UntypedRegion};
use jos_core::cap_rights::Rights;
use jos_core::cap_space::{CapLink, SpaceId};

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

/// Room for a registry's worth of CNodes and then some.
const UNTYPED_SIZE: usize = (MAX_CSPACES + 16) * 4096;

/// A page-aligned static untyped region the tests carve from.
#[repr(align(4096))]
struct UntypedBacking {
    bytes: UnsafeCell<[u8; UNTYPED_SIZE]>,
}
// SAFETY: single-threaded ring-0 kernel; handed out exactly once below.
unsafe impl Sync for UntypedBacking {}
static UNTYPED: UntypedBacking = UntypedBacking { bytes: UnsafeCell::new([0; UNTYPED_SIZE]) };

static mut REGION: Option<UntypedRegion> = None;
/// The kernel's own registered space the tests hold capabilities in, like a
/// root task's, built in place.
static mut ROOT: MaybeUninit<KernelCapSpace> = MaybeUninit::uninit();
static mut ROOT_READY: bool = false;

fn region() -> &'static mut UntypedRegion {
    // SAFETY: tests run single-threaded and sequentially; REGION is built on
    // first use and the &mut handed out is not held across calls.
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(REGION);
        if slot.is_none() {
            // SAFETY: UNTYPED is handed out exactly once here; 4096-aligned.
            *slot = Some(UntypedRegion::new(&mut *UNTYPED.bytes.get()));
        }
        slot.as_mut().unwrap()
    }
}

fn root() -> &'static mut KernelCapSpace {
    // SAFETY: as region(); the space is built in place and registered while
    // empty, once, before anything holds a reference to it.
    unsafe {
        let space = (*core::ptr::addr_of_mut!(ROOT)).as_mut_ptr();
        if !ROOT_READY {
            KernelCapSpace::init_in_place(space);
            cap::register_cspace(space).expect("register the root space");
            ROOT_READY = true;
        }
        &mut *space
    }
}

/// The capability space inside the CNode `cnode`.
fn space(cnode: ObjectId) -> &'static mut KernelCapSpace {
    // SAFETY: cnode was carved as a CNode by retype_cnode; the tests hold no
    // other reference to it across this call.
    unsafe { cnode.as_cnode_mut() }
}

/// Releases whatever earlier tests left unreachable, so each starts clean.
fn collect() {
    // SAFETY: single-threaded test kernel, no reference into a space is held.
    unsafe { cap::collect_cnodes() };
}

#[test_case]
fn cnodes_naming_only_each_other_are_collected() {
    collect();
    let a = region().retype_cnode().expect("carve a");
    let b = region().retype_cnode().expect("carve b");
    let to_a = root().insert(a, Rights::all()).expect("root's cap to a");
    space(a).insert(b, Rights::all()).expect("a's cap to b");
    space(b).insert(a, Rights::all()).expect("b's cap to a");
    assert_ne!(space(a).id(), SpaceId(0), "a cnode was not registered");
    // the root's capability goes; a and b now name only each other.
    cap::revoke_and_wake(root(), to_a);
    assert_eq!(space(a).id(), SpaceId(0), "a cnode nothing reaches was kept");
    assert_eq!(space(b).id(), SpaceId(0), "a cnode nothing reaches was kept");
    assert!(space(a).is_empty() && space(b).is_empty(), "a released cnode kept capabilities");
}

#[test_case]
fn what_came_through_a_collected_cnode_stays_revocable() {
    collect();
    let c = region().retype_cnode().expect("carve c");
    let ep = region().retype_endpoint().expect("carve an endpoint");
    let to_c = root().insert(c, Rights::all()).expect("root's cap to c");
    let original = root().insert(ep, Rights::all()).expect("root's endpoint cap");
    // the root's endpoint goes into c, and from c back to the root.
    let in_c = root().copy_into(original, space(c), 0, Rights::all()).expect("copy into c");
    let back = space(c).copy_into(in_c, root(), 40, Rights::READ).expect("copy back");
    cap::revoke_and_wake(root(), to_c);
    let relinked = root().lookup(back).expect("a copy outside the cnode went with it");
    let root_id = root().id();
    assert_eq!(relinked.parent, Some(CapLink { space: root_id, cap: original }), "not relinked to what is left");
    assert_eq!(cap::revoke_and_wake(root(), original), 2, "revoking the ancestor missed the relinked copy");
    assert!(root().lookup(back).is_none());
}

#[test_case]
fn a_freed_entry_goes_to_the_next_cnode_under_a_new_id() {
    collect();
    let first = region().retype_cnode().expect("carve");
    let first_id = space(first).id();
    let to_first = root().insert(first, Rights::all()).expect("cap");
    cap::revoke_and_wake(root(), to_first);
    let second = region().retype_cnode().expect("carve again");
    let second_id = space(second).id();
    assert_eq!(second_id.entry(), first_id.entry(), "the freed entry was not reused");
    assert_ne!(second_id, first_id, "a reused entry gave its old id again");
    let to_second = root().insert(second, Rights::all()).expect("cap");
    cap::revoke_and_wake(root(), to_second);
}

#[test_case]
fn a_full_registry_refuses_a_cnode_until_the_chain_holding_it_is_cut() {
    collect();
    // a chain from the root: each cnode holds the only capability to the next.
    let head = region().retype_cnode().expect("carve the head");
    let to_head = root().insert(head, Rights::all()).expect("root's cap to the head");
    let mut tail = head;
    let mut length = 1;
    while let Some(next) = region().retype_cnode() {
        space(tail).insert(next, Rights::all()).expect("link the chain");
        tail = next;
        length += 1;
    }
    assert!(length < MAX_CSPACES, "the registry never filled");
    assert!(!cap::registry_has_room());
    let used = region().used();
    assert!(region().retype_cnode().is_none());
    assert_eq!(region().used(), used, "a refused cnode still spent untyped memory");
    // the chain is cut at its head, and every link of it goes.
    cap::revoke_and_wake(root(), to_head);
    assert!(cap::registry_has_room(), "the cut chain was not collected");
    assert_eq!(space(tail).id(), SpaceId(0), "the end of the chain was kept");
    assert!(region().retype_cnode().is_some(), "a cnode was refused after the collection");
}
