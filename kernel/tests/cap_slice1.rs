// tests/cap_slice1.rs
//
// the first end-to-end demonstration that jos is a real capability system,
// headless. it exercises the whole chain: carve an endpoint out of untyped
// memory (no heap), put capabilities to it in a capability space, mint
// rights-attenuated derivations, prove rights are enforced (a send-only cap
// cannot receive and vice versa), pass a message, and revoke a capability so
// its ref goes stale.
//
// the verified pieces (rights attenuation, retype arithmetic, the cap space,
// the placement write) are already proven in jos-core under Kani/Miri; this
// test wires them to real memory and confirms the kernel glue behaves.
#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::cell::UnsafeCell;
use core::panic::PanicInfo;

use jos::cap::{cap_recv, cap_send, KernelCapSpace, Message, ObjectKind, UntypedRegion};
use jos_core::cap_rights::Rights;

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

// a statically-allocated untyped region. 64-byte aligned so placed objects meet
// their alignment; backed by a real static so all derived pointers have valid
// provenance. UnsafeCell + a Sync wrapper let us hand out one &'static mut to it.
#[repr(align(64))]
struct UntypedBacking {
    bytes: UnsafeCell<[u8; 4096]>,
}
// SAFETY: the kernel is single-threaded ring 0; the static is handed out exactly
// once below, so there is no concurrent access.
unsafe impl Sync for UntypedBacking {}

static UNTYPED: UntypedBacking = UntypedBacking {
    bytes: UnsafeCell::new([0u8; 4096]),
};

// builds an UntypedRegion over the static backing. must be called at most once.
fn take_untyped() -> UntypedRegion {
    // SAFETY: called exactly once per test binary, before any other reference to
    // UNTYPED exists, so the &'static mut is unique. the array is 64-byte aligned
    // via repr(align(64)).
    let bytes = unsafe { &mut *UNTYPED.bytes.get() };
    UntypedRegion::new(bytes)
}

#[test_case]
fn capability_endpoint_lifecycle() {
    let mut untyped = take_untyped();
    let mut space: KernelCapSpace = KernelCapSpace::new();

    // retype: carve an endpoint out of untyped memory (no heap).
    let endpoint = untyped.retype_endpoint().expect("untyped should fit an endpoint");
    assert_eq!(endpoint.kind(), ObjectKind::Endpoint);
    assert!(untyped.used() >= 64);

    // install a full-rights capability to the endpoint, then mint attenuated
    // send-only and recv-only derivations of it.
    let full = space.insert(endpoint, Rights::all()).unwrap();
    let send_cap = space.mint(full, Rights::WRITE).unwrap();
    let recv_cap = space.mint(full, Rights::READ).unwrap();

    // rights are enforced: a send-only cap cannot receive, a recv-only cap
    // cannot send. this is the confused-deputy defense in action.
    assert!(cap_recv(&space, send_cap).is_err());
    assert!(cap_send(&space, recv_cap, Message { label: 1, words: [0; 4] }).is_err());

    // the message round-trips through the capability chain.
    let msg = Message {
        label: 0xCAFE,
        words: [1, 2, 3, 4],
    };
    cap_send(&space, send_cap, msg).expect("send with WRITE right should succeed");
    let got = cap_recv(&space, recv_cap).expect("recv with READ right should succeed");
    assert_eq!(got, msg);

    // receiving again with nothing pending is empty, not a fresh message.
    assert!(cap_recv(&space, recv_cap).is_err());
}

#[test_case]
fn revoke_makes_capability_stale() {
    let mut untyped = take_untyped_second();
    let mut space: KernelCapSpace = KernelCapSpace::new();

    let endpoint = untyped.retype_endpoint().unwrap();
    let full = space.insert(endpoint, Rights::all()).unwrap();
    let child = space.mint(full, Rights::READ_WRITE).unwrap();

    // revoking the root removes it and the derived child; both refs go stale.
    let removed = space.revoke(full);
    assert_eq!(removed, 2);
    assert!(space.lookup(full).is_none());
    assert!(space.lookup(child).is_none());
    // a stale capability cannot be used for IPC.
    assert!(cap_send(&space, child, Message { label: 0, words: [0; 4] }).is_err());
}

// a second static region so the two tests do not share watermark state (each
// #[test_case] runs in the same binary/boot sequentially).
#[repr(align(64))]
struct UntypedBacking2 {
    bytes: UnsafeCell<[u8; 4096]>,
}
// SAFETY: as UntypedBacking; single-threaded, handed out once.
unsafe impl Sync for UntypedBacking2 {}
static UNTYPED2: UntypedBacking2 = UntypedBacking2 {
    bytes: UnsafeCell::new([0u8; 4096]),
};
fn take_untyped_second() -> UntypedRegion {
    // SAFETY: called exactly once; unique &'static mut, 64-byte aligned.
    let bytes = unsafe { &mut *UNTYPED2.bytes.get() };
    UntypedRegion::new(bytes)
}
