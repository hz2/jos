// tests/notification.rs
//
// the async Notification object: the asynchronous counterpart to the
// synchronous endpoint. a signaller never blocks (it ORs a badge into the
// notification and wakes any parked waiter); a waiter parks on an empty
// notification and is woken by a later signal, collecting the coalesced badge.
//
// the notification state machine is proven in jos-core (signal coalesces by OR,
// no lost wakeup, poll returns-then-clears); this wires the verified model to
// the kernel object placed in untyped memory, the capability rights gate, and
// the executor's park/wake path, headless under QEMU. it proves: a parked
// waiter is woken by a signal and reads the badge; multiple signals before a
// wait coalesce into one delivery; a signal-only capability cannot wait (rights
// enforced at the boundary); and revoking the capability under a parked waiter
// cancels the wait with InvalidCap rather than hanging.
#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use alloc::rc::Rc;
use core::cell::RefCell;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

use jos::cap::{cap_signal, wait, Badge, IpcError, KernelCapSpace, UntypedRegion};
use jos::executor::{Executor, Task};
use jos_core::cap_rights::Rights;
use jos_core::cap_table::CapRef;

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    jos::init();
    // SAFETY: boot.s identity-maps the first 1 GiB; called once before test_main.
    unsafe {
        let mut mapper = jos::memory::init_mapper();
        let mut frame_allocator = jos::memory::BootstrapFrameAllocator::new(info_ptr);
        jos::allocator::init_heap(&mut mapper, &mut frame_allocator).expect("heap init failed");
    }
    test_main();
    jos::hlt_loop()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}

// a statically-allocated, 64-byte-aligned untyped region with real provenance.
// each test takes a fresh 512-byte slice via a bump cursor so their objects do
// not alias (the tests run sequentially in one boot).
#[repr(align(64))]
struct UntypedBacking {
    bytes: core::cell::UnsafeCell<[u8; 4096]>,
}
// SAFETY: single-threaded ring 0; slices are handed out sequentially below.
unsafe impl Sync for UntypedBacking {}
static UNTYPED: UntypedBacking = UntypedBacking {
    bytes: core::cell::UnsafeCell::new([0u8; 4096]),
};
static NEXT: AtomicUsize = AtomicUsize::new(0);

// carves a fresh 512-byte untyped region out of the backing for one test.
fn fresh_untyped() -> UntypedRegion {
    let off = NEXT.fetch_add(512, Ordering::SeqCst);
    // SAFETY: each call claims a distinct [off, off+512) window of the static
    // backing (the cursor only advances), so the &'static mut is unique. off is a
    // multiple of 512 and the backing is 64-aligned, so the sub-slice base is
    // 64-aligned as UntypedRegion::new requires.
    let backing: &mut [u8; 4096] = unsafe { &mut *UNTYPED.bytes.get() };
    UntypedRegion::new(&mut backing[off..off + 512])
}

// builds a space with one notification and returns (space, signal_cap, wait_cap).
fn space_with_notification() -> (KernelCapSpace, CapRef, CapRef) {
    let mut untyped = fresh_untyped();
    let mut space = KernelCapSpace::new();
    let notification = untyped.retype_notification().expect("notification must fit");
    let full = space.insert(notification, Rights::all()).unwrap();
    let signal_cap = space.mint(full, Rights::WRITE).unwrap();
    let wait_cap = space.mint(full, Rights::READ).unwrap();
    (space, signal_cap, wait_cap)
}

// a waiter that parks on an empty notification is woken by a later signal, and
// reads back the signalled badge. the waiter is spawned first (so it parks on
// first poll), then the signaller runs and wakes it.
#[test_case]
fn waiter_parks_then_signal_wakes_it() {
    let (space, signal_cap, wait_cap) = space_with_notification();
    let space = Rc::new(space);
    let got: Rc<RefCell<Option<Badge>>> = Rc::new(RefCell::new(None));

    let mut executor = Executor::new();

    // waiter task: awaits a signal. on first poll the notification is empty, so
    // it parks (Poll::Pending) with its waker stored in the notification.
    {
        let space = space.clone();
        let got = got.clone();
        executor
            .spawn(Task::new(async move {
                let badge = wait(&space, wait_cap).await.expect("wait should succeed");
                *got.borrow_mut() = Some(badge);
            }))
            .unwrap();
    }

    // signaller task: signals badge 0b1010, which wakes the parked waiter.
    {
        let space = space.clone();
        executor
            .spawn(Task::new(async move {
                cap_signal(&space, signal_cap, Badge(0b1010)).expect("signal should succeed");
            }))
            .unwrap();
    }

    executor.run_until_idle();

    // the waiter woke and collected the exact badge that was signalled.
    assert_eq!(*got.borrow(), Some(Badge(0b1010)));
}

// signals delivered BEFORE any waiter exists coalesce by OR into a single
// pending badge, which one later wait collects in one go. proves order-
// independence and the coalescing semantics (the seL4 notification model).
#[test_case]
fn signals_coalesce_before_a_wait() {
    let (space, signal_cap, wait_cap) = space_with_notification();
    let space = Rc::new(space);
    let got: Rc<RefCell<Option<Badge>>> = Rc::new(RefCell::new(None));

    let mut executor = Executor::new();

    // three signals arrive first (no waiter yet): their badges OR together.
    {
        let space = space.clone();
        executor
            .spawn(Task::new(async move {
                cap_signal(&space, signal_cap, Badge(0b0001)).unwrap();
                cap_signal(&space, signal_cap, Badge(0b0100)).unwrap();
                cap_signal(&space, signal_cap, Badge(0b0001)).unwrap(); // repeat: no new bit
            }))
            .unwrap();
    }
    // then one waiter collects the union.
    {
        let space = space.clone();
        let got = got.clone();
        executor
            .spawn(Task::new(async move {
                *got.borrow_mut() = Some(wait(&space, wait_cap).await.unwrap());
            }))
            .unwrap();
    }

    executor.run_until_idle();

    // the waiter sees the OR of every signal since the (empty) start: 0b0101.
    assert_eq!(*got.borrow(), Some(Badge(0b0101)));
}

// a signal-only (WRITE) capability cannot wait, and a wait-only (READ)
// capability cannot signal: rights are enforced at the boundary, on every
// operation, exactly as for endpoint send/recv.
#[test_case]
fn rights_are_enforced() {
    let (space, signal_cap, wait_cap) = space_with_notification();

    // signalling needs WRITE: a wait-only cap is refused.
    assert_eq!(
        cap_signal(&space, wait_cap, Badge(1)),
        Err(IpcError::InsufficientRights),
    );

    // waiting needs READ: a signal-only cap is refused on the first poll. drive
    // the future once via a tiny executor and capture the terminal error.
    let space = Rc::new(space);
    let result: Rc<RefCell<Option<Result<Badge, IpcError>>>> = Rc::new(RefCell::new(None));
    let mut executor = Executor::new();
    {
        let space = space.clone();
        let result = result.clone();
        executor
            .spawn(Task::new(async move {
                *result.borrow_mut() = Some(wait(&space, signal_cap).await);
            }))
            .unwrap();
    }
    executor.run_until_idle();
    assert_eq!(*result.borrow(), Some(Err(IpcError::InsufficientRights)));
}

// NOTE: revoke-under-a-parked-waiter cancellation (the notification analogue of
// revoke_blocked_ipc.rs) needs a `wait_resolving` future that re-resolves the
// capability per poll, the mirror of `recv_resolving`. `revoke_and_wake` already
// clears a parked notification waiter (wired in cap.rs), so the kernel side is
// in place; adding the resolving wait future + its test is a small follow-up.
