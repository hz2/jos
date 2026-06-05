// tests/revoke_blocked_ipc.rs
//
// the revoke-under-blocked-IPC payoff (Phase-2 follow-up), headless: a task
// blocked (parked) on an empty endpoint is CANCELLED when its capability is
// revoked, waking with InvalidCap instead of hanging forever. This is the
// property that distinguishes a real capability microkernel: authority can be
// withdrawn even from an in-flight, blocked operation.
//
// The existing async_ipc.rs proves the revoke-BEFORE-park case (a stale cap is
// rejected on first poll). This proves the revoke-WHILE-parked case, which the
// async_ipc.rs module header explicitly deferred: it needs the capability space
// resolved fresh on every poll (so a concurrent &mut revoke is sound) plus a
// revoke that WAKES the parked waiter. recv_resolving + revoke_and_wake provide
// exactly those two pieces.
//
// Two in-kernel executor tasks share the space (no ring 3 needed): task A parks
// on recv_resolving; task B yields once (so A parks first), then calls
// revoke_and_wake. A is woken, re-polls, sees the stale cap, returns InvalidCap.
//
// A hang here would run forever, so the failure mode matters: run_until_idle
// returns when every task has completed or is truly parked with no pending
// wake. A lost wakeup therefore manifests as task A's result staying None (and
// the assertion failing), NOT as a hang. The negative control exploits exactly
// that: with no revoke, A stays parked and its result is None.
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

use jos::cap::{recv_resolving, revoke_and_wake, IpcError, KernelCapSpace, Message, UntypedRegion};
use jos::executor::{Executor, Task, yield_now};
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

#[repr(align(64))]
struct UntypedBacking {
    bytes: core::cell::UnsafeCell<[u8; 4096]>,
}
// SAFETY: single-threaded ring 0; slices handed out sequentially below.
unsafe impl Sync for UntypedBacking {}
static UNTYPED: UntypedBacking = UntypedBacking {
    bytes: core::cell::UnsafeCell::new([0u8; 4096]),
};
static NEXT: AtomicUsize = AtomicUsize::new(0);

fn fresh_untyped() -> UntypedRegion {
    let off = NEXT.fetch_add(512, Ordering::SeqCst);
    // SAFETY: each call claims a distinct [off, off+512) window (cursor only
    // advances), so the &'static mut is unique; off multiple of 512 and backing
    // 64-aligned, so the sub-slice base meets UntypedRegion::new's alignment.
    let backing: &mut [u8; 4096] = unsafe { &mut *UNTYPED.bytes.get() };
    UntypedRegion::new(&mut backing[off..off + 512])
}

// builds a space with one endpoint; returns (space, root_cap, recv_cap).
fn space_with_endpoint() -> (KernelCapSpace, CapRef, CapRef) {
    let mut untyped = fresh_untyped();
    let mut space = KernelCapSpace::new();
    let endpoint = untyped.retype_endpoint().expect("endpoint must fit");
    let full = space.insert(endpoint, Rights::all()).unwrap();
    let recv_cap = space.mint(full, Rights::READ).unwrap();
    (space, full, recv_cap)
}

// a stable pointer to the space inside the Rc<RefCell<..>>. the recv_resolving
// future re-derives a transient &KernelCapSpace from this on each poll; the
// pointer stays valid because the Rc keeps the cell alive for the whole test.
fn space_ptr(space: &Rc<RefCell<KernelCapSpace>>) -> *const KernelCapSpace {
    space.as_ptr()
}

// task A blocks on recv; task B revokes the cap; A wakes with InvalidCap.
#[test_case]
fn parked_receiver_is_cancelled_by_revoke() {
    let (space, root_cap, recv_cap) = space_with_endpoint();
    let space = Rc::new(RefCell::new(space));
    let result: Rc<RefCell<Option<Result<Message, IpcError>>>> = Rc::new(RefCell::new(None));

    let mut executor = Executor::new();

    // task A: park on the empty endpoint via the per-poll-resolving future.
    {
        let space = space.clone();
        let result = result.clone();
        let ptr = space_ptr(&space);
        executor
            .spawn(Task::new(async move {
                // keep the Rc alive for the future's lifetime (the pointer aliases
                // its interior); the future itself holds only the raw pointer.
                let _keep_alive = space;
                // SAFETY: ptr aliases the Rc's interior, kept alive by _keep_alive;
                // polled only on this single-threaded cooperative executor, and the
                // revoke in task B runs between polls (never during one).
                let r = unsafe { recv_resolving(ptr, recv_cap) }.await;
                *result.borrow_mut() = Some(r);
            }))
            .unwrap();
    }

    // task B: yield once so A polls first and parks, then revoke + wake.
    {
        let space = space.clone();
        executor
            .spawn(Task::new(async move {
                yield_now().await;
                // A is now parked in the endpoint's recv_waiter. revoke the whole
                // tree and wake the waiter.
                let removed = revoke_and_wake(&mut space.borrow_mut(), root_cap);
                assert_eq!(removed, 2); // root + recv_cap
            }))
            .unwrap();
    }

    executor.run_until_idle();

    // A was woken, re-polled, saw the stale cap, and returned InvalidCap.
    assert_eq!(*result.borrow(), Some(Err(IpcError::InvalidCap)));
}

// negative control: with NO revoke, the parked receiver never completes. proves
// task A genuinely parked (did not resolve eagerly) and that the cancellation in
// the test above is caused by the revoke, not by something incidental.
#[test_case]
fn parked_receiver_without_revoke_stays_blocked() {
    let (space, _root_cap, recv_cap) = space_with_endpoint();
    let space = Rc::new(RefCell::new(space));
    let result: Rc<RefCell<Option<Result<Message, IpcError>>>> = Rc::new(RefCell::new(None));

    let mut executor = Executor::new();
    {
        let space = space.clone();
        let result = result.clone();
        let ptr = space_ptr(&space);
        executor
            .spawn(Task::new(async move {
                let _keep_alive = space;
                // SAFETY: as above.
                let r = unsafe { recv_resolving(ptr, recv_cap) }.await;
                *result.borrow_mut() = Some(r);
            }))
            .unwrap();
    }

    // no revoker task. the executor drains to idle with A parked forever.
    executor.run_until_idle();

    // A never completed: its result is still None (it is parked, not resolved).
    assert_eq!(*result.borrow(), None);
}
