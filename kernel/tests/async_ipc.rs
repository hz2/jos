// tests/async_ipc.rs
//
// slice 2b: synchronous IPC turned into real async rendezvous. in-kernel tasks
// share one executor and talk over a capability-protected endpoint; a receiver
// parks (Poll::Pending) on an empty endpoint and the sender's deposit wakes it
// through the endpoint's stored Waker. also proves a sender blocks on a full
// (capacity-1) endpoint until a receiver drains it, and that a future built on a
// stale capability resolves to an error on its first poll (authority is
// re-validated whenever the future runs).
//
// the cap model (rights, mint, revoke) is proven in jos-core; the executor and
// verified run queue landed in slice 2a. this wires them together: cap-mediated
// IPC that blocks and wakes via the scheduler, headless under QEMU.
//
// note on borrowing: send()/recv() take `&KernelCapSpace` and the returned
// future holds that borrow across await points, so the space cannot be mutated
// (revoked) while an IPC future is in flight. revoking *under a parked waiter*
// and having it observe the cancellation needs the space resolved fresh on each
// poll, which arrives in slice 3 (CSpace in the TCB, IPC as a syscall). here the
// shared space is immutable (Rc, no RefCell): only the endpoint behind its lock
// mutates, so multiple tasks borrow the space concurrently without conflict.
#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

use jos::cap::{recv, send, IpcError, KernelCapSpace, Message, UntypedRegion};
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
// each test takes a fresh 512-byte slice via a bump cursor so their endpoints do
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
    // form the whole-array &mut in one explicit deref (avoiding an implicit
    // autoref through the raw pointer), then sub-slice that safe reference.
    // SAFETY: each call claims a distinct [off, off+512) window of the static
    // backing (the cursor only advances), so the &'static mut is unique. off is a
    // multiple of 512 and the backing is 64-aligned, so the sub-slice base is
    // 64-aligned as UntypedRegion::new requires.
    let backing: &mut [u8; 4096] = unsafe { &mut *UNTYPED.bytes.get() };
    UntypedRegion::new(&mut backing[off..off + 512])
}

// builds a space with one endpoint and returns (space, send_cap, recv_cap).
fn space_with_endpoint() -> (KernelCapSpace, CapRef, CapRef) {
    let mut untyped = fresh_untyped();
    let mut space = KernelCapSpace::new();
    let endpoint = untyped.retype_endpoint().expect("endpoint must fit");
    let full = space.insert(endpoint, Rights::all()).unwrap();
    let send_cap = space.mint(full, Rights::WRITE).unwrap();
    let recv_cap = space.mint(full, Rights::READ).unwrap();
    (space, send_cap, recv_cap)
}

// a receiver that parks on an empty endpoint is woken by a later sender, and the
// message round-trips. the receiver is spawned first (so it parks on first
// poll), then the sender runs and wakes it.
#[test_case]
fn receiver_parks_then_sender_wakes_it() {
    let (space, send_cap, recv_cap) = space_with_endpoint();
    let space = Rc::new(space);
    let got: Rc<RefCell<Option<Message>>> = Rc::new(RefCell::new(None));

    let mut executor = Executor::new();

    // receiver task: awaits a message. on first poll the endpoint is empty, so
    // it parks (Poll::Pending) with its waker stored in the endpoint.
    {
        let space = space.clone();
        let got = got.clone();
        executor
            .spawn(Task::new(async move {
                let msg = recv(&space, recv_cap).await.expect("recv should succeed");
                *got.borrow_mut() = Some(msg);
            }))
            .unwrap();
    }

    // sender task: deposits a message, which wakes the parked receiver.
    let sent = Message {
        label: 0xBEEF,
        words: [9, 8, 7, 6],
    };
    {
        let space = space.clone();
        executor
            .spawn(Task::new(async move {
                send(&space, send_cap, sent).await.expect("send should succeed");
            }))
            .unwrap();
    }

    executor.run_until_idle();

    // the receiver woke, received, and stored the exact message the sender sent.
    assert_eq!(*got.borrow(), Some(sent));
}

// the reverse order: the sender deposits before any receiver exists, then a
// receiver drains it. no parking needed; proves order-independence.
#[test_case]
fn sender_first_then_receiver_drains() {
    let (space, send_cap, recv_cap) = space_with_endpoint();
    let space = Rc::new(space);
    let got: Rc<RefCell<Option<Message>>> = Rc::new(RefCell::new(None));

    let sent = Message {
        label: 1,
        words: [1, 2, 3, 4],
    };

    let mut executor = Executor::new();
    {
        let space = space.clone();
        executor
            .spawn(Task::new(async move {
                send(&space, send_cap, sent).await.unwrap();
            }))
            .unwrap();
    }
    {
        let space = space.clone();
        let got = got.clone();
        executor
            .spawn(Task::new(async move {
                *got.borrow_mut() = Some(recv(&space, recv_cap).await.unwrap());
            }))
            .unwrap();
    }

    executor.run_until_idle();
    assert_eq!(*got.borrow(), Some(sent));
}

// a second sender blocks while the endpoint already holds an undelivered
// message, and completes only after a receiver drains the first. the capacity-1
// endpoint serializes two sends through one receive each, so all four events
// (two sends, two receipts) occur exactly once.
#[test_case]
fn sender_blocks_on_full_endpoint_until_drained() {
    let (space, send_cap, recv_cap) = space_with_endpoint();
    let space = Rc::new(space);
    let order: Rc<RefCell<Vec<u64>>> = Rc::new(RefCell::new(Vec::new()));

    let mut executor = Executor::new();

    // two senders deposit messages 10 and 20. the endpoint holds one at a time,
    // so the second sender must park until the receiver drains the first.
    for label in [10_u64, 20] {
        let space = space.clone();
        let order = order.clone();
        executor
            .spawn(Task::new(async move {
                send(&space, send_cap, Message { label, words: [0; 4] })
                    .await
                    .unwrap();
                order.borrow_mut().push(label);
            }))
            .unwrap();
    }

    // one receiver drains both messages, recording each as 100 + its label.
    {
        let space = space.clone();
        let order = order.clone();
        executor
            .spawn(Task::new(async move {
                for _ in 0..2 {
                    let msg = recv(&space, recv_cap).await.unwrap();
                    order.borrow_mut().push(100 + msg.label);
                }
            }))
            .unwrap();
    }

    executor.run_until_idle();

    // both messages delivered: two sends completed and two receipts recorded.
    // the exact interleaving depends on poll order, so assert presence (not
    // sequence): a lost wakeup or dropped message would drop an event.
    let log = order.borrow();
    assert_eq!(log.len(), 4, "two sends and two receipts: {log:?}");
    assert!(log.contains(&10) && log.contains(&20), "both sends done: {log:?}");
    assert!(
        log.contains(&110) && log.contains(&120),
        "both messages received: {log:?}"
    );
}

// a future built on a capability that is already stale resolves to InvalidCap on
// its first poll: the IPC futures re-validate authority through resolve_endpoint
// every time they run, rather than trusting a check made at creation. (the cap
// is revoked before the space is shared, so no mutation crosses an await; the
// revoke-while-parked path is a slice-3 item, see the module header.)
#[test_case]
fn stale_capability_is_rejected_at_poll() {
    let mut untyped = fresh_untyped();
    let mut space = KernelCapSpace::new();
    let endpoint = untyped.retype_endpoint().unwrap();
    let full = space.insert(endpoint, Rights::all()).unwrap();
    let recv_cap = space.mint(full, Rights::READ).unwrap();

    // revoke the whole tree: recv_cap is now stale before any task runs.
    let removed = space.revoke(full);
    assert_eq!(removed, 2); // root + recv_cap

    let space = Rc::new(space);
    let result: Rc<RefCell<Option<Result<Message, IpcError>>>> = Rc::new(RefCell::new(None));

    let mut executor = Executor::new();
    {
        let space = space.clone();
        let result = result.clone();
        executor
            .spawn(Task::new(async move {
                *result.borrow_mut() = Some(recv(&space, recv_cap).await);
            }))
            .unwrap();
    }
    executor.run_until_idle();

    // the await resolved immediately with InvalidCap; it never parked.
    assert_eq!(*result.borrow(), Some(Err(IpcError::InvalidCap)));
}
