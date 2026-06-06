// tests/recv_timeout.rs
//
// receive-with-timeout: the consumer that makes IPC deadlock-freedom real. a
// blocked recv can no longer wait forever; it either receives a message or, at
// a deadline, times out. the timeout is driven by real hardware: the TSC clock
// (jos::clock::TscClock) supplies now(), and the periodic PIT timer IRQ drains
// the global TimerQueue, firing the waker of any timer whose deadline the TSC
// has passed.
//
// the verified pieces (the deadline arithmetic, the TimerQueue, the endpoint
// rendezvous and its cancel_receiver) live in jos-core and are proven under
// simulation; this wires them to the TSC, the PIT handler, and the executor,
// headless under QEMU. it proves: (1) a receiver whose sender deposits before
// the deadline gets the message (no spurious timeout); (2) a receiver with no
// sender times out once the deadline passes (no hang).
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

use jos::cap::{recv_timeout, send, KernelCapSpace, Message, RecvTimeout, UntypedRegion};
use jos::clock;
use jos::executor::{Executor, Task};
use jos_core::cap_rights::Rights;
use jos_core::cap_table::CapRef;
use jos_core::clock::Duration;

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
// SAFETY: single-threaded ring 0; slices are handed out sequentially below.
unsafe impl Sync for UntypedBacking {}
static UNTYPED: UntypedBacking = UntypedBacking {
    bytes: core::cell::UnsafeCell::new([0u8; 4096]),
};
static NEXT: AtomicUsize = AtomicUsize::new(0);

fn fresh_untyped() -> UntypedRegion {
    let off = NEXT.fetch_add(512, Ordering::SeqCst);
    // SAFETY: each call claims a distinct [off, off+512) window of the static
    // backing (the cursor only advances); off is a multiple of 512 and the
    // backing is 64-aligned, so the sub-slice base is 64-aligned.
    let backing: &mut [u8; 4096] = unsafe { &mut *UNTYPED.bytes.get() };
    UntypedRegion::new(&mut backing[off..off + 512])
}

fn space_with_endpoint() -> (KernelCapSpace, CapRef, CapRef) {
    let mut untyped = fresh_untyped();
    let mut space = KernelCapSpace::new();
    let endpoint = untyped.retype_endpoint().expect("endpoint must fit");
    let full = space.insert(endpoint, Rights::all()).unwrap();
    let send_cap = space.mint(full, Rights::WRITE).unwrap();
    let recv_cap = space.mint(full, Rights::READ).unwrap();
    (space, send_cap, recv_cap)
}

// drives the executor until `done` is set, sleeping the cpu (hlt) between turns
// so the periodic PIT timer IRQ advances and fires due timers. a bounded outer
// cap (TICK_COUNT-based) keeps a buggy never-completing future from hanging the
// test forever: it asserts progress within a generous tick budget.
fn run_until(executor: &mut Executor, done: &RefCell<bool>) {
    use jos::interrupts::TICK_COUNT;
    let start = TICK_COUNT.load(Ordering::Relaxed);
    loop {
        executor.run_until_idle();
        if *done.borrow() {
            return;
        }
        // nothing ready: wait for the next interrupt (the PIT tick), which may
        // fire a due timeout timer and wake the receiver.
        x86_64::instructions::interrupts::enable_and_hlt();
        // generous bound: the PIT is ~18.2 Hz, deadlines here are small TSC
        // deltas, so a handful of ticks is plenty. 200 ticks (~11 s) means a
        // genuine hang, not just a slow timeout.
        let elapsed = TICK_COUNT.load(Ordering::Relaxed).wrapping_sub(start);
        assert!(elapsed < 200, "recv_timeout did not complete within the tick budget");
    }
}

// a sender that deposits before the deadline delivers the message: the receiver
// returns RecvTimeout::Message, not a timeout. the deadline is far in the future
// (a large TSC delta), so the sender always wins.
#[test_case]
fn message_arrives_before_deadline() {
    let (space, send_cap, recv_cap) = space_with_endpoint();
    let space = Rc::new(space);
    let got: Rc<RefCell<Option<RecvTimeout>>> = Rc::new(RefCell::new(None));
    let done = Rc::new(RefCell::new(false));

    // a deadline far ahead: 1e12 TSC ticks (~hundreds of ms at GHz), so the
    // immediately-spawned sender deposits well before it.
    let deadline = clock::now().saturating_add(Duration::new(1_000_000_000_000));
    let sent = Message { label: 0xCAFE, words: [1, 2, 3, 4] };

    let mut executor = Executor::new();
    {
        let space = space.clone();
        let got = got.clone();
        let done = done.clone();
        executor
            .spawn(Task::new(async move {
                *got.borrow_mut() = Some(recv_timeout(&space, recv_cap, deadline).await.unwrap());
                *done.borrow_mut() = true;
            }))
            .unwrap();
    }
    {
        let space = space.clone();
        executor
            .spawn(Task::new(async move {
                send(&space, send_cap, sent).await.unwrap();
            }))
            .unwrap();
    }

    run_until(&mut executor, &done);
    assert_eq!(*got.borrow(), Some(RecvTimeout::Message(sent)));
}

// a receiver with no sender times out: once the TSC passes the (near) deadline,
// the PIT timer IRQ fires the armed timer's waker, the receiver re-polls, sees
// the deadline passed, and returns RecvTimeout::TimedOut instead of hanging.
#[test_case]
fn no_sender_times_out() {
    let (space, _send_cap, recv_cap) = space_with_endpoint();
    let space = Rc::new(space);
    let got: Rc<RefCell<Option<RecvTimeout>>> = Rc::new(RefCell::new(None));
    let done = Rc::new(RefCell::new(false));

    // a near deadline: a small TSC delta, reached within a PIT tick or two. no
    // sender is ever spawned, so the only way the receiver completes is by
    // timing out, which proves the timeout path fires.
    let deadline = clock::now().saturating_add(Duration::new(1_000_000));

    let mut executor = Executor::new();
    {
        let space = space.clone();
        let got = got.clone();
        let done = done.clone();
        executor
            .spawn(Task::new(async move {
                *got.borrow_mut() = Some(recv_timeout(&space, recv_cap, deadline).await.unwrap());
                *done.borrow_mut() = true;
            }))
            .unwrap();
    }

    run_until(&mut executor, &done);
    assert_eq!(*got.borrow(), Some(RecvTimeout::TimedOut));
}
