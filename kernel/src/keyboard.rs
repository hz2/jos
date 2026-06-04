//! Keyboard scancode stream: decoding moved off the interrupt handler.
//!
//! The PS/2 keyboard IRQ must do as little as possible: reading the data port
//! and pushing the raw byte is bounded and lock-free, but decoding a scancode
//! (the `pc-keyboard` state machine, printing) is unbounded work that does not
//! belong in interrupt context. So the handler ([`add_scancode`]) only enqueues
//! the byte and wakes a task; an executor task ([`print_keypresses`]) drains the
//! queue through [`ScancodeStream`] and decodes at leisure.
//!
//! This is the same producer/consumer split the async IPC endpoints use (a
//! lock-free queue carries data in from interrupt context, a [`Waker`] hands the
//! work to the scheduler), applied to a device driver. It is the seam where a
//! userspace keyboard driver will later attach: the IRQ becomes an interrupt
//! capability that wakes a driver task instead of an in-kernel one.
//!
//! # Why the fixed-capacity queue
//!
//! [`SCANCODE_QUEUE`] is a bounded [`ArrayQueue`]: the interrupt handler must
//! never allocate (it can fire at any time, including inside the allocator), so
//! the queue is sized once at startup and a push into a full queue drops the
//! scancode with a warning rather than growing. Dropped keystrokes under a flood
//! are preferable to an allocator deadlock.

use alloc::string::String;
use core::pin::Pin;
use core::task::{Context, Poll};

use conquer_once::spin::OnceCell;
use crossbeam_queue::ArrayQueue;
use futures_util::stream::{Stream, StreamExt};
use futures_util::task::AtomicWaker;

/// Capacity of the scancode queue. 128 bytes absorbs a healthy burst of key
/// events between executor polls; a full queue drops scancodes (see module doc).
const QUEUE_CAPACITY: usize = 128;

/// The bounded queue the keyboard IRQ pushes raw scancodes into and the decoder
/// task pops them from. `OnceCell` because `ArrayQueue::new` allocates, so it is
/// initialized once at startup (after the heap is up), not at const time.
static SCANCODE_QUEUE: OnceCell<ArrayQueue<u8>> = OnceCell::uninit();

/// Waker of the task blocked in [`ScancodeStream::poll_next`] on an empty queue.
/// `AtomicWaker` is the single-consumer, multi-producer waker cell: the IRQ
/// (producer) wakes it; the decoder task (consumer) registers itself in it.
static WAKER: AtomicWaker = AtomicWaker::new();

/// Initializes the scancode queue. Call once during kernel init, after the heap
/// is live and before the keyboard IRQ is expected to enqueue anything.
///
/// Idempotent-safe to the extent that a second call is ignored.
pub fn init() {
    // a fresh queue; ignore the error if init() somehow runs twice.
    let _ = SCANCODE_QUEUE.try_init_once(|| ArrayQueue::new(QUEUE_CAPACITY));
}

/// Pushes a raw scancode onto the queue and wakes the decoder task.
///
/// Called directly from the keyboard interrupt handler, so it must stay
/// lock-free and allocation-free: it does a single queue push and an atomic
/// waker wake. A push into a full queue, or a call before [`init`], drops the
/// scancode with a warning rather than blocking or allocating.
pub fn add_scancode(scancode: u8) {
    // try_get avoids any blocking: in the unlikely case the queue is mid-init we
    // simply drop the byte rather than spin in interrupt context.
    if let Ok(queue) = SCANCODE_QUEUE.try_get() {
        if queue.push(scancode).is_err() {
            crate::serial_println!("WARNING: scancode queue full; dropping input");
        } else {
            // a byte is now available: wake the registered consumer (if any).
            WAKER.wake();
        }
    } else {
        crate::serial_println!("WARNING: scancode queue uninitialized; dropping input");
    }
}

/// A [`Stream`] of raw scancodes drained from [`SCANCODE_QUEUE`].
///
/// Single-consumer: at most one `ScancodeStream` should exist, because the
/// shared [`WAKER`] holds exactly one consumer. Constructed via [`new`](Self::new).
pub struct ScancodeStream {
    // private field so the only way to build one is `new`, which asserts the
    // queue is initialized; keeps a stream from existing before init().
    _private: (),
}

impl ScancodeStream {
    /// Creates the scancode stream. [`init`] must have been called first.
    ///
    /// # Panics
    ///
    /// Panics if [`init`] has not initialized the queue yet.
    #[must_use]
    pub fn new() -> Self {
        assert!(
            SCANCODE_QUEUE.try_get().is_ok(),
            "keyboard::init() must be called before ScancodeStream::new()"
        );
        ScancodeStream { _private: () }
    }
}

impl Default for ScancodeStream {
    fn default() -> Self {
        Self::new()
    }
}

impl Stream for ScancodeStream {
    type Item = u8;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context) -> Poll<Option<u8>> {
        // the queue exists (ScancodeStream::new asserted it); try_get never
        // blocks. expect is justified: the only producer of None here would be a
        // teardown path that does not exist on a never-ending input stream.
        let queue = SCANCODE_QUEUE
            .try_get()
            .expect("scancode queue not initialized");

        // fast path: a scancode is already waiting.
        if let Ok(scancode) = queue.pop() {
            return Poll::Ready(Some(scancode));
        }

        // empty: register our waker, then re-check. the re-check closes the race
        // where a scancode is pushed (and WAKER.wake() called) between the first
        // pop and registering the waker: without it that wake would be lost and
        // the task could sleep forever with a byte already queued.
        WAKER.register(context.waker());
        match queue.pop() {
            Ok(scancode) => {
                // a byte arrived during registration: consume the registration
                // (we are about to make progress) and return it.
                WAKER.take();
                Poll::Ready(Some(scancode))
            }
            Err(_) => Poll::Pending,
        }
    }
}

/// Executor task: decode scancodes from the keyboard and print the characters.
///
/// Runs the `pc-keyboard` state machine off the interrupt handler. This never
/// returns; it is spawned once onto the executor and awaits the endless stream.
pub async fn print_keypresses() {
    use pc_keyboard::{layouts, DecodedKey, HandleControl, Keyboard, ScancodeSet1};

    let mut scancodes = ScancodeStream::new();
    // pc-keyboard 0.5 arg order is (layout, scancode_set, handle_control).
    let mut keyboard = Keyboard::new(layouts::Us104Key, ScancodeSet1, HandleControl::Ignore);

    while let Some(scancode) = scancodes.next().await {
        let Ok(Some(event)) = keyboard.add_byte(scancode) else {
            continue;
        };
        let Some(key) = keyboard.process_keyevent(event) else {
            continue;
        };
        match key {
            DecodedKey::Unicode(c) => {
                let mut s = String::new();
                s.push(c);
                crate::print!("{s}");
            }
            DecodedKey::RawKey(k) => crate::print!("{k:?}"),
        }
    }
}
