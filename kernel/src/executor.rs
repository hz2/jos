//! Cooperative async executor: jos's in-kernel scheduler.
//!
//! This is the async-as-scheduler north star made concrete (VISION star 2). It
//! is not a standalone copy of blog_os post 12: it is the capability kernel's
//! cooperative scheduler, and the seam through which a blocked IPC operation
//! parks and a peer wakes it (slice 2b) and through which an interrupt hands
//! work to a task without decoding it inline (slice 2c).
//!
//! # Two-level ready tracking (and why)
//!
//! A [`Waker`] may be invoked from *any* context, including an interrupt
//! handler. So whatever `wake()` touches must be lock-free / interrupt-safe.
//! The verified scheduling model ([`RunQueue`]) is single-owner pure logic with
//! no atomics, so wakers cannot touch it directly. Hence two levels:
//!
//! - a lock-free [`ArrayQueue`] **wake inbox** that wakers push task slot
//!   indices into (safe from interrupt context); a per-task [`AtomicBool`]
//!   `queued` flag dedups at the source, so the inbox holds at most one entry
//!   per slot and can neither overflow nor starve a distinct wake; and
//! - the verified [`RunQueue`], which the executor (the single-threaded owner)
//!   drains the inbox into and dequeues from. It provides FIFO scheduling order
//!   and the Kani-proven `len <= MAX_TASKS` bound, so the executor can enqueue a
//!   freshly woken task without ever handling a queue-full failure.
//!
//! # Tasks
//!
//! A [`Task`] is a heap-pinned future the executor drives to completion. These
//! are in-kernel cooperative tasks: their "stack" is the future's state machine
//! and there is no separate register context. The retypeable TCB *object* (a
//! thread with a saved register context plus CSpace/VSpace roots, carved from
//! untyped like an `Endpoint`) belongs with userspace threads in a later slice;
//! an in-kernel task needs none of that.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::task::Wake;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};

use crossbeam_queue::ArrayQueue;
use jos_core::run_queue::RunQueue;

/// Maximum number of simultaneously-live tasks.
///
/// Fixed so the executor builds its task slab and run queue once, with no
/// reallocation, and so the slot index domain matches the verified
/// [`RunQueue`]'s `[0, N)` range exactly.
pub const MAX_TASKS: usize = 64;

// --------------------------------------------------------------------------
// Task
// --------------------------------------------------------------------------

/// A unit of asynchronous work: a heap-pinned future driven to completion.
pub struct Task {
    future: Pin<Box<dyn Future<Output = ()>>>,
}

impl Task {
    /// Wraps `future` as a task. The future must be `'static` (it outlives the
    /// poll calls) and yield `()` (a task is run for its effects).
    #[must_use]
    pub fn new(future: impl Future<Output = ()> + 'static) -> Self {
        Self {
            future: Box::pin(future),
        }
    }

    // polls the inner future. `Pin::as_mut` reborrows the pinned box so the
    // future is never moved out of its pinned location.
    fn poll(&mut self, context: &mut Context) -> Poll<()> {
        self.future.as_mut().poll(context)
    }
}

// the boxed `dyn Future` cannot derive Debug, but a Task should still be
// printable (and `spawn`'s `Result<_, Task>` needs it for `.expect`). report
// the opaque shape rather than the future's state.
impl core::fmt::Debug for Task {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Task").finish_non_exhaustive()
    }
}

// --------------------------------------------------------------------------
// Waker glue
// --------------------------------------------------------------------------

/// The wake target for one task slot. Shared (via `Arc`) between the executor,
/// which clears `queued` before each poll, and the [`Waker`] handed to the
/// task, whose `wake` pushes the slot into the inbox.
struct TaskWaker {
    slot: usize,
    // "this slot is in flight toward a poll": set by wake, cleared by the
    // executor just before it polls the task. gates inbox pushes so the inbox
    // holds at most one entry per slot.
    queued: AtomicBool,
    wake_inbox: Arc<ArrayQueue<usize>>,
}

impl TaskWaker {
    // records a wake: if this slot is not already in flight, claim it and push
    // it to the inbox. lock-free, so this is safe to call from an interrupt
    // handler. a push failure is impossible here (the flag bounds the inbox to
    // one entry per slot, and the inbox has MAX_TASKS capacity), but the result
    // is discarded rather than unwrapped so a wake can never panic.
    fn schedule(&self) {
        if !self.queued.swap(true, Ordering::AcqRel) {
            let _ = self.wake_inbox.push(self.slot);
        }
    }
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.schedule();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.schedule();
    }
}

// --------------------------------------------------------------------------
// Executor
// --------------------------------------------------------------------------

/// The cooperative executor: owns the task slab and drives ready tasks.
pub struct Executor {
    // slot-indexed task slab; `None` is a free slot. not `Box<[..]>` so the
    // whole executor can be a value the kernel holds on its stack/static.
    tasks: [Option<Task>; MAX_TASKS],
    // the wake target per slot, kept alive while the task is live so its
    // `queued` flag persists across polls.
    wakers: [Option<Arc<TaskWaker>>; MAX_TASKS],
    // the verified scheduling model: which slots are ready, in FIFO order.
    ready: RunQueue<MAX_TASKS>,
    // lock-free inbox wakers push into; drained into `ready` by the executor.
    wake_inbox: Arc<ArrayQueue<usize>>,
}

impl Executor {
    /// Creates an empty executor. Allocates the wake inbox once, so it must be
    /// called after the heap is initialized.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tasks: [const { None }; MAX_TASKS],
            wakers: [const { None }; MAX_TASKS],
            ready: RunQueue::new(),
            wake_inbox: Arc::new(ArrayQueue::new(MAX_TASKS)),
        }
    }

    /// Spawns `task` into a free slot and marks it ready, returning its slot
    /// index.
    ///
    /// # Errors
    ///
    /// Returns the rejected `task` if all [`MAX_TASKS`] slots are occupied.
    pub fn spawn(&mut self, task: Task) -> Result<usize, Task> {
        let Some(slot) = self.free_slot() else {
            return Err(task);
        };
        let waker = Arc::new(TaskWaker {
            slot,
            // a freshly spawned task goes straight onto the ready queue, so it
            // starts in the "in flight" state to match.
            queued: AtomicBool::new(true),
            wake_inbox: self.wake_inbox.clone(),
        });
        self.tasks[slot] = Some(task);
        self.wakers[slot] = Some(waker);
        // a fresh slot is never already queued, and the run queue is proven to
        // have room for every distinct slot, so this enqueue always takes.
        let enqueued = self.ready.enqueue(slot);
        debug_assert!(enqueued, "fresh slot must enqueue");
        Ok(slot)
    }

    // index of the first free task slot, if any.
    fn free_slot(&self) -> Option<usize> {
        self.tasks.iter().position(Option::is_none)
    }

    // moves every pending wake from the lock-free inbox into the verified ready
    // queue. a wake for a slot whose task has since completed (now `None`) is
    // dropped; the run queue dedups the rest.
    fn drain_inbox(&mut self) {
        while let Ok(slot) = self.wake_inbox.pop() {
            if slot < MAX_TASKS && self.tasks[slot].is_some() {
                self.ready.enqueue(slot);
            }
        }
    }

    // polls every currently-ready task once, in FIFO order. a task that
    // completes frees its slot; a task that wakes itself or another during its
    // poll lands back in the inbox for the next drain.
    fn run_ready(&mut self) {
        while let Some(slot) = self.ready.dequeue() {
            // clone the Arc so no borrow of `self.wakers` is held while we
            // borrow `self.tasks` to poll.
            let Some(waker_arc) = self.wakers[slot].clone() else {
                continue;
            };
            // clear the flag BEFORE polling: a wake that arrives during the
            // poll then re-queues the task (it will be polled again), rather
            // than being suppressed as a duplicate.
            waker_arc.queued.store(false, Ordering::Release);
            let waker = Waker::from(waker_arc);
            let mut context = Context::from_waker(&waker);
            let poll = match self.tasks[slot].as_mut() {
                Some(task) => task.poll(&mut context),
                None => continue,
            };
            if poll.is_ready() {
                // task finished: free the slot and drop its waker.
                self.tasks[slot] = None;
                self.wakers[slot] = None;
            }
        }
    }

    /// Drives tasks until none are ready and the inbox is empty, then returns.
    ///
    /// Used by tests and by callers that want to make progress without halting
    /// the cpu. Pending tasks with no outstanding wake remain parked.
    pub fn run_until_idle(&mut self) {
        loop {
            self.drain_inbox();
            if self.ready.is_empty() {
                break;
            }
            self.run_ready();
        }
    }

    /// Runs the executor forever: drive ready tasks, then sleep the cpu until
    /// the next interrupt when there is nothing to do.
    ///
    /// This is the kernel's idle loop. It never returns.
    pub fn run(&mut self) -> ! {
        loop {
            self.drain_inbox();
            self.run_ready();
            self.sleep_if_idle();
        }
    }

    // halts the cpu if there is no pending work, closing the race against an
    // interrupt that arrives between the emptiness check and the halt.
    fn sleep_if_idle(&self) {
        use x86_64::instructions::interrupts;
        // disable interrupts so the check below and the halt are atomic with
        // respect to an interrupt that would push a wake: without this, an IRQ
        // firing after the check but before `hlt` would be missed and the cpu
        // could sleep through a pending wake.
        interrupts::disable();
        if self.wake_inbox.is_empty() && self.ready.is_empty() {
            // enable_and_hlt is `sti; hlt`: the cpu enables interrupts and
            // halts as one step, so a wake-causing interrupt cannot slip in
            // between re-enabling and halting.
            interrupts::enable_and_hlt();
        } else {
            // work arrived after all: re-enable and loop without sleeping.
            interrupts::enable();
        }
    }
}

impl Default for Executor {
    fn default() -> Self {
        Self::new()
    }
}

// --------------------------------------------------------------------------
// yield_now
// --------------------------------------------------------------------------

/// Yields control back to the executor once, then resumes.
///
/// The first poll registers a wake and returns `Poll::Pending`, so the executor
/// runs other ready tasks before polling this one again. Exercises the full
/// park/wake path without needing an endpoint, and lets a task voluntarily give
/// others a turn.
pub async fn yield_now() {
    YieldNow { yielded: false }.await;
}

struct YieldNow {
    yielded: bool,
}

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context) -> Poll<()> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            // re-queue ourselves before parking so the executor polls us again.
            context.waker().wake_by_ref();
            Poll::Pending
        }
    }
}
