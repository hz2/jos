//! Hardware time: the TSC-backed [`KernelClock`] and the global timer queue.
//!
//! This is the kernel-side realization of the injected-time seam
//! ([`jos_core::clock`]). The verified deadline arithmetic and the
//! deadline-ordered [`TimerQueue`](jos_core::timer::TimerQueue) live in
//! `jos-core`, exercised under simulation by `SimClock`; here they meet real
//! hardware:
//!
//! - [`TscClock`] implements [`KernelClock`] by reading the CPU timestamp
//!   counter (`rdtsc`). The TSC is a monotonic free-running counter, so it
//!   needs no calibration to drive *relative* deadlines (deadline = now + span),
//!   which is all a timeout needs. (Converting ticks to wall-clock seconds would
//!   need the TSC frequency; jos does not need that yet.)
//! - a single global [`TimerQueue`] holds the armed timers. A task arms a timer
//!   for a deadline; the periodic timer IRQ ([`drain_due`], called from the PIT
//!   handler) pops every timer whose deadline the TSC has reached and fires its
//!   stored waker, so a blocked task wakes when its deadline passes.
//!
//! Together with the endpoint wait path this gives receive-with-timeout: a
//! `recv` parks on the endpoint AND arms a timer; whichever fires first (a
//! sender depositing, or the deadline passing) wakes the task. That is the
//! mechanism behind IPC deadlock-freedom: a blocked `recv` can no longer block
//! forever, it always either receives or times out.

use core::task::Waker;

use jos_core::clock::{Instant, KernelClock};
use jos_core::timer::{TimerId, TimerQueue};
use spin::Mutex;
use x86_64::instructions::interrupts;

use crate::executor::MAX_TASKS;

/// A monotonic clock backed by the CPU timestamp counter (`rdtsc`).
///
/// Zero-sized: it carries no state, since the time lives in the hardware
/// counter. `now()` reads the TSC, which increments at a constant rate on
/// modern parts (invariant TSC) and never runs backwards, so it satisfies the
/// [`KernelClock`] monotonicity contract by construction.
#[derive(Debug, Clone, Copy, Default)]
pub struct TscClock;

impl TscClock {
    /// Creates a `TscClock` (a zero-sized handle to the hardware counter).
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl KernelClock for TscClock {
    fn now(&self) -> Instant {
        // SAFETY: rdtsc is an unprivileged, side-effect-free read of the
        // timestamp counter; it touches no memory and faults only if CR4.TSD
        // disables it (jos leaves TSD clear). _rdtsc returns the full 64-bit
        // counter.
        let ticks = unsafe { core::arch::x86_64::_rdtsc() };
        Instant::new(ticks)
    }
}

/// The kernel's global wall of pending timers, sized to one per task slot.
///
/// Behind a `Mutex` because both task context (arming a timer) and the timer
/// IRQ handler (draining due ones) touch it. CRITICAL: this lock is shared with
/// an interrupt handler, so every TASK-context acquisition must hold it with
/// interrupts disabled (`interrupts::without_interrupts`), exactly as
/// `serial::_print` does for `SERIAL1`. Otherwise a timer IRQ firing while a
/// task holds the lock would spin-deadlock (`spin::Mutex` is not reentrant, and
/// on single-core the held lock never releases). The IRQ handler itself runs
/// with interrupts already disabled, so its acquisition needs no extra guard;
/// `without_interrupts` saves/restores the flag, so wrapping it there too is a
/// correct no-op. A task must not hold this across an `.await`.
static TIMERS: Mutex<TimerQueue<MAX_TASKS>> = Mutex::new(TimerQueue::new());

/// Arms a timer for `deadline` carrying `data`, returning its [`TimerId`], or
/// `None` if the global queue is full.
///
/// The `data` word is opaque to the queue; the timeout path stores a slot index
/// or token it can correlate when the timer fires. The caller pairs the id with
/// whatever it must cancel if its other wakeup (a delivered message) wins first.
pub fn arm(deadline: Instant, data: u64) -> Option<TimerId> {
    // interrupts off while holding the IRQ-shared lock (see TIMERS doc).
    interrupts::without_interrupts(|| TIMERS.lock().arm(deadline, data))
}

/// Cancels the timer with id `id`, returning `true` if one was removed.
///
/// Called when a timeout's other outcome wins (a message arrived before the
/// deadline), so the timer does not later fire a stale wakeup.
pub fn cancel(id: TimerId) -> bool {
    interrupts::without_interrupts(|| TIMERS.lock().cancel(id))
}

/// Returns the current time from the TSC.
#[must_use]
pub fn now() -> Instant {
    TscClock.now()
}

/// Fires every timer whose deadline the current time has reached, invoking
/// `on_fire` with each expired timer's [`TimerId`].
///
/// Called from the periodic timer IRQ handler. Each expired timer's id is
/// collected under the queue lock first, then the lock is dropped before
/// `on_fire` runs, so a waker fired here cannot deadlock against a task arming a
/// timer. Returns the number of timers fired.
pub fn drain_due(mut on_fire: impl FnMut(TimerId)) -> usize {
    let now = now();
    // collect expired ids under the lock, into a fixed-size buffer (no heap in
    // the IRQ path); at most MAX_TASKS timers can be due at once.
    let mut fired: [TimerId; MAX_TASKS] = [TimerId(0); MAX_TASKS];
    let mut count = 0;
    // interrupts off while holding the IRQ-shared lock (see TIMERS doc). when
    // called FROM the timer IRQ, interrupts are already disabled, so this is a
    // no-op; when called from task context it is the necessary guard.
    interrupts::without_interrupts(|| {
        let mut timers = TIMERS.lock();
        while let Some(timer) = timers.expire_next(now) {
            fired[count] = timer.id;
            count += 1;
            // the queue holds at most MAX_TASKS timers, so this never overflows;
            // guard anyway so a logic error cannot write out of bounds.
            if count == MAX_TASKS {
                break;
            }
        }
    });
    // fire callbacks after dropping the lock.
    for &id in fired.iter().take(count) {
        on_fire(id);
    }
    count
}

// --------------------------------------------------------------------------
// waker registry for timer wakeups
// --------------------------------------------------------------------------
//
// a timer's `data` word cannot be a Waker (the queue is pure-logic, Copy data),
// so the timeout path stores the waker here, keyed by the timer's unique
// TimerId, and puts that id in the timer's `data`. when the timer fires, the IRQ
// handler looks up the waker by id and fires it. TimerIds are strictly
// increasing and never reused, so there is no ABA: a fired-or-cancelled id never
// matches a later timer. the registry is a fixed array of (id, waker) pairs (no
// heap), sized to MAX_TASKS (one outstanding timeout per task slot).

struct TimerWaker {
    id: TimerId,
    waker: Waker,
}

static TIMER_WAKERS: Mutex<[Option<TimerWaker>; MAX_TASKS]> =
    Mutex::new([const { None }; MAX_TASKS]);

/// Registers `waker` to be fired when the timer with id `id` expires.
///
/// Stored in the first free registry slot; returns `false` if the registry is
/// full (every task slot already has an outstanding timeout, which the
/// MAX_TASKS sizing makes unreachable in practice). A prior registration for the
/// same id is replaced, so re-arming on a later poll updates the waker.
pub fn register_timer_waker(id: TimerId, waker: Waker) -> bool {
    // interrupts off while holding the IRQ-shared registry lock (see TIMERS doc):
    // take_timer_waker is also called from on_timer_tick in interrupt context.
    interrupts::without_interrupts(|| {
        let mut registry = TIMER_WAKERS.lock();
        // replace an existing entry for this id (a re-poll re-registers).
        for entry in registry.iter_mut() {
            if matches!(entry, Some(e) if e.id == id) {
                *entry = Some(TimerWaker { id, waker });
                return true;
            }
        }
        // otherwise take the first free slot.
        for entry in registry.iter_mut() {
            if entry.is_none() {
                *entry = Some(TimerWaker { id, waker });
                return true;
            }
        }
        false
    })
}

/// Removes and returns the waker registered for timer `id`, if any.
pub fn take_timer_waker(id: TimerId) -> Option<Waker> {
    // interrupts off while holding the IRQ-shared registry lock (see TIMERS doc).
    // a no-op when called from on_timer_tick (interrupts already disabled), the
    // necessary guard when called from task context (forget_timer_waker).
    interrupts::without_interrupts(|| {
        let mut registry = TIMER_WAKERS.lock();
        for entry in registry.iter_mut() {
            if matches!(entry, Some(e) if e.id == id) {
                return entry.take().map(|e| e.waker);
            }
        }
        None
    })
}

/// Discards any registered waker for timer `id` (without firing it).
///
/// Called alongside [`cancel`] when a timeout's other outcome wins, so the
/// registry does not leak the waker of a cancelled timer.
pub fn forget_timer_waker(id: TimerId) {
    let _ = take_timer_waker(id);
}

/// The timer-IRQ tick: fire the wakers of every timer that has come due.
///
/// Called from the PIT interrupt handler. Each expired timer's registered waker
/// (keyed by its [`TimerId`]) is taken and fired, re-scheduling the timed-out
/// task. Lock-free wake transport (the executor's inbox) makes firing a waker
/// safe from interrupt context.
pub fn on_timer_tick() {
    drain_due(|id| {
        if let Some(waker) = take_timer_waker(id) {
            waker.wake();
        }
    });
}
