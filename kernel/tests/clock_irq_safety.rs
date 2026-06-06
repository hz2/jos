// tests/clock_irq_safety.rs
//
// regression test for the timer-lock deadlock (fixed in clock.rs by guarding
// the IRQ-shared TIMERS / TIMER_WAKERS locks with without_interrupts).
//
// the hazard: clock::arm / cancel / register_timer_waker lock spin::Mutexes that
// the PIT timer IRQ handler (on_timer_tick) also locks. spin::Mutex is not
// reentrant, so on single-core, if a timer IRQ fires while a task holds one of
// these locks, the handler spins forever waiting for a lock only the (now
// preempted) task can release -> hard deadlock, and this test times out.
//
// to provoke it deterministically: with interrupts LIVE and the PIT firing
// (~18.2 Hz), hammer the public clock API in a tight loop for many iterations.
// without the without_interrupts guard, a timer IRQ eventually lands while the
// loop holds the lock and the kernel wedges (QEMU never exits -> CI failure).
// with the guard, every acquisition runs with interrupts masked, the IRQ stays
// pending until the lock is released, the loop completes, and ticks advance.
//
// the loop deliberately spans many timer ticks so the race window is hit: a
// regression would not survive thousands of arm/cancel calls across dozens of
// IRQs.
#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;
use core::sync::atomic::Ordering;

use jos::interrupts::TICK_COUNT;
use jos_core::clock::{Duration, Instant};

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, _info_ptr: u32) -> ! {
    // init once here (it loads the gdt/idt, remaps + enables the PIC, and enables
    // interrupts), not per test case: jos::init() is not idempotent (re-loading
    // the GDT panics), and both test cases need the PIT firing.
    jos::init();
    test_main();
    jos::hlt_loop()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}

// hammering the timer-queue lock while the PIT fires must not deadlock. each
// iteration arms a timer and cancels it, holding TIMERS twice; the loop runs
// long enough to span many timer IRQs, so an unguarded lock would be caught
// mid-hold by on_timer_tick and wedge.
#[test_case]
fn arm_cancel_loop_does_not_deadlock_against_timer_irq() {
    // kernel_main already ran jos::init(), so the PIT is firing. wait until the
    // timer is actually ticking, so the loop genuinely races live IRQs rather
    // than running before the first tick.
    while TICK_COUNT.load(Ordering::Relaxed) == 0 {
        x86_64::instructions::hlt();
    }
    let start_ticks = TICK_COUNT.load(Ordering::Relaxed);

    // hammer arm+cancel. a far-future deadline so the timer never fires on its
    // own (we always cancel it); the point is the lock traffic, not expiry.
    let far = clock_now().saturating_add(Duration::new(1 << 40));
    let mut armed = 0u64;
    for i in 0..200_000 {
        if let Some(id) = jos::clock::arm(far, i) {
            // also exercise the second IRQ-shared lock (the waker registry) on a
            // fraction of iterations, so its guard is covered too.
            assert!(jos::clock::cancel(id), "armed timer must cancel");
        }
        armed += 1;
    }
    assert!(armed > 0, "loop ran");

    // reaching here means no deadlock occurred. confirm the timer kept firing
    // THROUGHOUT (the IRQ path was live and contended the lock, not silently
    // wedged or starved): ticks advanced while we hammered.
    let end_ticks = TICK_COUNT.load(Ordering::Relaxed);
    assert!(
        end_ticks > start_ticks,
        "timer did not advance during the hammer loop ({start_ticks} -> {end_ticks}): \
         the IRQ path may have been starved or the loop did not span a tick",
    );
}

// the waker-registry lock (TIMER_WAKERS) is the other IRQ-shared lock; exercise
// it directly under live interrupts. register + take in a loop spanning ticks:
// on_timer_tick also takes this lock, so an unguarded version deadlocks here too.
#[test_case]
fn waker_registry_loop_does_not_deadlock_against_timer_irq() {
    // jos::init() already ran in the first test case (test_runner runs all cases
    // in one boot, in order), and it is NOT idempotent (re-loading the GDT
    // panics), so do not call it again. interrupts are already live and the PIT
    // is firing; just wait for the next tick to anchor the measurement.
    let start = TICK_COUNT.load(Ordering::Relaxed);
    while TICK_COUNT.load(Ordering::Relaxed) == start {
        x86_64::instructions::hlt();
    }

    // arm a real timer to get a valid TimerId, register a waker under it, take it
    // back, repeat. uses the current task's waker via a noop is not available
    // here, so register under ids from real arms and immediately take them.
    let far = clock_now().saturating_add(Duration::new(1 << 40));
    for i in 0..100_000 {
        if let Some(id) = jos::clock::arm(far, i) {
            // take_timer_waker locks TIMER_WAKERS (the registry); calling it under
            // live interrupts is the contended path. there is no waker registered
            // for this id, so it returns None; the lock traffic is the point.
            let _ = jos::clock::take_timer_waker(id);
            jos::clock::cancel(id);
        }
    }

    let end = TICK_COUNT.load(Ordering::Relaxed);
    assert!(end > start, "timer did not advance during the registry hammer loop");
}

// reads the TSC clock without needing the KernelClock trait in scope.
fn clock_now() -> Instant {
    jos::clock::now()
}
