// tests/executor.rs
//
// boots the cooperative async executor headless under QEMU and proves it drives
// in-kernel async tasks to completion: a spawned future runs, yield_now parks
// and resumes a task through the full waker -> inbox -> ready-queue path, many
// tasks interleave, and a finished task frees its slot. this is slice 2a: the
// async-as-scheduler north star running on real (emulated) hardware.
//
// the verified scheduling model (RunQueue) is proven in jos-core under
// Kani/Miri; this test wires the kernel executor (heap, Arc wakers, hlt) to it
// and confirms the glue behaves.
#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

use jos::executor::{yield_now, Executor, Task, MAX_TASKS};

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    jos::init();
    // the executor allocates (Box-pinned futures, Arc wakers, the inbox), so the
    // heap must be live before any test runs. set it up once here, mirroring
    // tests/paging_heap.rs.
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

// a single spawned task runs to completion when the executor is driven.
#[test_case]
fn single_task_runs_to_completion() {
    let ran = Arc::new(AtomicU32::new(0));
    let ran_in_task = ran.clone();

    let mut executor = Executor::new();
    executor
        .spawn(Task::new(async move {
            ran_in_task.fetch_add(1, Ordering::SeqCst);
        }))
        .expect("spawn should succeed");

    // before running, nothing has executed.
    assert_eq!(ran.load(Ordering::SeqCst), 0);
    executor.run_until_idle();
    // the task body ran exactly once.
    assert_eq!(ran.load(Ordering::SeqCst), 1);
}

// yield_now parks the task and resumes it: the body observes execution on both
// sides of the yield, exercising the waker -> inbox -> ready-queue requeue path.
#[test_case]
fn yield_now_parks_and_resumes() {
    let stage = Arc::new(AtomicU32::new(0));
    let stage_in_task = stage.clone();

    let mut executor = Executor::new();
    executor
        .spawn(Task::new(async move {
            stage_in_task.store(1, Ordering::SeqCst);
            yield_now().await;
            stage_in_task.store(2, Ordering::SeqCst);
        }))
        .unwrap();

    executor.run_until_idle();
    // run_until_idle drains the requeue from yield_now, so the task reaches the
    // far side of the yield: stage advances all the way to 2.
    assert_eq!(stage.load(Ordering::SeqCst), 2);
}

// many independent tasks all complete, and each runs exactly once. the shared
// counter ends at the task count, proving none were dropped or double-run.
#[test_case]
fn many_tasks_all_complete() {
    const TASKS: u32 = 20;
    let count = Arc::new(AtomicU32::new(0));

    let mut executor = Executor::new();
    for _ in 0..TASKS {
        let c = count.clone();
        executor
            .spawn(Task::new(async move {
                // yield once so the tasks interleave rather than each running
                // straight through; all must still complete.
                yield_now().await;
                c.fetch_add(1, Ordering::SeqCst);
            }))
            .unwrap();
    }

    executor.run_until_idle();
    assert_eq!(count.load(Ordering::SeqCst), TASKS);
}

// a completed task frees its slot, so the executor can be refilled to capacity
// again afterward. this checks the slot-reclaim path (tasks[slot] = None on
// completion) against the fixed MAX_TASKS bound.
#[test_case]
fn completed_tasks_free_their_slots() {
    let mut executor = Executor::new();

    // fill every slot, run them all to completion (freeing every slot), then
    // confirm the executor accepts a full fresh batch.
    for _ in 0..MAX_TASKS {
        executor.spawn(Task::new(async {})).expect("slot should be free");
    }
    executor.run_until_idle();

    for _ in 0..MAX_TASKS {
        executor
            .spawn(Task::new(async {}))
            .expect("slots should be free again after completion");
    }
    executor.run_until_idle();
}

// spawning past capacity is rejected (the task is handed back), not a panic or
// silent drop. confirms the Err path of spawn.
#[test_case]
fn spawn_past_capacity_is_rejected() {
    let mut executor = Executor::new();
    // pending tasks that never complete, so slots stay occupied.
    for _ in 0..MAX_TASKS {
        executor
            .spawn(Task::new(async {
                core::future::pending::<()>().await;
            }))
            .expect("slot should be free");
    }
    // the next spawn has no free slot and must return the task back.
    let overflow = executor.spawn(Task::new(async {}));
    assert!(overflow.is_err());
}
