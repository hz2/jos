// tests/keyboard_stream.rs
//
// slice 2c: the keyboard IRQ no longer decodes inline; it pushes raw scancodes
// onto a lock-free queue and wakes a decoder task (the async ScancodeStream
// pattern). a headless test cannot press physical keys, so it drives the seam
// directly: add_scancode() is exactly what the IRQ handler calls, so feeding it
// scancodes and draining the stream on the executor exercises the whole
// queue -> waker -> stream -> decode path that real keystrokes would.
//
// proves: scancodes enqueued before a consumer exists are still delivered in
// order; a stream parked on the empty queue is woken by a later add_scancode;
// and the pc-keyboard decode (run on the executor, off the interrupt) turns the
// scancode bytes into the expected characters.
#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use alloc::rc::Rc;
use alloc::string::String;
use core::cell::RefCell;
use core::panic::PanicInfo;

use futures_util::stream::StreamExt;
use jos::executor::{Executor, Task};
use jos::keyboard::{add_scancode, ScancodeStream};

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    jos::init();
    // SAFETY: boot.s identity-maps the first 1 GiB; called once before test_main.
    unsafe {
        let mut mapper = jos::memory::init_mapper();
        let mut frame_allocator = jos::memory::BootstrapFrameAllocator::new(info_ptr);
        jos::allocator::init_heap(&mut mapper, &mut frame_allocator).expect("heap init failed");
    }
    // the scancode queue allocates, so it is initialized after the heap is up,
    // exactly as the real kernel main will order it.
    jos::keyboard::init();
    test_main();
    jos::hlt_loop()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}

// scancodes pushed BEFORE the consumer runs are buffered and then drained in
// fifo order: the stream yields them oldest-first. (set-1 make codes for keys.)
#[test_case]
fn buffered_scancodes_drain_in_order() {
    // 0x1E,0x30,0x2E = make codes for 'a','b','c' in scancode set 1.
    let codes = [0x1E_u8, 0x30, 0x2E];
    for &c in &codes {
        add_scancode(c);
    }

    let got: Rc<RefCell<alloc::vec::Vec<u8>>> = Rc::new(RefCell::new(alloc::vec::Vec::new()));
    let got_in_task = got.clone();

    let mut executor = Executor::new();
    executor
        .spawn(Task::new(async move {
            let mut stream = ScancodeStream::new();
            // pull exactly the three buffered bytes, then stop (the stream never
            // ends on its own; a test task must bound itself).
            for _ in 0..3 {
                let b = stream.next().await.expect("stream yields buffered byte");
                got_in_task.borrow_mut().push(b);
            }
        }))
        .unwrap();

    executor.run_until_idle();
    assert_eq!(&got.borrow()[..], &codes[..]);
}

// a consumer parked on the empty queue is woken by a later add_scancode: spawn a
// task that awaits one byte (parks, since the queue is empty), drive the
// executor to quiescence, then feed a byte and drive again. the byte must be
// delivered, proving the IRQ-side wake reaches the parked stream.
#[test_case]
fn parked_consumer_is_woken_by_later_scancode() {
    let got: Rc<RefCell<Option<u8>>> = Rc::new(RefCell::new(None));
    let got_in_task = got.clone();

    let mut executor = Executor::new();
    executor
        .spawn(Task::new(async move {
            let mut stream = ScancodeStream::new();
            let b = stream.next().await.expect("stream yields after wake");
            *got_in_task.borrow_mut() = Some(b);
        }))
        .unwrap();

    // first drive: the queue is empty, so the task parks in poll_next.
    executor.run_until_idle();
    assert!(got.borrow().is_none(), "consumer should be parked, nothing delivered yet");

    // simulate an IRQ delivering a scancode; this wakes the parked stream.
    add_scancode(0x1E); // 'a' make code
    executor.run_until_idle();
    assert_eq!(*got.borrow(), Some(0x1E));
}

// the decode path (pc-keyboard) run on the executor turns scancode bytes into
// characters: feed the make/break sequence for "ok" and assert the decoder task
// produced exactly those characters. this is print_keypresses' logic, capturing
// the output instead of printing it.
#[test_case]
fn decoder_task_turns_scancodes_into_characters() {
    use pc_keyboard::{layouts, DecodedKey, HandleControl, Keyboard, ScancodeSet1};

    // set-1: 'o' make=0x18 break=0x98, 'k' make=0x25 break=0xA5.
    let sequence = [0x18_u8, 0x98, 0x25, 0xA5];
    for &c in &sequence {
        add_scancode(c);
    }

    let typed: Rc<RefCell<String>> = Rc::new(RefCell::new(String::new()));
    let typed_in_task = typed.clone();

    let mut executor = Executor::new();
    executor
        .spawn(Task::new(async move {
            let mut stream = ScancodeStream::new();
            let mut keyboard =
                Keyboard::new(layouts::Us104Key, ScancodeSet1, HandleControl::Ignore);
            for _ in 0..sequence.len() {
                let scancode = stream.next().await.expect("buffered scancode");
                if let Ok(Some(event)) = keyboard.add_byte(scancode)
                    && let Some(DecodedKey::Unicode(c)) = keyboard.process_keyevent(event)
                {
                    typed_in_task.borrow_mut().push(c);
                }
            }
        }))
        .unwrap();

    executor.run_until_idle();
    assert_eq!(typed.borrow().as_str(), "ok");
}
