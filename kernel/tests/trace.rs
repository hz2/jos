// tests/trace.rs
//
// in-kernel structured tracing, headless: every system call that crosses the
// dispatcher (the mandatory capability chokepoint) is recorded into a per-CPU
// ring buffer as a SyscallEvent. this drives the REAL dispatch path via the
// dispatch_for_test seam (the same function a `syscall` instruction reaches,
// including the trace tap) and asserts the buffer captured each call faithfully:
// the syscall number, its arguments, the value returned to userspace, and a
// monotone sequence number. it then confirms the recording order is the drain
// (replay) order, and that the overwrite-oldest policy keeps the most recent
// window once the buffer fills.
//
// the buffer mechanics (FIFO, overwrite, monotone seq) are also unit-tested in
// kernel/src/trace.rs; this test proves the WIRING: that real dispatched
// syscalls actually land in the trace, with the right fields.
#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;

use jos::serial_println;
use jos::syscall::{dispatch_for_test, Syscall};
use jos::trace::{self, TRACE_CAPACITY};
use jos_core::trace::SyscallEvent;

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, _info_ptr: u32) -> ! {
    jos::init();
    test_main();
    jos::hlt_loop()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}

// drains the whole trace buffer into a small fixed array (no heap in these
// tests). returns the count drained; events[..count] are in record order.
fn drain_all(events: &mut [SyscallEvent]) -> usize {
    trace::with_buffer(|buf| {
        let mut n = 0;
        while n < events.len() {
            match buf.drain_oldest() {
                Some(ev) => {
                    events[n] = ev;
                    n += 1;
                }
                None => break,
            }
        }
        n
    })
}

// clears any events left by a prior test so each test sees only its own. the
// trace buffer is a single global, and the test_runner runs cases in sequence.
fn clear_trace() {
    trace::with_buffer(|buf| while buf.drain_oldest().is_some() {});
}

// a real, dispatched SYS_ADD is recorded with its number, args, and result.
// SYS_ADD is a pure probe (no capability state), so it isolates the trace tap.
#[test_case]
fn dispatched_add_is_recorded() {
    clear_trace();
    let result = dispatch_for_test(Syscall::Add as u64, 0x100, 0x23, 0);
    assert_eq!(result, 0x123, "SYS_ADD should return the sum");

    let mut events = [SyscallEvent::new(0, 0, [0; 3], 0); 4];
    let n = drain_all(&mut events);
    assert_eq!(n, 1, "exactly one syscall was dispatched");
    let ev = events[0];
    assert_eq!(ev.syscall, Syscall::Add as u64, "recorded the right syscall number");
    assert_eq!(ev.args, [0x100, 0x23, 0], "recorded the raw arguments");
    assert_eq!(ev.result, 0x123, "recorded the value returned to userspace");
    serial_println!("[trace] recorded SYS_ADD seq={} result={:#x}", ev.seq, ev.result);
}

// several dispatched syscalls are recorded in order, with strictly increasing
// sequence numbers (the total order replay relies on).
#[test_case]
fn dispatch_order_and_monotone_seq() {
    clear_trace();
    // a mix of recordable syscalls (avoid Exit, which diverges). an unknown
    // number is recorded verbatim too (it returns ENOSYS, not dropped).
    let _ = dispatch_for_test(Syscall::Add as u64, 1, 2, 0);
    let _ = dispatch_for_test(Syscall::Add as u64, 10, 20, 0);
    let _ = dispatch_for_test(0xDEAD, 0, 0, 0); // unknown -> ENOSYS, still traced

    let mut events = [SyscallEvent::new(0, 0, [0; 3], 0); 8];
    let n = drain_all(&mut events);
    assert_eq!(n, 3, "all three dispatches recorded");
    // record order == drain order, with strictly increasing seq.
    assert_eq!(events[0].args, [1, 2, 0]);
    assert_eq!(events[0].result, 3);
    assert_eq!(events[1].args, [10, 20, 0]);
    assert_eq!(events[1].result, 30);
    assert_eq!(events[2].syscall, 0xDEAD, "an unknown syscall is recorded, not dropped");
    assert!(
        events[0].seq < events[1].seq && events[1].seq < events[2].seq,
        "sequence numbers must be strictly increasing in dispatch order",
    );
}

// once the buffer fills, the oldest events are overwritten and counted, so a
// busy syscall stream keeps the most recent window rather than going deaf.
#[test_case]
fn full_buffer_overwrites_oldest() {
    clear_trace();
    let before_dropped = trace::with_buffer(|buf| buf.dropped());
    // dispatch more than the buffer can hold; tag each with a distinct arg so we
    // can identify which survived.
    let total = (TRACE_CAPACITY + 5) as u64;
    for i in 0..total {
        let _ = dispatch_for_test(Syscall::Add as u64, i, 0, 0);
    }
    let (len, dropped) = trace::with_buffer(|buf| (buf.len(), buf.dropped()));
    assert_eq!(len, TRACE_CAPACITY, "buffer is capped at its capacity");
    assert_eq!(dropped - before_dropped, 5, "the five oldest events were overwritten");

    // the oldest retained event is the 6th dispatched (arg == 5): the first five
    // (args 0..5) were overwritten.
    let oldest = trace::with_buffer(|buf| buf.drain_oldest()).expect("event present");
    assert_eq!(oldest.args[0], 5, "the five oldest events should have been dropped");
}

// off-box capture: events recorded on the real dispatch path survive a postcard
// COBS-frame encode and decode unchanged. this is the round trip a host capture
// tool performs (drain -> frame -> serial -> decode), proving the serialized
// form is a faithful, reconstructable record of what crossed the boundary.
#[test_case]
fn recorded_events_survive_postcard_round_trip() {
    use jos_core::trace::codec::{self, MAX_FRAMED_EVENT_LEN};

    clear_trace();
    // dispatch a few real syscalls with distinctive arguments.
    let _ = dispatch_for_test(Syscall::Add as u64, 0xCAFE, 0xBABE, 0);
    let _ = dispatch_for_test(Syscall::Add as u64, 1, 2, 0);

    // drain and round-trip each event: encode it as a framed record, decode the
    // frame back, and assert the decoded event equals the original.
    let mut events = [SyscallEvent::new(0, 0, [0; 3], 0); 4];
    let n = drain_all(&mut events);
    assert_eq!(n, 2, "two syscalls were dispatched");
    for original in &events[..n] {
        let mut buf = [0u8; MAX_FRAMED_EVENT_LEN];
        let framed = codec::encode_framed(original, &mut buf).expect("encode fits");
        // a real frame is COBS-delimited by a trailing zero.
        assert_eq!(framed.last(), Some(&0), "framed record ends in the COBS delimiter");
        let (decoded, rest) = codec::decode_framed(framed).expect("decode the frame");
        assert_eq!(&decoded, original, "the decoded event must match what was recorded");
        assert!(rest.is_empty(), "one frame, no trailing bytes");
    }
    serial_println!("[trace] {} events survived the postcard round trip", n);
}

// dump_trace_hex drains the buffer and reports how many events it emitted; an
// empty buffer dumps nothing. (the hex output itself goes to the serial log for
// a host tool; here we just confirm the drain count and that it empties.)
#[test_case]
fn dump_trace_hex_drains_and_counts() {
    clear_trace();
    let _ = dispatch_for_test(Syscall::Add as u64, 7, 8, 0);
    let _ = dispatch_for_test(Syscall::Add as u64, 9, 10, 0);
    let _ = dispatch_for_test(Syscall::Add as u64, 11, 12, 0);
    let dumped = trace::dump_trace_hex();
    assert_eq!(dumped, 3, "dump should emit every recorded event");
    // the buffer is now empty, so a second dump emits nothing.
    assert_eq!(trace::dump_trace_hex(), 0, "a drained buffer dumps nothing");
}
