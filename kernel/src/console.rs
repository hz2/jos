//! Console input: bytes typed at the serial console, kept for a reader.
//!
//! The UART raises IRQ4 once it has received bytes. The interrupt handler
//! moves them out of its receive FIFO into a small ring buffer, then hands what
//! it can to a thread parked in `console_read` (`syscall::console_input_arrived`).
//! A reader that finds bytes waiting takes them at once. Bytes that arrive while
//! the buffer is full are dropped, and counted.
//!
//! The buffer is locked by the receive interrupt and by syscalls, both with
//! interrupts disabled; [`take`] disables them for other callers, and the
//! interrupt side only tries the lock, so no path can spin on it forever.

use core::sync::atomic::{AtomicU64, Ordering};

use jos_core::ring_buffer::RingBuffer;
use spin::Mutex;
use x86_64::instructions::interrupts;
use x86_64::instructions::port::Port;

/// Bytes of input kept for a reader: a few lines of typing.
pub const INPUT_BYTES: usize = 256;

/// Received bytes no thread has read yet.
static INPUT: Mutex<RingBuffer<u8, INPUT_BYTES>> = Mutex::new(RingBuffer::new());

/// Bytes dropped because the buffer was full.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// COM1's line status register: bit 0 is set while a received byte waits.
const LINE_STATUS: u16 = 0x3FD;

/// COM1's receive buffer register.
const RECEIVE: u16 = 0x3F8;

/// Moves every byte the UART holds into the input buffer, then offers the
/// input to a parked reader. Called from the COM1 interrupt handler.
pub fn on_receive() {
    let mut status: Port<u8> = Port::new(LINE_STATUS);
    let mut data: Port<u8> = Port::new(RECEIVE);
    loop {
        // SAFETY: reading COM1's line status register has no side effect but
        // clearing its error bits, which nothing reads.
        if unsafe { status.read() } & 1 == 0 {
            break;
        }
        // SAFETY: a byte is waiting, and reading the receive register takes it
        // out of the FIFO, which is what draining means.
        let byte = unsafe { data.read() };
        let stored = INPUT.try_lock().is_some_and(|mut input| input.push(byte).is_ok());
        if !stored {
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }
    crate::syscall::console_input_arrived();
}

/// Moves up to `out.len()` waiting bytes into `out`, oldest first, and returns
/// how many.
pub fn take(out: &mut [u8]) -> usize {
    interrupts::without_interrupts(|| fill(&mut INPUT.lock(), out))
}

/// Like [`take`], from interrupt context: `None` if the buffer is locked.
pub fn try_take(out: &mut [u8]) -> Option<usize> {
    INPUT.try_lock().map(|mut input| fill(&mut input, out))
}

/// Returns whether input is waiting, or `None` if the buffer is locked.
pub fn try_pending() -> Option<bool> {
    INPUT.try_lock().map(|input| !input.is_empty())
}

/// Returns how many bytes were dropped because the buffer was full.
#[must_use]
pub fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

/// Pops bytes from `input` into `out` until either runs out.
fn fill(input: &mut RingBuffer<u8, INPUT_BYTES>, out: &mut [u8]) -> usize {
    let mut count = 0;
    for slot in out.iter_mut() {
        let Some(byte) = input.pop() else { break };
        *slot = byte;
        count += 1;
    }
    count
}
