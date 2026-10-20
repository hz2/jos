//! Console output and input through a Console capability.
//!
//! The kernel never reads a user pointer: a program copies the bytes into the
//! data area of its own IPC buffer and passes only their length. Each thread
//! finds its IPC buffer from its stack pointer: every thread runs in a thread
//! block (`abi::layout::THREAD_BLOCK`), and the buffer sits at a fixed offset
//! in it, so threads sharing an address space never write each other's
//! buffers. [`print!`] and [`println!`](crate::println) format into a small
//! stack buffer first, so a typical line costs one syscall.

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::abi::layout::{THREAD_BLOCK, THREAD_IPC_BUFFER};
use crate::abi::{IpcSyscallError, NO_TIMEOUT};
use crate::sys::{self, Slot};
use jos_core::ipc_buffer::{DATA_LEN, DATA_OFFSET};
use jos_core::line::{Edit, LineEditor};

/// The console slot plus one; zero means this program has no console.
static CONSOLE: AtomicU64 = AtomicU64::new(0);

/// Points console output at the capability in `console`, for every thread of
/// this program.
pub fn init(console: Slot) {
    CONSOLE.store(console + 1, Ordering::Relaxed);
}

/// Returns the slot of the console capability output goes to, if there is one.
#[must_use]
pub fn slot() -> Option<Slot> {
    CONSOLE.load(Ordering::Relaxed).checked_sub(1)
}

/// Returns the virtual address of the calling thread's IPC buffer: the fixed
/// offset in the thread block its stack lives in.
#[must_use]
pub fn ipc_buffer() -> u64 {
    let rsp: u64;
    // SAFETY: reads the stack pointer and nothing else.
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)) };
    (rsp & !(THREAD_BLOCK - 1)) + THREAD_IPC_BUFFER
}

/// Writes `bytes` to the console, one data-area-sized chunk per syscall.
///
/// # Errors
///
/// [`IpcSyscallError::BadCap`] if there is no console, or why the kernel
/// refused the write.
pub fn write_bytes(bytes: &[u8]) -> Result<(), IpcSyscallError> {
    let console = CONSOLE.load(Ordering::Relaxed).checked_sub(1).ok_or(IpcSyscallError::BadCap)?;
    let data = usize::try_from(ipc_buffer()).map_err(|_| IpcSyscallError::NoIpcBuffer)? + DATA_OFFSET;
    for chunk in bytes.chunks(DATA_LEN) {
        // SAFETY: the thread block convention maps this thread's IPC buffer
        // writable at that address, so the data area holds DATA_LEN bytes from
        // `data`, and no reference into it is live; a chunk is at most DATA_LEN
        // bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(chunk.as_ptr(), data as *mut u8, chunk.len());
        }
        sys::console_write(console, chunk.len())?;
    }
    Ok(())
}

/// What erasing a character echoes: back, blank it, back again.
const ERASE: &[u8] = b"\x08 \x08";

/// Reads console input into `buf`: what is waiting, or else the first bytes
/// to arrive within `ms` milliseconds ([`NO_TIMEOUT`] waits for as long as it
/// takes). Returns how many bytes it read.
///
/// # Errors
///
/// [`IpcSyscallError::TimedOut`] (or [`IpcSyscallError::WouldBlock`] for an
/// `ms` of 0) if nothing came, [`IpcSyscallError::BadCap`] if there is no
/// console, or why the kernel refused the read.
pub fn read(buf: &mut [u8], ms: u64) -> Result<usize, IpcSyscallError> {
    let console = CONSOLE.load(Ordering::Relaxed).checked_sub(1).ok_or(IpcSyscallError::BadCap)?;
    let data = usize::try_from(ipc_buffer()).map_err(|_| IpcSyscallError::NoIpcBuffer)? + DATA_OFFSET;
    let max = buf.len().min(DATA_LEN);
    let count = usize::try_from(sys::console_read(console, max, ms)?).map_or(0, |count| count.min(max));
    // SAFETY: as in write_bytes, the data area holds DATA_LEN bytes from
    // `data`; the kernel wrote the first `count` of them, and no reference
    // into it is live.
    unsafe {
        core::ptr::copy_nonoverlapping(data as *const u8, buf.as_mut_ptr(), count);
    }
    Ok(count)
}

/// Reads one line into `editor`, echoing it as it is typed: each character,
/// each erase, and the end of the line. Returns `true` when Enter ended it,
/// with the line in [`LineEditor::line`], and `false` when Ctrl-C abandoned it.
///
/// It takes a byte at a time, so input typed ahead of the next line stays in
/// the kernel's buffer for that line.
///
/// # Errors
///
/// Why the console refused a read or a write.
pub fn read_line<const N: usize>(editor: &mut LineEditor<N>) -> Result<bool, IpcSyscallError> {
    editor.clear();
    loop {
        let mut byte = [0];
        if read(&mut byte, NO_TIMEOUT)? == 0 {
            continue;
        }
        match editor.feed(byte[0]) {
            Edit::Typed(typed) => write_bytes(&[typed])?,
            Edit::Erased => write_bytes(ERASE)?,
            Edit::Cleared(count) => {
                for _ in 0..count {
                    write_bytes(ERASE)?;
                }
            }
            // the terminal bell.
            Edit::Full => write_bytes(b"\x07")?,
            Edit::Done => {
                write_bytes(b"\n")?;
                return Ok(true);
            }
            Edit::Interrupted => {
                write_bytes(b"^C\n")?;
                return Ok(false);
            }
            Edit::Nothing => {}
        }
    }
}

/// Collects formatted output into one buffer, so a line is one syscall.
struct LineBuffer {
    /// The pending bytes.
    bytes: [u8; 256],
    /// How many of `bytes` are pending.
    len: usize,
}

impl LineBuffer {
    /// Prints the pending bytes and empties the buffer.
    fn flush(&mut self) -> fmt::Result {
        let pending = &self.bytes[..self.len];
        self.len = 0;
        write_bytes(pending).map_err(|_| fmt::Error)
    }
}

impl fmt::Write for LineBuffer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &byte in s.as_bytes() {
            if self.len == self.bytes.len() {
                self.flush()?;
            }
            self.bytes[self.len] = byte;
            self.len += 1;
        }
        Ok(())
    }
}

/// Prints formatted arguments to the console; the backend of [`print!`].
#[doc(hidden)]
pub fn print_args(args: fmt::Arguments) {
    let mut out = LineBuffer { bytes: [0; 256], len: 0 };
    // output is best effort: a program without a console prints nothing.
    let _ = fmt::write(&mut out, args);
    let _ = out.flush();
}

/// Prints to the console.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::console::print_args(format_args!($($arg)*))
    };
}

/// Prints to the console, with a newline.
#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n")
    };
    ($($arg:tt)*) => {
        $crate::console::print_args(format_args!("{}\n", format_args!($($arg)*)))
    };
}
