//! Console output through a Console capability.
//!
//! The kernel never reads a user pointer: a program copies the bytes into the
//! data area of its own IPC buffer and passes only their length. [`print!`]
//! and [`println!`](crate::println) format into a small stack buffer first, so
//! a typical line costs one syscall.

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::abi::IpcSyscallError;
use crate::sys::{self, Slot};
use jos_core::ipc_buffer::{DATA_LEN, DATA_OFFSET};

/// The console slot plus one; zero means this program has no console.
static CONSOLE: AtomicU64 = AtomicU64::new(0);

/// Virtual address of this thread's IPC buffer; zero means none.
static IPC_BUFFER: AtomicU64 = AtomicU64::new(0);

/// Points console output at the capability in `console`, writing through the
/// IPC buffer mapped at `ipc_buffer`.
pub fn init(console: Slot, ipc_buffer: u64) {
    IPC_BUFFER.store(ipc_buffer, Ordering::Relaxed);
    CONSOLE.store(console + 1, Ordering::Relaxed);
}

/// Returns the virtual address of this thread's IPC buffer, if it has one.
#[must_use]
pub fn ipc_buffer() -> Option<u64> {
    match IPC_BUFFER.load(Ordering::Relaxed) {
        0 => None,
        addr => Some(addr),
    }
}

/// Writes `bytes` to the console, one data-area-sized chunk per syscall.
///
/// # Errors
///
/// [`IpcSyscallError::BadCap`] if there is no console, or why the kernel
/// refused the write.
pub fn write_bytes(bytes: &[u8]) -> Result<(), IpcSyscallError> {
    let console = CONSOLE.load(Ordering::Relaxed).checked_sub(1).ok_or(IpcSyscallError::BadCap)?;
    let buffer = ipc_buffer().ok_or(IpcSyscallError::NoIpcBuffer)?;
    let data = usize::try_from(buffer).map_err(|_| IpcSyscallError::NoIpcBuffer)? + DATA_OFFSET;
    for chunk in bytes.chunks(DATA_LEN) {
        // SAFETY: the IPC buffer is a writable page mapped at `buffer` for this
        // thread, so the data area holds DATA_LEN bytes from `data`, and no
        // reference into it is live; a chunk is at most DATA_LEN bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(chunk.as_ptr(), data as *mut u8, chunk.len());
        }
        sys::console_write(console, chunk.len())?;
    }
    Ok(())
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
