//! Threads: starting more threads in this program's capability space and
//! address space.
//!
//! A thread is made of capabilities the program retypes itself: a TCB, its
//! stack frames, and its IPC buffer frame, mapped into a fresh thread block
//! (`abi::layout::THREAD_BLOCK`) so it finds its own IPC buffer from its stack
//! pointer. [`Thread::reap`] revokes all of them, which stops the thread and
//! unmaps its pages.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::abi::layout::{
    THREAD_BLOCK, THREAD_BLOCKS_END, THREAD_BLOCKS_START, THREAD_IPC_BUFFER, THREAD_STACK,
    THREAD_STACK_PAGES,
};
use crate::abi::{Syscall, root_slot};
use crate::mem::{self, Error};
use crate::sys::{self, Slot};
use jos_core::untyped::ObjectType;

/// The function a new thread runs, given the argument it was started with;
/// the thread exits when it returns.
pub type Entry = extern "C" fn(u64);

/// Pages of stack a thread gets unless it asks for more.
pub const STACK_PAGES: u64 = 4;

/// Room for a full stack plus the IPC buffer frame.
const MAX_FRAMES: usize = 17;
const _: () = assert!(MAX_FRAMES as u64 == THREAD_STACK_PAGES + 1);

/// The next unused thread block.
static NEXT_BLOCK: AtomicU64 = AtomicU64::new(THREAD_BLOCKS_START);

/// A thread this program started, and the capabilities it is made of.
pub struct Thread {
    /// Its TCB, once retyped.
    tcb: Option<Slot>,
    /// Its stack frames, then its IPC buffer frame.
    frames: [Slot; MAX_FRAMES],
    /// How many entries of `frames` are live.
    frame_count: usize,
}

impl Thread {
    /// Starts a thread running `entry(arg)` on a stack of `stack_pages` pages
    /// (1 to 16), in this program's capability space and address space.
    ///
    /// # Errors
    ///
    /// Why a slot, an object, a mapping, or the start was refused; whatever
    /// was built by then is revoked again.
    pub fn spawn(entry: Entry, arg: u64, stack_pages: u64) -> Result<Self, Error> {
        Self::spawn_with(entry, arg, stack_pages, None)
    }

    /// Like [`spawn`](Self::spawn), and sends the thread's faults to the
    /// endpoint in slot `fault_handler` (see [`sys::tcb_set_fault_handler`]).
    ///
    /// # Errors
    ///
    /// As [`spawn`](Self::spawn).
    pub fn spawn_with(entry: Entry, arg: u64, stack_pages: u64, fault_handler: Option<Slot>) -> Result<Self, Error> {
        let block = NEXT_BLOCK.fetch_add(THREAD_BLOCK, Ordering::Relaxed);
        if block >= THREAD_BLOCKS_END {
            return Err(Error::NoMemory);
        }
        let mut thread = Self { tcb: None, frames: [0; MAX_FRAMES], frame_count: 0 };
        match thread.build(block, entry, arg, stack_pages.clamp(1, THREAD_STACK_PAGES), fault_handler) {
            Ok(()) => Ok(thread),
            Err(e) => {
                thread.release();
                Err(e)
            }
        }
    }

    /// Returns the slot of the thread's TCB.
    #[must_use]
    pub fn tcb(&self) -> Option<Slot> {
        self.tcb
    }

    /// Stops the thread for good and frees every capability it was made of.
    pub fn reap(mut self) {
        self.release();
    }

    /// Maps the stack and IPC buffer, then configures and starts the TCB.
    fn build(&mut self, block: u64, entry: Entry, arg: u64, pages: u64, fault_handler: Option<Slot>) -> Result<(), Error> {
        let stack_top = block + THREAD_STACK + THREAD_STACK_PAGES * 0x1000;
        for page in 1..=pages {
            self.frames[self.frame_count] = mem::map_new_page(stack_top - page * 0x1000)?;
            self.frame_count += 1;
        }
        let ipc_buffer = mem::map_new_page(block + THREAD_IPC_BUFFER)?;
        self.frames[self.frame_count] = ipc_buffer;
        self.frame_count += 1;
        let tcb = mem::retype(ObjectType::Tcb)?;
        self.tcb = Some(tcb);
        sys::tcb_configure(tcb, root_slot::CNODE, root_slot::VSPACE)?;
        if let Some(handler) = fault_handler {
            sys::tcb_set_fault_handler(tcb, handler)?;
        }
        sys::tcb_set_ipc_buffer(tcb, ipc_buffer)?;
        // the trampoline pops the entry and its argument off the new stack.
        let words = (stack_top - 16) as *mut u64;
        // SAFETY: the top stack page was just mapped writable at these
        // addresses, and the thread that will use it has not started.
        unsafe {
            words.write(entry as usize as u64);
            words.add(1).write(arg);
        }
        let start = trampoline as extern "C" fn() -> !;
        sys::tcb_start(tcb, start as usize as u64, stack_top - 16)?;
        Ok(())
    }

    /// Revokes the TCB first (which stops the thread), then every frame.
    fn release(&mut self) {
        if let Some(tcb) = self.tcb.take() {
            let _ = mem::release(tcb);
        }
        for &frame in &self.frames[..self.frame_count] {
            let _ = mem::release(frame);
        }
        self.frame_count = 0;
    }
}

/// The first instruction of every thread [`Thread::spawn`] starts: pops the
/// entry and its argument the spawner left on the stack, calls the entry, and
/// exits the thread when it returns.
#[unsafe(naked)]
extern "C" fn trampoline() -> ! {
    core::arch::naked_asm!(
        "pop rax",
        "pop rdi",
        "xor ebp, ebp",
        "and rsp, -16",
        "call rax",
        "mov eax, {exit}",
        "syscall",
        "ud2",
        exit = const Syscall::ThreadExit as u32,
    )
}
