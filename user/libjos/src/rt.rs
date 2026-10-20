//! The program entry points, halting, and the panic handler.
//!
//! The kernel starts the root task at its ELF entry point with the address of
//! a read-only [`BootInfo`] page in `rdi`. [`root_entry!`](crate::root_entry)
//! defines that entry point: a small naked stub that aligns the stack and
//! calls into Rust, which checks the boot information, points the console at
//! the root task's Console capability, and runs `main`.
//!
//! A process another program starts (see [`crate::process`]) finds a
//! [`ProcessStart`] at its initial stack pointer instead, and
//! [`process_entry!`](crate::process_entry) is its entry point: its `main`
//! returns an exit code, which the runtime sends to the parent.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::abi::{
    BOOT_INFO_MAGIC, BOOT_INFO_VERSION, BootInfo, PROCESS_START_MAGIC, ProcessStart, process_slot, root_slot,
};
use crate::sys::{self, Slot};

/// The machine slot plus one; zero means this program holds no machine
/// capability.
static MACHINE: AtomicU64 = AtomicU64::new(0);

/// Halt code for boot information that is not jos's.
const BAD_BOOT_INFO: u64 = 0xB0;

/// Halt code for a panic.
const PANICKED: u64 = 0xDEAD;

/// Checks the boot information the kernel handed the root task and sets up
/// the runtime from it: console output through the Console capability, and
/// [`halt`] through the Machine capability, both at their fixed slots.
///
/// # Safety
///
/// `boot` must be the address the kernel passed to the root task in `rdi`.
#[must_use]
pub unsafe fn init_root(boot: u64) -> &'static BootInfo {
    MACHINE.store(root_slot::MACHINE + 1, Ordering::Relaxed);
    // SAFETY: per the contract `boot` is where the kernel mapped the BootInfo
    // page, read-only for the root task's whole life.
    let info = unsafe { &*(boot as *const BootInfo) };
    if info.magic != BOOT_INFO_MAGIC || info.version != BOOT_INFO_VERSION {
        // without trustworthy boot information there is no console to report on.
        halt(BAD_BOOT_INFO);
    }
    crate::console::init(root_slot::CONSOLE);
    crate::mem::init(info);
    info
}

/// Checks the start record a process's spawner left at its initial stack
/// pointer and sets up the runtime: console output through the console it
/// was given ([`process_slot`]).
///
/// # Safety
///
/// `start` must be the stack pointer the process started with, where
/// `process::Process::spawn` wrote its [`ProcessStart`].
///
/// # Panics
///
/// If there is no start record there, which a spawned thread's panic turns
/// into a fault its parent hears of.
#[must_use]
pub unsafe fn init_process(start: u64) -> &'static ProcessStart {
    crate::console::init(process_slot::CONSOLE);
    // SAFETY: per the contract the record lies at `start`, at the top of the
    // process's stack, which is mapped for its whole life and never written.
    let info = unsafe { &*(start as *const ProcessStart) };
    assert!(info.magic == PROCESS_START_MAGIC, "no process start record at {start:#x}");
    info
}

/// Ends a process: sends `code` to its parent, then exits its thread.
pub fn exit_process(code: u64) -> ! {
    let _ = sys::send_blocking(process_slot::PARENT, code);
    sys::thread_exit()
}

/// Returns the machine capability's slot, if this program holds one.
#[must_use]
pub fn machine() -> Option<Slot> {
    MACHINE.load(Ordering::Relaxed).checked_sub(1)
}

/// Stops the machine with `code` (0 reports success) when this program holds
/// the machine capability; otherwise spins forever.
pub fn halt(code: u64) -> ! {
    if let Some(machine) = machine() {
        let _ = sys::machine_halt(machine, code);
    }
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // one diagnostic line: the default form puts the message on a line of its own.
    match info.location() {
        Some(at) => crate::println!("# panic at {}:{}: {}", at.file(), at.line(), info.message()),
        None => crate::println!("# panic: {}", info.message()),
    }
    // a spawned thread, or any thread of a process without the machine, stops
    // itself with a fault, so whoever handles its faults hears of it while
    // the rest runs on; the root task's first thread has no fault handler, and
    // stops the machine.
    if crate::thread::is_spawned() || machine().is_none() {
        // SAFETY: ud2 raises an invalid-opcode fault and touches nothing else.
        unsafe { core::arch::asm!("ud2", options(nomem, nostack)) };
    }
    halt(PANICKED)
}

/// Defines the root task's entry point: `$main` is a function taking
/// `&'static BootInfo` and never returning.
#[macro_export]
macro_rules! root_entry {
    ($main:path) => {
        // SAFETY: the kernel starts the root task here with the BootInfo address
        // in rdi. the stub clears rbp for unwinders, aligns the stack as the
        // System V ABI expects before a call, and passes rdi on untouched; no
        // other item defines `_start`.
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        unsafe extern "C" fn _start() -> ! {
            core::arch::naked_asm!(
                "xor ebp, ebp",
                "and rsp, -16",
                "call {main}",
                "ud2",
                main = sym __libjos_root_main,
            )
        }

        /// Sets up the runtime from the boot information, then runs the
        /// program's main function.
        extern "C" fn __libjos_root_main(boot: u64) -> ! {
            // SAFETY: `_start` passes on the rdi the kernel set: the BootInfo
            // address.
            let boot = unsafe { $crate::rt::init_root(boot) };
            $main(boot)
        }
    };
}

/// Defines a process's entry point: `$main` takes the
/// [`ProcessStart`](crate::abi::ProcessStart) and returns the process's exit
/// code, which the runtime sends to its parent before the process exits.
#[macro_export]
macro_rules! process_entry {
    ($main:path) => {
        // SAFETY: the spawner starts the process here with its stack pointer
        // at the ProcessStart it wrote. the stub passes that address on in
        // rdi, clears rbp for unwinders, and aligns the stack for the call;
        // the record lies above the new stack top, so nothing overwrites it.
        // no other item defines `_start`.
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        unsafe extern "C" fn _start() -> ! {
            core::arch::naked_asm!(
                "mov rdi, rsp",
                "xor ebp, ebp",
                "and rsp, -16",
                "call {main}",
                "ud2",
                main = sym __libjos_process_main,
            )
        }

        /// Sets up the runtime from the start record, runs the program's main
        /// function, and reports its exit code to the parent.
        extern "C" fn __libjos_process_main(start: u64) -> ! {
            // SAFETY: `_start` passes on the stack pointer the process started
            // with, where its spawner wrote the start record.
            let start = unsafe { $crate::rt::init_process(start) };
            $crate::rt::exit_process($main(start))
        }
    };
}
