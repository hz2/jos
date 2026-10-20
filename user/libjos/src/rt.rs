//! The program entry point, halting, and the panic handler.
//!
//! The kernel starts the root task at its ELF entry point with the address of
//! a read-only [`BootInfo`] page in `rdi`. [`root_entry!`](crate::root_entry)
//! defines that entry point for a program: a small naked stub that aligns the
//! stack and calls into Rust, which checks the boot information, points the
//! console at the root task's Console capability, and runs `main`.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::abi::{BOOT_INFO_MAGIC, BOOT_INFO_VERSION, BootInfo, root_slot};
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
    crate::console::init(root_slot::CONSOLE, info.ipc_buffer);
    info
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
    crate::println!("panic: {}", info);
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
