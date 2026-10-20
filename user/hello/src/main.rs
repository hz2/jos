//! A small program the root task starts as a process of its own, from the
//! `hello` boot module, to check what a process can and cannot do.
//!
//! It runs in an address space of its own and holds only what a process is
//! given: a console it can write to, an endpoint to its parent, and the one
//! its faults go to. Its argument picks what it does, and its exit code (the
//! value `main` returns) reaches the parent:
//!
//! - [`GREET`] prints a line and exits with 0;
//! - [`TRY_HALT`] tries to halt the machine through the slot the root task
//!   keeps its machine capability in, and exits with the error it got;
//! - any other value is an address, which it reads and exits with the word
//!   found there (an address it has nothing mapped at faults instead, and the
//!   fault goes to its parent).
#![no_std]
#![no_main]
#![warn(clippy::pedantic)]

use libjos::abi::{ProcessStart, root_slot};
use libjos::{println, sys};

libjos::process_entry!(main);

/// The argument that makes it greet.
const GREET: u64 = 0;

/// The argument that makes it try to halt the machine.
const TRY_HALT: u64 = 1;

/// Does what its argument says and returns its exit code.
fn main(start: &ProcessStart) -> u64 {
    match start.arg {
        GREET => {
            println!("hello from a process of its own");
            0
        }
        TRY_HALT => sys::machine_halt(root_slot::MACHINE, 1) as u64,
        address => {
            // SAFETY: the read is meant to fault unless the address is mapped
            // in this process; volatile, so it is not optimized away.
            unsafe { core::ptr::read_volatile(address as *const u64) }
        }
    }
}
