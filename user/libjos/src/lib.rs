//! libjos: the runtime every jos userspace program links.
//!
//! A jos program has no ambient authority: everything it can do, it does by
//! invoking a capability through a syscall. This crate is the thin layer
//! between a program and that boundary:
//!
//! - [`syscall`] issues the raw `syscall` instruction;
//! - [`sys`] wraps every call in a typed function over the shared ABI in
//!   `jos_core::abi`, so the kernel and userspace read one definition;
//! - [`console`] prints through a Console capability ([`print!`], [`println!`]);
//! - [`rt`] provides the entry point ([`root_entry!`]) and the panic handler;
//! - [`mem`] allocates slots, retypes objects, and maps pages;
//! - [`thread`] starts more threads in the same spaces;
//! - [`ktap`] prints test results in KTAP, the format the host harness reads.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::pedantic)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod console;
pub mod ktap;
pub mod mem;
pub mod rt;
pub mod sys;
pub mod syscall;
pub mod thread;

pub use jos_core;
pub use jos_core::abi;
