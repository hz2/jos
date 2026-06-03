//! jos-core: pure, hardware-free kernel logic.
//!
//! everything here is `no_std` and free of asm, MMIO, and platform intrinsics,
//! so it builds for the host as well as the bare-metal kernel target. that is
//! what lets these data structures be exercised under `cargo test`, Miri (for
//! undefined behavior in unsafe code), and Kani (for bounded proofs), none of
//! which can run the kernel binary itself.
//!
//! the kernel links this crate and wires the logic to real hardware behind the
//! hal boundary. capability tables, IPC routing, allocator free-lists, ring
//! buffers, bitmaps, and page-table index math will live here.
#![no_std]
// deny implicit unsafe: every unsafe op must sit in an explicit unsafe block,
// even inside an unsafe fn, so the audited surface is obvious.
#![deny(unsafe_op_in_unsafe_fn)]
// stage 0 hygiene: pedantic lints on the pure-logic crate. warn (not deny) so
// new code is flagged without blocking local iteration; CI treats them as
// errors via -D warnings.
#![warn(clippy::pedantic)]

// host-side test and proof crates pull in std/alloc as needed; the library
// itself stays no_std so it is identical on the kernel target.

pub mod bitmap;
pub mod ring_buffer;

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        // placeholder so the crate has a host-runnable test from day one;
        // real module tests replace this as logic lands.
        assert_eq!(2 + 2, 4);
    }
}
