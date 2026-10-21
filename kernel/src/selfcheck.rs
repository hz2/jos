//! Kernel-wide invariants, checked on demand.
//!
//! The pure core proves its parts one at a time; this checks that the live
//! kernel's parts agree with each other, the invariants of
//! [`jos_core::abi::invariant`]: the registry of capability spaces with the
//! spaces in it, every derivation link with the capability it names, the
//! threads with the scheduler and the blocking tables, and the mapping
//! registry with the page tables. The root task asks after every check of its
//! suite and after every fuzzer run (the `selfcheck` syscall, which needs the
//! Machine capability), so a step that leaves the kernel inconsistent fails
//! itself instead of a later step that trips over it.

use jos_core::abi::invariant;

use crate::cap::TcbState;
use crate::sched::{self, MAX_THREADS};

/// Checks every invariant and returns the bits of those that do not hold, 0
/// if all do.
#[must_use]
pub fn check() -> u64 {
    // SAFETY: the syscall path runs single-CPU with interrupts disabled, and
    // the caller holds no reference into a capability space.
    let mut failed = unsafe { crate::cap::check_spaces() };
    failed |= check_threads();
    failed |= check_ready();
    failed |= crate::syscall::check_waits();
    if !crate::mapping::check_mappings() {
        failed |= invariant::MAPPINGS;
    }
    failed
}

/// Returns [`invariant::THREADS`] if a registered thread was never started or
/// is retired, or runs in a capability space that is not registered.
fn check_threads() -> u64 {
    let mut failed = 0;
    // SAFETY: single-CPU syscall path; each thread and its space are only read.
    unsafe {
        sched::for_each_thread(|_, tcb| {
            let started = matches!((*tcb).state, TcbState::Running | TcbState::Faulted);
            if !started || !crate::cap::is_registered((*tcb).cspace_ptr) {
                failed = invariant::THREADS;
            }
        });
    }
    failed
}

/// Returns [`invariant::READY`] if the ready set holds a thread that is not
/// registered, or the thread on the cpu.
fn check_ready() -> u64 {
    let current = sched::current_thread_id();
    let stray = (0..MAX_THREADS).any(|id| {
        // SAFETY: id is in range; thread_table_entry reads one entry.
        sched::is_ready(id) && (id == current || unsafe { sched::thread_table_entry(id) }.is_null())
    });
    if stray { invariant::READY } else { 0 }
}
