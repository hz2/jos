//! The tables of threads parked in blocking IPC (BLOCK-1).
//!
//! A thread whose blocking send, call, or receive finds no partner parks: it
//! is recorded with the endpoint it waits on until a partner takes it, the
//! endpoint goes away, or, for a timed wait, its deadline passes. The kernel
//! keeps one table for parked senders and one for parked receivers, each
//! entry carrying what finishing the operation needs (`T`: a sender's message,
//! a receiver's reply object). This module is the bookkeeping both share, so
//! its rules are checked once, without the kernel.
//!
//! # Invariant
//!
//! - A thread is parked in a table at most once.
//! - Every park is numbered after every earlier one, and of the waiters a take
//!   may pick it picks the one that parked first: waiters on an endpoint are
//!   served in the order they arrived, and expired waiters are woken in that
//!   order too.
//! - A waiter leaves the table exactly once, through whichever take reaches
//!   it first ([`take_oldest`](WaitTable::take_oldest),
//!   [`take_expired`](WaitTable::take_expired), or
//!   [`take_thread`](WaitTable::take_thread)), and only that caller wakes the
//!   thread: a thread is never woken twice, or after it stopped waiting.
//!
//! The Kani harness at the bottom of this file checks all three against a
//! plain list in park order, over every short sequence of operations.

use crate::clock::Instant;

/// A thread parked in a [`WaitTable`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Waiter<T> {
    /// The endpoint it waits on: the kernel names an endpoint by its address.
    pub endpoint: u64,
    /// Its scheduler id.
    pub thread: usize,
    /// When it stops waiting, for a timed wait.
    pub deadline: Option<Instant>,
    /// What finishing its operation needs.
    pub data: T,
    /// Its park number: a later park has a larger one.
    seq: u64,
}

/// Why a thread could not park.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParkError {
    /// Every entry is in use.
    Full,
    /// The thread is parked already.
    AlreadyParked,
}

/// Up to `N` parked threads.
pub struct WaitTable<T, const N: usize> {
    /// The waiters, in no particular order: free entries are reused.
    entries: [Option<Waiter<T>>; N],
    /// The number the next park gets. A `u64` does not run out: at a park a
    /// nanosecond it would last 584 years.
    next_seq: u64,
}

impl<T: Copy, const N: usize> WaitTable<T, N> {
    /// Returns an empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self { entries: [None; N], next_seq: 0 }
    }

    /// Parks `thread` on `endpoint`, until `deadline` if one is given, with
    /// `data` for whoever takes it.
    ///
    /// # Errors
    ///
    /// [`ParkError::AlreadyParked`] if `thread` is in the table already, or
    /// [`ParkError::Full`] if no entry is free.
    pub fn park(&mut self, endpoint: u64, thread: usize, deadline: Option<Instant>, data: T) -> Result<(), ParkError> {
        if self.is_parked(thread) {
            return Err(ParkError::AlreadyParked);
        }
        let entry = self.entries.iter_mut().find(|e| e.is_none()).ok_or(ParkError::Full)?;
        *entry = Some(Waiter { endpoint, thread, deadline, data, seq: self.next_seq });
        self.next_seq += 1;
        Ok(())
    }

    /// Returns whether `thread` is parked here.
    #[must_use]
    pub fn is_parked(&self, thread: usize) -> bool {
        self.entries.iter().flatten().any(|w| w.thread == thread)
    }

    /// Returns how many threads are parked here.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    /// Returns whether no thread is parked here.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Calls `f` with every parked waiter, in no particular order.
    pub fn for_each(&self, f: impl FnMut(&Waiter<T>)) {
        self.entries.iter().flatten().for_each(f);
    }

    /// Takes the waiter on `endpoint` that parked first, if there is one.
    #[must_use = "a taken waiter must be woken"]
    pub fn take_oldest(&mut self, endpoint: u64) -> Option<Waiter<T>> {
        self.take_first(|w| w.endpoint == endpoint)
    }

    /// Takes the waiter that parked first among those whose deadline `now`
    /// has reached, if there is one. Called until it returns `None`, it takes
    /// every waiter that is due.
    #[must_use = "a taken waiter must be woken"]
    pub fn take_expired(&mut self, now: Instant) -> Option<Waiter<T>> {
        self.take_first(|w| w.deadline.is_some_and(|d| now.reached(d)))
    }

    /// Takes `thread`'s entry, if it is parked: for a thread that stops
    /// waiting because it stops altogether.
    #[must_use = "a taken waiter must be woken or retired"]
    pub fn take_thread(&mut self, thread: usize) -> Option<Waiter<T>> {
        self.take_first(|w| w.thread == thread)
    }

    /// Takes the waiter that parked first among those `pick` accepts.
    fn take_first(&mut self, pick: impl Fn(&Waiter<T>) -> bool) -> Option<Waiter<T>> {
        let (_, index) = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.as_ref().filter(|w| pick(w)).map(|w| (w.seq, i)))
            .min()?;
        self.entries[index].take()
    }
}

impl<T: Copy, const N: usize> Default for WaitTable<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{Instant, ParkError, WaitTable};

    #[test]
    fn waiters_on_an_endpoint_are_served_in_arrival_order() {
        let mut table: WaitTable<u8, 4> = WaitTable::new();
        table.park(7, 1, None, b'a').unwrap();
        table.park(9, 2, None, b'b').unwrap();
        table.park(7, 3, None, b'c').unwrap();
        assert_eq!(table.take_oldest(7).map(|w| w.data), Some(b'a'));
        // the freed entry is reused, but the newcomer still queues last.
        table.park(7, 4, None, b'd').unwrap();
        assert_eq!(table.take_oldest(7).map(|w| w.data), Some(b'c'));
        assert_eq!(table.take_oldest(7).map(|w| w.data), Some(b'd'));
        assert_eq!(table.take_oldest(7), None);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn only_due_deadlines_expire_and_untimed_waits_never_do() {
        let mut table: WaitTable<u8, 4> = WaitTable::new();
        table.park(1, 1, Some(Instant::new(20)), b'a').unwrap();
        table.park(1, 2, None, b'b').unwrap();
        table.park(2, 3, Some(Instant::new(10)), b'c').unwrap();
        assert_eq!(table.take_expired(Instant::new(9)), None);
        assert_eq!(table.take_expired(Instant::new(25)).map(|w| w.data), Some(b'a'));
        assert_eq!(table.take_expired(Instant::new(25)).map(|w| w.data), Some(b'c'));
        assert_eq!(table.take_expired(Instant::new(u64::MAX)), None);
        assert!(table.is_parked(2));
    }

    #[test]
    fn a_thread_parks_once_and_a_full_table_refuses() {
        let mut table: WaitTable<u8, 2> = WaitTable::new();
        table.park(1, 5, None, 0).unwrap();
        assert_eq!(table.park(2, 5, None, 0), Err(ParkError::AlreadyParked));
        table.park(1, 6, None, 0).unwrap();
        assert_eq!(table.park(1, 7, None, 0), Err(ParkError::Full));
        assert_eq!(table.take_thread(5).map(|w| w.endpoint), Some(1));
        assert_eq!(table.take_thread(5), None);
        assert!(!table.is_parked(5) && table.is_parked(6));
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::{Instant, ParkError, WaitTable, Waiter};

    /// Entries in the table: two, so it fills and a freed entry is reused.
    const N: usize = 2;

    /// Operations per run: enough to park twice, take the older waiter, park
    /// a newcomer in the freed entry, and take again.
    const STEPS: usize = 5;

    /// A waiter as the model keeps it.
    #[derive(Clone, Copy)]
    struct Parked {
        /// The endpoint it waits on.
        endpoint: u64,
        /// Its thread.
        thread: usize,
        /// Its deadline.
        deadline: Option<Instant>,
        /// The step it parked in, which tells waiters apart.
        step: u8,
    }

    /// Whether `got`, a waiter the table gave back, is `want`.
    fn same(got: &Waiter<u8>, want: &Parked) -> bool {
        got.endpoint == want.endpoint && got.thread == want.thread && got.deadline == want.deadline && got.data == want.step
    }

    /// Over every sequence of five parks and takes on a two-entry table, the
    /// table behaves as a list in park order (BLOCK-1): a park fails exactly
    /// when the thread is listed or the list is full; each take returns the
    /// first listed waiter it matches, or nothing when none does, and that
    /// waiter leaves the list, so it is never returned again.
    ///
    /// The model keeps every successful park at its own index in park order
    /// and blanks a waiter once it is taken, so finding the first match is a
    /// scan of a fixed array (shifting a list with a symbolic length took
    /// cbmc past 8 GB).
    #[kani::proof]
    #[kani::unwind(6)] // five steps and a five-entry model, plus one
    fn the_table_is_a_list_in_park_order() {
        let mut table: WaitTable<u8, N> = WaitTable::new();
        let mut model: [Option<Parked>; STEPS] = [None; STEPS];
        let mut parks = 0;
        for step in 0..STEPS as u8 {
            let endpoint = u64::from(kani::any::<bool>());
            let thread = usize::from(kani::any::<u8>() & 3);
            let at = Instant::new(u64::from(kani::any::<u8>() & 3));
            let op = kani::any::<u8>() & 3;
            if op == 0 {
                let deadline = if kani::any() { Some(at) } else { None };
                let parked = table.park(endpoint, thread, deadline, step);
                if model.iter().flatten().any(|p| p.thread == thread) {
                    assert!(parked == Err(ParkError::AlreadyParked));
                } else if model.iter().flatten().count() == N {
                    assert!(parked == Err(ParkError::Full));
                } else {
                    assert!(parked.is_ok());
                    model[parks] = Some(Parked { endpoint, thread, deadline, step });
                    parks += 1;
                }
            } else {
                let matches = |p: &Parked| match op {
                    1 => p.endpoint == endpoint,
                    2 => p.deadline.is_some_and(|d| at.reached(d)),
                    _ => p.thread == thread,
                };
                let got = match op {
                    1 => table.take_oldest(endpoint),
                    2 => table.take_expired(at),
                    _ => table.take_thread(thread),
                };
                match model.iter().position(|p| p.is_some_and(|p| matches(&p))) {
                    None => assert!(got.is_none()),
                    Some(i) => {
                        assert!(got.is_some_and(|w| model[i].is_some_and(|p| same(&w, &p))));
                        model[i] = None;
                    }
                }
            }
            assert!(table.len() == model.iter().flatten().count());
        }
    }
}
