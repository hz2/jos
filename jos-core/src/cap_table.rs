//! Fixed-size capability table with generation-counted slots.
//!
//! This is the pure-logic core of the capability system: the data structure
//! that stores capabilities and hands out references to them. It has no
//! hardware dependencies, so it is exercised on the host under `cargo test`,
//! Miri, and Kani; the kernel wraps it with the real object types and syscalls.
//!
//! # Model
//!
//! A `CapTable<T, N>` is an array of `N` slots. Each slot is either empty or
//! holds one capability of type `T`, plus a generation counter. Inserting a
//! capability returns a `CapRef`: a small, copyable token carrying the slot
//! index and the generation that was current at insertion time.
//!
//! Every access (`get`, `remove`, `invoke`) revalidates the `CapRef` against
//! the slot's current generation. When a capability is removed, the slot's
//! generation is bumped, so every `CapRef` minted before the removal becomes
//! permanently stale. This gives O(1) revocation: re-handing the same physical
//! slot to a new capability never lets an old token address the new occupant.
//!
//! # Invariant
//!
//! - A slot is occupied iff its `entry` is `Some`.
//! - `len` equals the number of occupied slots, always in `[0, N]`.
//! - A `CapRef { slot, generation }` is *valid* iff `slot < N`, the slot is
//!   occupied, and the slot's stored generation equals `generation`.
//! - Generations are monotonically non-decreasing per slot; they only advance
//!   on removal, so a (slot, generation) pair never refers to two different
//!   capabilities over the table's lifetime (until generation wraps, which is
//!   `u32`-wide and treated as effectively unbounded for a hobby kernel).
//!
//! This mirrors the unforgeable-token idea from `seL4` `CNode`s and Zircon
//! handle tables: holding a `CapRef` is the authority, and it cannot be forged
//! to point at a capability the holder was not explicitly given.

/// An unforgeable reference to a capability stored in a [`CapTable`].
///
/// A `CapRef` is plain data (slot index plus generation) and is `Copy`, but it
/// only grants access while it stays valid: the referenced slot must still hold
/// the same capability it did when the ref was minted. A removed-and-reused
/// slot invalidates every prior `CapRef` to it via the generation bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapRef {
    slot: usize,
    generation: u32,
}

impl CapRef {
    /// Returns the slot index this reference points at.
    #[inline]
    #[must_use]
    pub const fn slot(&self) -> usize {
        self.slot
    }

    /// Returns the generation this reference was minted at.
    #[inline]
    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }
}

// a single table slot: the optional capability plus the generation counter.
// the generation advances each time the slot is vacated, invalidating any
// outstanding CapRef that named the previous occupant.
struct Slot<T> {
    entry: Option<T>,
    generation: u32,
}

impl<T> Slot<T> {
    const fn empty() -> Self {
        Self {
            entry: None,
            generation: 0,
        }
    }
}

/// A fixed-capacity table of capabilities addressed by generation-checked refs.
///
/// `T` is the capability payload (in the kernel this becomes the typed kernel
/// object plus its rights). The table owns its slots; no heap allocation.
pub struct CapTable<T, const N: usize> {
    slots: [Slot<T>; N],
    len: usize,
}

impl<T, const N: usize> CapTable<T, N> {
    /// Creates an empty capability table with all `N` slots vacant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| Slot::empty()),
            len: 0,
        }
    }

    /// Returns the total number of slots, `N`.
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Returns the number of occupied slots.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if no slots are occupied.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` if every slot is occupied.
    #[inline]
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.len == N
    }

    /// Inserts `cap` into the lowest free slot and returns a [`CapRef`] to it.
    ///
    /// Returns `Err(cap)` (preserving ownership) when the table is full.
    ///
    /// # Errors
    ///
    /// Returns the rejected capability when there is no free slot.
    pub fn insert(&mut self, cap: T) -> Result<CapRef, T> {
        // scan for the lowest-index vacant slot. a real kernel would keep a
        // free-list for O(1); a linear scan keeps the verifiable core simple
        // and is fine for the small N a capability space uses.
        for slot in 0..N {
            if self.slots[slot].entry.is_none() {
                self.slots[slot].entry = Some(cap);
                self.len += 1;
                return Ok(CapRef {
                    slot,
                    generation: self.slots[slot].generation,
                });
            }
        }
        Err(cap)
    }

    // returns true if `cap_ref` currently names a live capability: in range,
    // occupied, and matching generation. the single source of validity.
    #[inline]
    fn is_valid(&self, cap_ref: CapRef) -> bool {
        cap_ref.slot < N
            && self.slots[cap_ref.slot].entry.is_some()
            && self.slots[cap_ref.slot].generation == cap_ref.generation
    }

    /// Returns a shared reference to the capability named by `cap_ref`, or
    /// `None` if the reference is stale or out of range.
    #[must_use]
    pub fn get(&self, cap_ref: CapRef) -> Option<&T> {
        if self.is_valid(cap_ref) {
            self.slots[cap_ref.slot].entry.as_ref()
        } else {
            None
        }
    }

    /// Returns a mutable reference to the capability named by `cap_ref`, or
    /// `None` if the reference is stale or out of range.
    #[must_use]
    pub fn get_mut(&mut self, cap_ref: CapRef) -> Option<&mut T> {
        if self.is_valid(cap_ref) {
            self.slots[cap_ref.slot].entry.as_mut()
        } else {
            None
        }
    }

    /// Removes and returns the capability named by `cap_ref`, bumping the
    /// slot's generation so every outstanding ref to it becomes stale.
    ///
    /// Returns `None` if the reference is already stale or out of range, in
    /// which case the table is unchanged (idempotent revocation).
    pub fn remove(&mut self, cap_ref: CapRef) -> Option<T> {
        if !self.is_valid(cap_ref) {
            return None;
        }
        let slot = &mut self.slots[cap_ref.slot];
        // advance the generation first so any copy of this cap_ref is invalid
        // from here on, including against a future occupant of the same slot.
        slot.generation = slot.generation.wrapping_add(1);
        self.len -= 1;
        slot.entry.take()
    }

    /// Returns `true` if `cap_ref` currently names a live capability.
    #[must_use]
    pub fn contains(&self, cap_ref: CapRef) -> bool {
        self.is_valid(cap_ref)
    }

    /// Returns the [`CapRef`] for `slot` if it is occupied, else `None`.
    ///
    /// The returned ref carries the slot's current generation, so it is valid
    /// until the slot is removed. Slot indices are stable, so this is how a
    /// caller enumerates live capabilities (for example, to find the children
    /// of a capability during revocation) without being handed a forgeable ref.
    #[must_use]
    pub fn ref_at(&self, slot: usize) -> Option<CapRef> {
        if slot < N && self.slots[slot].entry.is_some() {
            Some(CapRef {
                slot,
                generation: self.slots[slot].generation,
            })
        } else {
            None
        }
    }

    /// Calls `f` with the [`CapRef`] and a shared reference to every live
    /// capability in the table, in ascending slot order.
    ///
    /// Useful for scans like "find all capabilities derived from this one".
    /// The closure cannot mutate the table; collect the refs it wants and act
    /// on them afterward (the borrow checker enforces this).
    pub fn for_each(&self, mut f: impl FnMut(CapRef, &T)) {
        for slot in 0..N {
            if let Some(entry) = self.slots[slot].entry.as_ref() {
                let cap_ref = CapRef {
                    slot,
                    generation: self.slots[slot].generation,
                };
                f(cap_ref, entry);
            }
        }
    }
}

impl<T, const N: usize> Default for CapTable<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // the test harness links std, so we can use std::vec here even though the
    // library itself is no_std.
    extern crate std;

    #[test]
    fn new_table_is_empty() {
        let t: CapTable<u32, 8> = CapTable::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        assert_eq!(t.capacity(), 8);
    }

    #[test]
    fn insert_then_get_roundtrip() {
        let mut t: CapTable<u32, 4> = CapTable::new();
        let r = t.insert(42).unwrap();
        assert_eq!(t.get(r), Some(&42));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn insert_fills_lowest_slot_first() {
        let mut t: CapTable<u32, 4> = CapTable::new();
        let a = t.insert(1).unwrap();
        let b = t.insert(2).unwrap();
        assert_eq!(a.slot(), 0);
        assert_eq!(b.slot(), 1);
    }

    #[test]
    fn insert_on_full_returns_err_with_value() {
        let mut t: CapTable<u32, 2> = CapTable::new();
        t.insert(1).unwrap();
        t.insert(2).unwrap();
        assert!(t.is_full());
        assert_eq!(t.insert(3), Err(3));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn remove_returns_value_and_frees_slot() {
        let mut t: CapTable<u32, 4> = CapTable::new();
        let r = t.insert(7).unwrap();
        assert_eq!(t.remove(r), Some(7));
        assert!(t.is_empty());
        assert_eq!(t.get(r), None);
    }

    #[test]
    fn stale_ref_after_removal_is_rejected() {
        let mut t: CapTable<u32, 4> = CapTable::new();
        let r = t.insert(7).unwrap();
        assert_eq!(t.remove(r), Some(7));
        // the ref is now stale: get, get_mut, contains, and a second remove
        // must all reject it rather than touch whatever later lives here.
        assert_eq!(t.get(r), None);
        assert!(!t.contains(r));
        assert_eq!(t.remove(r), None);
    }

    #[test]
    fn reused_slot_does_not_honor_old_ref() {
        // the core revocation property: removing a cap and inserting a new one
        // into the same physical slot must not let the old ref reach the new
        // occupant.
        let mut t: CapTable<u32, 1> = CapTable::new();
        let old = t.insert(100).unwrap();
        assert_eq!(t.remove(old), Some(100));
        let new = t.insert(200).unwrap();
        // both refs name slot 0, but generations differ.
        assert_eq!(old.slot(), new.slot());
        assert_ne!(old.generation(), new.generation());
        assert_eq!(t.get(old), None); // stale ref sees nothing
        assert_eq!(t.get(new), Some(&200)); // fresh ref sees the new cap
    }

    #[test]
    fn get_mut_allows_mutation() {
        let mut t: CapTable<u32, 4> = CapTable::new();
        let r = t.insert(1).unwrap();
        *t.get_mut(r).unwrap() = 99;
        assert_eq!(t.get(r), Some(&99));
    }

    #[test]
    fn distinct_refs_are_independent() {
        let mut t: CapTable<u32, 4> = CapTable::new();
        let a = t.insert(10).unwrap();
        let b = t.insert(20).unwrap();
        assert_eq!(t.remove(a), Some(10));
        // removing a must not disturb b.
        assert_eq!(t.get(b), Some(&20));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn out_of_range_ref_is_rejected() {
        let mut t: CapTable<u32, 2> = CapTable::new();
        let bogus = CapRef {
            slot: 99,
            generation: 0,
        };
        assert_eq!(t.get(bogus), None);
        assert!(!t.contains(bogus));
        assert_eq!(t.remove(bogus), None);
        // a forged-generation ref to a real slot is also rejected.
        let real = t.insert(1).unwrap();
        let forged = CapRef {
            slot: real.slot(),
            generation: real.generation().wrapping_add(1),
        };
        assert_eq!(t.get(forged), None);
    }

    #[test]
    fn len_conserved_across_op_sequence() {
        let mut t: CapTable<u32, 8> = CapTable::new();
        let mut refs = [None; 8];
        // fill it.
        for (i, slot) in refs.iter_mut().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let v = i as u32;
            *slot = Some(t.insert(v).unwrap());
        }
        assert!(t.is_full());
        // remove the even-indexed ones.
        let mut removed = 0;
        for slot in refs.iter_mut().step_by(2) {
            if let Some(r) = slot.take() {
                assert!(t.remove(r).is_some());
                removed += 1;
            }
        }
        assert_eq!(t.len(), 8 - removed);
        // re-fill the freed slots.
        for _ in 0..removed {
            assert!(t.insert(0).is_ok());
        }
        assert!(t.is_full());
    }

    #[test]
    fn ref_at_matches_insert_and_tracks_generation() {
        let mut t: CapTable<u32, 4> = CapTable::new();
        let r = t.insert(7).unwrap();
        // ref_at on the occupied slot reproduces the insert ref.
        assert_eq!(t.ref_at(r.slot()), Some(r));
        // empty slots and out-of-range yield None.
        assert_eq!(t.ref_at(1), None);
        assert_eq!(t.ref_at(99), None);
        // after remove + reinsert the slot's generation has advanced, so the
        // new ref_at differs from the old ref (the stale one no longer matches).
        t.remove(r);
        let r2 = t.insert(8).unwrap();
        assert_eq!(r2.slot(), r.slot());
        assert_eq!(t.ref_at(r.slot()), Some(r2));
        assert_ne!(t.ref_at(r.slot()), Some(r));
    }

    #[test]
    fn for_each_visits_every_live_entry() {
        let mut t: CapTable<u32, 8> = CapTable::new();
        let a = t.insert(10).unwrap();
        let b = t.insert(20).unwrap();
        let c = t.insert(30).unwrap();
        t.remove(b); // leave a hole in the middle.

        let mut seen = std::vec::Vec::new();
        t.for_each(|r, &v| seen.push((r, v)));
        // visits exactly the two live entries, each ref valid, in slot order.
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], (a, 10));
        assert_eq!(seen[1], (c, 30));
        assert!(t.contains(seen[0].0));
        assert!(t.contains(seen[1].0));
    }
}

// bounded proof harnesses, run under `cargo kani` once the verifier is wired.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // a fresh insert always yields a ref that resolves back to the same value.
    #[kani::proof]
    fn insert_then_get_identity() {
        let mut t: CapTable<u32, 4> = CapTable::new();
        let v: u32 = kani::any();
        let r = t.insert(v).unwrap();
        assert!(t.get(r) == Some(&v));
    }

    // after removal the same ref never resolves, no matter the value.
    #[kani::proof]
    fn removed_ref_is_always_stale() {
        let mut t: CapTable<u32, 2> = CapTable::new();
        let v: u32 = kani::any();
        let r = t.insert(v).unwrap();
        let _ = t.remove(r);
        assert!(t.get(r).is_none());
        assert!(t.remove(r).is_none());
    }

    // the revocation guarantee: an old ref cannot reach a slot's new occupant.
    #[kani::proof]
    fn reused_slot_rejects_old_ref() {
        let mut t: CapTable<u32, 1> = CapTable::new();
        let a: u32 = kani::any();
        let b: u32 = kani::any();
        let old = t.insert(a).unwrap();
        let _ = t.remove(old);
        let _new = t.insert(b).unwrap();
        assert!(t.get(old).is_none());
    }

    // len stays within bounds across a short arbitrary op sequence.
    #[kani::proof]
    #[kani::unwind(5)]
    fn len_within_bounds() {
        let mut t: CapTable<u32, 3> = CapTable::new();
        let mut last: Option<CapRef> = None;
        for _ in 0..4 {
            if kani::any() {
                if let Ok(r) = t.insert(kani::any()) {
                    last = Some(r);
                }
            } else if let Some(r) = last.take() {
                let _ = t.remove(r);
            }
            assert!(t.len() <= t.capacity());
        }
    }
}
