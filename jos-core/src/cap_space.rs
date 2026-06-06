//! Capability space: a task's table of typed, rights-bearing capabilities.
//!
//! A `CapSpace` is the jos analogue of an `seL4` `CSpace` (single-level for now:
//! one flat table, no guard/radix multi-level addressing yet). It is built on the
//! Kani-verified [`CapTable`](crate::cap_table::CapTable): each slot holds a
//! [`Capability`], and the table's generation-counted [`CapRef`] addresses it.
//!
//! A [`Capability`] pairs an object handle with a [`Rights`] mask and an
//! optional parent link (the start of a capability derivation tree). The object
//! handle type `O` is a generic parameter: `jos-core` proves the rights,
//! derivation, and revocation logic for any handle, and the kernel instantiates
//! `O` with its concrete kernel-object reference. This keeps the whole capability
//! space pure and verifiable, with no dependency on kernel object representation.
//!
//! # What this enforces (and what the type system gives for free)
//!
//! - Authority is the capability: an operation is permitted only if the holder
//!   has a live `CapRef` whose `Capability` carries the required `Rights`.
//! - Attenuation is monotone: [`mint`](CapSpace::mint) can only reduce rights
//!   (it intersects via [`Rights::attenuate`]), never grant new ones. This holds
//!   transitively: along a derivation chain of any depth, no descendant holds a
//!   right its root ancestor lacked, so delegation can never manufacture
//!   authority (the global no-amplification property, the seL4 integrity story).
//!   The `mint_chain_never_amplifies` and `derived_authority_bounded_by_root`
//!   Kani harnesses discharge this over the real `mint`/`check` path; it rests on
//!   the single-link `mint_never_escalates` plus `contains` transitivity (both
//!   proved here and in [`crate::cap_rights`]).
//! - Unforgeability is a language property: `CapRef` fields are private, so a
//!   ref can only come from inserting into a real table. No "fake" capability
//!   can be constructed in safe code.
//! - Revocation is O(1) per slot: removing a capability bumps the table slot's
//!   generation, so every outstanding `CapRef` to it goes stale at once.

use crate::cap_rights::Rights;
use crate::cap_table::{CapRef, CapTable};
pub use crate::cap_table::InsertAtError;

/// A typed, rights-bearing capability: the entry stored in a [`CapSpace`] slot.
///
/// `O` is the object-handle type (in the kernel, a reference into the object
/// store). It is `Copy` so capabilities can be duplicated and minted freely;
/// the authority comes from holding a live `CapRef`, not from the handle value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability<O: Copy> {
    /// The kernel object this capability names.
    pub object: O,
    /// The operations the holder may invoke on the object.
    pub rights: Rights,
    /// The capability this one was derived from, if any. `None` marks an
    /// original capability (for example, the one produced by retyping untyped
    /// memory). Used to find children during revocation.
    pub parent: Option<CapRef>,
}

impl<O: Copy> Capability<O> {
    /// Creates an original capability (no parent) with the given rights.
    #[must_use]
    pub const fn new(object: O, rights: Rights) -> Self {
        Self {
            object,
            rights,
            parent: None,
        }
    }
}

/// Errors from a [`CapSpace::mint`] operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintError {
    /// The source `CapRef` does not name a live capability.
    InvalidSource,
    /// The capability space has no free slot for the derived capability.
    SpaceFull,
}

/// A single-level capability space backed by a [`CapTable`] of `N` slots.
pub struct CapSpace<O: Copy, const N: usize> {
    table: CapTable<Capability<O>, N>,
}

impl<O: Copy, const N: usize> CapSpace<O, N> {
    /// Creates an empty capability space.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: CapTable::new(),
        }
    }

    /// Returns the total number of capability slots, `N`.
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Returns the number of occupied slots.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.table.len()
    }

    /// Returns `true` if the space holds no capabilities.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Installs an original capability (no parent) for `object` with `rights`
    /// and returns its `CapRef`.
    ///
    /// # Errors
    ///
    /// Returns the rejected capability when the space is full.
    pub fn insert(&mut self, object: O, rights: Rights) -> Result<CapRef, Capability<O>> {
        self.table.insert(Capability::new(object, rights))
    }

    /// Installs an original capability (no parent) for `object` with `rights`
    /// at the caller-chosen slot `slot`, returning its `CapRef`.
    ///
    /// The slot-addressed counterpart of [`insert`](Self::insert), for when a
    /// deterministic destination matters (a `Retype` syscall names the slot the
    /// new capability must land in).
    ///
    /// # Errors
    ///
    /// [`InsertAtError::OutOfRange`] if `slot >= N`; [`InsertAtError::Occupied`]
    /// if the slot already holds a live capability.
    pub fn insert_at(
        &mut self,
        slot: usize,
        object: O,
        rights: Rights,
    ) -> Result<CapRef, InsertAtError> {
        self.table.insert_at(slot, Capability::new(object, rights))
    }

    /// Returns the capability named by `cap_ref`, or `None` if it is stale.
    #[must_use]
    pub fn lookup(&self, cap_ref: CapRef) -> Option<&Capability<O>> {
        self.table.get(cap_ref)
    }

    /// Returns a live, generation-checked [`CapRef`] for capability `slot`, or
    /// `None` if the slot is out of range or empty.
    ///
    /// This is how an external addressing scheme (a syscall that names a
    /// capability by a plain slot index) resolves to an unforgeable ref: the
    /// caller supplies only the index, and the space reconstructs the ref with
    /// the slot's current generation. A revoked-and-reused slot yields a ref
    /// for the new occupant (or `None` if now empty), never a stale one, so the
    /// resolution is safe to do afresh on every syscall.
    #[must_use]
    pub fn ref_at(&self, slot: usize) -> Option<CapRef> {
        self.table.ref_at(slot)
    }

    /// Returns `true` if `cap_ref` currently names a live capability AND that
    /// capability carries every right in `required`.
    ///
    /// This is the single gate every capability-mediated operation passes
    /// through: present the ref, prove you hold the right.
    #[must_use]
    pub fn check(&self, cap_ref: CapRef, required: Rights) -> bool {
        self.table
            .get(cap_ref)
            .is_some_and(|cap| cap.rights.contains(required))
    }

    /// Derives a new capability to the same object as `source`, with rights
    /// attenuated by `mask`, recording `source` as its parent.
    ///
    /// The derived rights are `source.rights.attenuate(mask)`, so they can only
    /// be a subset of the source's rights (never more). Returns the new
    /// capability's `CapRef`.
    ///
    /// # Errors
    ///
    /// [`MintError::InvalidSource`] if `source` is stale; [`MintError::SpaceFull`]
    /// if there is no free slot.
    pub fn mint(&mut self, source: CapRef, mask: Rights) -> Result<CapRef, MintError> {
        let parent = self.table.get(source).ok_or(MintError::InvalidSource)?;
        let derived = Capability {
            object: parent.object,
            // monotone: the result is a subset of the parent's rights.
            rights: parent.rights.attenuate(mask),
            parent: Some(source),
        };
        self.table.insert(derived).map_err(|_| MintError::SpaceFull)
    }

    /// Removes the capability named by `cap_ref`, returning it if it was live.
    ///
    /// Bumps the slot generation, so all outstanding refs to it go stale. Does
    /// not recurse into children (use [`revoke`](CapSpace::revoke) for that).
    pub fn remove(&mut self, cap_ref: CapRef) -> Option<Capability<O>> {
        self.table.remove(cap_ref)
    }

    /// Revokes `cap_ref`: removes it and every capability transitively derived
    /// from it (its children, their children, and so on).
    ///
    /// After this returns, neither `cap_ref` nor any descendant names a live
    /// capability. Returns the number of capabilities removed.
    ///
    /// It first marks the whole subtree (while all `parent` links are intact),
    /// then sweeps the marked refs out. Marking before removing matters: once a
    /// capability is removed its `parent` link is no longer reachable, so we
    /// cannot follow chains through already-removed nodes. The scan is O(N) per
    /// layer of the tree; capability spaces are small, and a plain scan keeps
    /// the logic verifiable.
    pub fn revoke(&mut self, cap_ref: CapRef) -> usize {
        // mark phase: collect cap_ref plus every capability that descends from
        // it, with all links still live. fixed-size scratch sized to the table.
        let mut marked: [Option<CapRef>; N] = [None; N];
        let mut count = 0;
        self.table.for_each(|r, _| {
            if self.descends_from(r, cap_ref) {
                marked[count] = Some(r);
                count += 1;
            }
        });

        // sweep phase: remove every marked ref. order does not matter now that
        // membership is already decided.
        let mut removed = 0;
        for r in marked.into_iter().take(count).flatten() {
            if self.table.remove(r).is_some() {
                removed += 1;
            }
        }
        removed
    }

    /// Calls `f` with the [`CapRef`] and a shared reference to every capability
    /// in the subtree rooted at `root` (the root itself plus every capability
    /// transitively derived from it), in ascending slot order.
    ///
    /// This visits exactly the set [`revoke`](Self::revoke) would remove, but
    /// without removing anything, so a caller can act on those capabilities'
    /// objects (for example, waking any IPC waiters parked on a soon-to-be-
    /// revoked endpoint) *before* revoking them, while the parent links are
    /// still intact. The closure cannot mutate the space; collect what it needs
    /// and act afterward.
    pub fn for_each_in_subtree(&self, root: CapRef, mut f: impl FnMut(CapRef, &Capability<O>)) {
        self.table.for_each(|r, cap| {
            if self.descends_from(r, root) {
                f(r, cap);
            }
        });
    }

    /// Returns `true` if `cap_ref` is `ancestor`, or is transitively derived
    /// from `ancestor` by following `parent` links.
    #[must_use]
    fn descends_from(&self, cap_ref: CapRef, ancestor: CapRef) -> bool {
        if cap_ref == ancestor {
            return true;
        }
        let mut current = cap_ref;
        // bound the walk by the slot count so a corrupted cycle cannot hang.
        for _ in 0..N {
            match self.table.get(current).and_then(|cap| cap.parent) {
                Some(p) if p == ancestor => return true,
                Some(p) => current = p,
                None => return false,
            }
        }
        false
    }
}

impl<O: Copy, const N: usize> Default for CapSpace<O, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // the test harness links std, so we can use std helpers here even though
    // the library itself is no_std.
    extern crate std;

    // a tiny object handle for tests: just an id.
    type Obj = u32;

    #[test]
    fn insert_and_lookup() {
        let mut space: CapSpace<Obj, 16> = CapSpace::new();
        let r = space.insert(7, Rights::all()).unwrap();
        let cap = space.lookup(r).unwrap();
        assert_eq!(cap.object, 7);
        assert_eq!(cap.rights, Rights::all());
        assert_eq!(cap.parent, None);
        assert_eq!(space.len(), 1);
    }

    #[test]
    fn check_enforces_rights() {
        let mut space: CapSpace<Obj, 16> = CapSpace::new();
        let r = space.insert(1, Rights::READ).unwrap();
        assert!(space.check(r, Rights::READ));
        assert!(!space.check(r, Rights::WRITE));
        assert!(!space.check(r, Rights::READ_WRITE));
    }

    #[test]
    fn mint_attenuates_rights() {
        let mut space: CapSpace<Obj, 16> = CapSpace::new();
        let full = space.insert(1, Rights::all()).unwrap();
        // mint a read-only child of a full-rights cap.
        let ro = space.mint(full, Rights::READ).unwrap();
        assert!(space.check(ro, Rights::READ));
        assert!(!space.check(ro, Rights::WRITE));
        assert_eq!(space.lookup(ro).unwrap().parent, Some(full));
        // minting cannot escalate: a read-only cap minted with WRITE stays empty.
        let escalated = space.mint(ro, Rights::WRITE).unwrap();
        assert_eq!(space.lookup(escalated).unwrap().rights, Rights::empty());
    }

    #[test]
    fn mint_of_stale_ref_fails() {
        let mut space: CapSpace<Obj, 16> = CapSpace::new();
        let r = space.insert(1, Rights::all()).unwrap();
        space.remove(r);
        assert_eq!(space.mint(r, Rights::READ), Err(MintError::InvalidSource));
    }

    #[test]
    fn remove_makes_ref_stale() {
        let mut space: CapSpace<Obj, 16> = CapSpace::new();
        let r = space.insert(9, Rights::all()).unwrap();
        assert!(space.remove(r).is_some());
        assert!(space.lookup(r).is_none());
        assert!(!space.check(r, Rights::READ));
    }

    #[test]
    fn revoke_removes_whole_subtree() {
        let mut space: CapSpace<Obj, 32> = CapSpace::new();
        let root = space.insert(1, Rights::all()).unwrap();
        let child = space.mint(root, Rights::READ_WRITE).unwrap();
        let grandchild = space.mint(child, Rights::READ).unwrap();
        // an unrelated capability that must survive the revoke.
        let other = space.insert(2, Rights::all()).unwrap();

        let removed = space.revoke(root);
        assert_eq!(removed, 3); // root + child + grandchild
        assert!(space.lookup(root).is_none());
        assert!(space.lookup(child).is_none());
        assert!(space.lookup(grandchild).is_none());
        // the unrelated capability is untouched.
        assert!(space.lookup(other).is_some());
        assert_eq!(space.len(), 1);
    }

    #[test]
    fn revoke_child_leaves_root() {
        let mut space: CapSpace<Obj, 32> = CapSpace::new();
        let root = space.insert(1, Rights::all()).unwrap();
        let child = space.mint(root, Rights::READ).unwrap();
        let grandchild = space.mint(child, Rights::READ).unwrap();

        // revoking the child removes child + grandchild but keeps root.
        let removed = space.revoke(child);
        assert_eq!(removed, 2);
        assert!(space.lookup(root).is_some());
        assert!(space.lookup(child).is_none());
        assert!(space.lookup(grandchild).is_none());
    }

    #[test]
    fn for_each_in_subtree_visits_exactly_the_revoke_set() {
        let mut space: CapSpace<Obj, 32> = CapSpace::new();
        let root = space.insert(1, Rights::all()).unwrap();
        let child = space.mint(root, Rights::READ_WRITE).unwrap();
        let grandchild = space.mint(child, Rights::READ).unwrap();
        // an unrelated capability that must NOT be visited.
        let other = space.insert(2, Rights::all()).unwrap();

        let mut visited = std::vec::Vec::new();
        space.for_each_in_subtree(root, |r, _| visited.push(r));
        // visits root + child + grandchild (the revoke set), not `other`.
        assert_eq!(visited.len(), 3);
        assert!(visited.contains(&root));
        assert!(visited.contains(&child));
        assert!(visited.contains(&grandchild));
        assert!(!visited.contains(&other));

        // and it matches what revoke would remove.
        let removed = space.revoke(root);
        assert_eq!(removed, visited.len());
        assert!(space.lookup(other).is_some());
    }

    #[test]
    fn for_each_in_subtree_of_leaf_is_just_the_leaf() {
        let mut space: CapSpace<Obj, 16> = CapSpace::new();
        let root = space.insert(1, Rights::all()).unwrap();
        let child = space.mint(root, Rights::READ).unwrap();
        let mut visited = std::vec::Vec::new();
        space.for_each_in_subtree(child, |r, _| visited.push(r));
        // the child has no descendants, so only it is visited.
        assert_eq!(visited, std::vec![child]);
    }

    #[test]
    fn full_space_mint_fails() {
        let mut space: CapSpace<Obj, 2> = CapSpace::new();
        let a = space.insert(1, Rights::all()).unwrap();
        let _b = space.insert(2, Rights::all()).unwrap();
        assert_eq!(space.mint(a, Rights::READ), Err(MintError::SpaceFull));
    }
}

// bounded proofs of the capability-space invariants.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // minting never grants a right the source did not have.
    #[kani::proof]
    fn mint_never_escalates() {
        let mut space: CapSpace<u32, 4> = CapSpace::new();
        let src_rights = Rights::from_bits_truncate(kani::any());
        let mask = Rights::from_bits_truncate(kani::any());
        let src = space.insert(kani::any(), src_rights).unwrap();
        if let Ok(child) = space.mint(src, mask) {
            let child_rights = space.lookup(child).unwrap().rights;
            // child rights are a subset of the source's rights.
            assert!(src_rights.contains(child_rights));
            // and a subset of the mask.
            assert!(mask.contains(child_rights));
        }
    }

    // check() passes only when the live capability holds all required rights.
    #[kani::proof]
    fn check_implies_rights_held() {
        let mut space: CapSpace<u32, 4> = CapSpace::new();
        let rights = Rights::from_bits_truncate(kani::any());
        let required = Rights::from_bits_truncate(kani::any());
        let r = space.insert(kani::any(), rights).unwrap();
        if space.check(r, required) {
            assert!(rights.contains(required));
        }
    }

    // a removed capability is never accepted by check, for any rights.
    #[kani::proof]
    fn removed_cap_never_checks() {
        let mut space: CapSpace<u32, 4> = CapSpace::new();
        let r = space.insert(kani::any(), Rights::all()).unwrap();
        space.remove(r);
        let required = Rights::from_bits_truncate(kani::any());
        assert!(!space.check(r, required));
    }

    // the global no-amplification property, the headline security guarantee:
    // along a derivation CHAIN of arbitrary masks, no descendant holds a right
    // its root ancestor lacked. mint_never_escalates proves one link; this
    // proves the transitive closure over a three-deep chain (root -> child ->
    // grandchild), which by induction stands for any depth (each mint only
    // attenuates, and contains is transitive, proved in cap_rights). a 4-slot
    // space holds the whole chain; any mint may legitimately fail with
    // SpaceFull, so each link is guarded rather than unwrapped.
    #[kani::proof]
    fn mint_chain_never_amplifies() {
        let mut space: CapSpace<u32, 4> = CapSpace::new();
        let root_rights = Rights::from_bits_truncate(kani::any());
        let mask1 = Rights::from_bits_truncate(kani::any());
        let mask2 = Rights::from_bits_truncate(kani::any());

        let root = space.insert(kani::any(), root_rights).unwrap();
        if let Ok(child) = space.mint(root, mask1) {
            // the child never exceeds the root (the single-link property).
            let child_rights = space.lookup(child).unwrap().rights;
            assert!(root_rights.contains(child_rights));

            if let Ok(grandchild) = space.mint(child, mask2) {
                // the transitive guarantee: two derivations deep, the grandchild
                // still holds no right the root lacked. this is what "authority
                // only ever decreases along the derivation tree" means.
                let grandchild_rights = space.lookup(grandchild).unwrap().rights;
                assert!(child_rights.contains(grandchild_rights));
                assert!(root_rights.contains(grandchild_rights));
            }
        }
    }

    // the operational form of no-amplification: if any descendant in a mint
    // chain passes check(required) (i.e. is permitted to perform an operation),
    // then the root ancestor also holds `required`. so a derived capability can
    // never authorize an operation the original could not: delegation cannot
    // manufacture authority. this is the property a confused-deputy attack would
    // have to violate.
    #[kani::proof]
    fn derived_authority_bounded_by_root() {
        let mut space: CapSpace<u32, 4> = CapSpace::new();
        let root_rights = Rights::from_bits_truncate(kani::any());
        let mask1 = Rights::from_bits_truncate(kani::any());
        let mask2 = Rights::from_bits_truncate(kani::any());
        let required = Rights::from_bits_truncate(kani::any());

        let root = space.insert(kani::any(), root_rights).unwrap();
        if let Ok(child) = space.mint(root, mask1) {
            if let Ok(grandchild) = space.mint(child, mask2) {
                // if the grandchild is allowed to do something requiring
                // `required`, the root must have been allowed it too.
                if space.check(grandchild, required) {
                    assert!(space.check(root, required));
                }
            }
        }
    }
}
