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
use crate::notification::Badge;
pub use crate::cap_table::InsertAtError;

/// Identifies a capability space, so a derivation link can point into any of
/// them. The kernel gives every space a distinct id when it registers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpaceId(pub u32);

/// A link to one capability in some capability space: the space plus the
/// generation-checked [`CapRef`] inside it. Parent links are `CapLink`s, so the
/// derivation tree can span spaces (a capability copied into another thread's
/// `CNode` still descends from its source, and revoking the source reaches it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapLink {
    /// The space holding the capability.
    pub space: SpaceId,
    /// The capability within that space.
    pub cap: CapRef,
}

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
    /// The capability this one was derived from, if any, possibly in another
    /// capability space. `None` marks an original capability (for example, the
    /// one produced by retyping untyped memory). Used to find descendants during
    /// revocation.
    pub parent: Option<CapLink>,
    /// The badge delivered to a receiver with every message sent through this
    /// capability, so a server can tell its clients apart. [`Badge::NONE`]
    /// means unbadged. Set at most once, by [`CapSpace::mint_badged`]; every
    /// later derivation inherits it unchanged.
    pub badge: Badge,
}

impl<O: Copy> Capability<O> {
    /// Creates an original, unbadged capability (no parent) with the given
    /// rights.
    #[must_use]
    pub const fn new(object: O, rights: Rights) -> Self {
        Self {
            object,
            rights,
            parent: None,
            badge: Badge::NONE,
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
    /// The source capability already carries a badge. A badge is set at most
    /// once and is never changed by a later derivation.
    AlreadyBadged,
}

/// A single-level capability space backed by a [`CapTable`] of `N` slots.
pub struct CapSpace<O: Copy, const N: usize> {
    /// This space's id, recorded in the parent links of capabilities derived
    /// from it.
    id: SpaceId,
    table: CapTable<Capability<O>, N>,
}

impl<O: Copy, const N: usize> CapSpace<O, N> {
    /// Creates an empty capability space with id 0. Use
    /// [`with_id`](Self::with_id) when several spaces must link to each other.
    #[must_use]
    pub fn new() -> Self {
        Self::with_id(SpaceId(0))
    }

    /// Creates an empty capability space with the given id.
    #[must_use]
    pub fn with_id(id: SpaceId) -> Self {
        Self {
            id,
            table: CapTable::new(),
        }
    }

    /// Returns this space's id.
    #[must_use]
    pub const fn id(&self) -> SpaceId {
        self.id
    }

    /// Sets this space's id. Only for a space that holds no capabilities yet,
    /// since existing links record the old id; returns `false` (changing
    /// nothing) otherwise.
    pub fn set_id(&mut self, id: SpaceId) -> bool {
        if !self.is_empty() {
            return false;
        }
        self.id = id;
        true
    }

    /// Initializes an empty capability space in place at `ptr`, without
    /// building it on the stack first. See [`CapTable::init_in_place`].
    ///
    /// # Safety
    ///
    /// `ptr` must be valid for writes of `Self` and properly aligned. Any value
    /// previously there is overwritten without being dropped.
    pub unsafe fn init_in_place(ptr: *mut Self) {
        // SAFETY: per this function's contract `ptr` is valid and aligned for
        // `Self`, and so for each of its fields.
        unsafe {
            core::ptr::addr_of_mut!((*ptr).id).write(SpaceId(0));
            CapTable::init_in_place(core::ptr::addr_of_mut!((*ptr).table));
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
            parent: Some(CapLink { space: self.id, cap: source }),
            // a plain mint inherits the badge, never changes it.
            badge: parent.badge,
        };
        self.table.insert(derived).map_err(|_| MintError::SpaceFull)
    }

    /// Derives a badged capability from an unbadged `source`, with rights
    /// attenuated by `mask`.
    ///
    /// This is the seL4 badge discipline: a server holding an unbadged
    /// endpoint capability mints one badged copy per client, and the badge is
    /// delivered with every message sent through that copy. The badge can be
    /// set only once, so a client can never relabel itself as another client.
    ///
    /// # Errors
    ///
    /// [`MintError::InvalidSource`] if `source` is stale;
    /// [`MintError::AlreadyBadged`] if `source` already carries a badge;
    /// [`MintError::SpaceFull`] if there is no free slot.
    pub fn mint_badged(
        &mut self,
        source: CapRef,
        mask: Rights,
        badge: Badge,
    ) -> Result<CapRef, MintError> {
        let parent = self.table.get(source).ok_or(MintError::InvalidSource)?;
        if !parent.badge.is_empty() {
            return Err(MintError::AlreadyBadged);
        }
        let derived = Capability {
            object: parent.object,
            rights: parent.rights.attenuate(mask),
            parent: Some(CapLink { space: self.id, cap: source }),
            badge,
        };
        self.table.insert(derived).map_err(|_| MintError::SpaceFull)
    }

    /// Derives a copy of the capability at `source` into slot `slot` of another
    /// space, `dest`, with rights attenuated by `mask` and the badge inherited.
    ///
    /// The copy's parent link points back to `source` in this space, so
    /// revoking the source with [`revoke_across`] reaches the copy. Like
    /// [`mint`](Self::mint), a copy can only lose rights, never gain them.
    ///
    /// # Errors
    ///
    /// See [`CopyError`].
    pub fn copy_into<const M: usize>(
        &self,
        source: CapRef,
        dest: &mut CapSpace<O, M>,
        slot: usize,
        mask: Rights,
    ) -> Result<CapRef, CopyError> {
        if dest.id == self.id {
            return Err(CopyError::SameSpace);
        }
        let parent = self.table.get(source).ok_or(CopyError::InvalidSource)?;
        let derived = Capability {
            object: parent.object,
            rights: parent.rights.attenuate(mask),
            parent: Some(CapLink { space: self.id, cap: source }),
            badge: parent.badge,
        };
        dest.table.insert_at(slot, derived).map_err(|e| match e {
            InsertAtError::OutOfRange => CopyError::OutOfRange,
            InsertAtError::Occupied => CopyError::Occupied,
        })
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
                // a link into another space leaves this space's tree.
                Some(p) if p.space != self.id => return false,
                Some(p) if p.cap == ancestor => return true,
                Some(p) => current = p.cap,
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

/// Errors from [`CapSpace::copy_into`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyError {
    /// The source `CapRef` does not name a live capability.
    InvalidSource,
    /// The destination slot is out of range.
    OutOfRange,
    /// The destination slot already holds a capability.
    Occupied,
    /// Both spaces carry the same id, so a link could not tell them apart.
    SameSpace,
}

/// Returns the capability `link` names among `spaces`, if it is live.
fn resolve<'a, O: Copy, const N: usize>(
    spaces: &'a [&mut CapSpace<O, N>],
    link: CapLink,
) -> Option<&'a Capability<O>> {
    spaces.iter().find(|s| s.id == link.space)?.lookup(link.cap)
}

/// Returns `true` if `link` is `ancestor`, or descends from it through parent
/// links that may cross between `spaces`.
fn descends_across<O: Copy, const N: usize>(
    spaces: &[&mut CapSpace<O, N>],
    link: CapLink,
    ancestor: CapLink,
) -> bool {
    let mut current = link;
    // bound the walk by the total slot count so a corrupted cycle cannot hang.
    for _ in 0..=spaces.len() * N {
        if current == ancestor {
            return true;
        }
        match resolve(spaces, current).and_then(|cap| cap.parent) {
            Some(parent) => current = parent,
            None => return false,
        }
    }
    false
}

/// Returns `true` if any capability in `spaces` names `link` as its parent.
fn has_child<O: Copy, const N: usize>(spaces: &[&mut CapSpace<O, N>], link: CapLink) -> bool {
    let mut found = false;
    for space in spaces {
        space.table.for_each(|_, cap| found |= cap.parent == Some(link));
    }
    found
}

/// Calls `f` with every live capability in the subtree rooted at `root` (the
/// root included), wherever in `spaces` it lives, without removing anything.
///
/// This visits exactly the set [`revoke_across`] would remove, so a caller can
/// act on those capabilities' objects first (for example, waking IPC waiters
/// parked on an endpoint about to be revoked).
pub fn for_each_descendant_across<O: Copy, const N: usize>(
    spaces: &[&mut CapSpace<O, N>],
    root: CapLink,
    mut f: impl FnMut(CapLink, &Capability<O>),
) {
    for space in spaces {
        space.table.for_each(|cap_ref, cap| {
            let link = CapLink { space: space.id, cap: cap_ref };
            if descends_across(spaces, link, root) {
                f(link, cap);
            }
        });
    }
}

/// Revokes `root` and everything derived from it, in every space in `spaces`,
/// and returns how many capabilities were removed.
///
/// It removes the subtree leaves first: each step finds a capability in the
/// subtree that no other capability names as its parent and removes it. Every
/// link it follows to decide membership therefore stays intact until the
/// capability holding it is itself removed, with no scratch storage needed.
pub fn revoke_across<O: Copy, const N: usize>(
    spaces: &mut [&mut CapSpace<O, N>],
    root: CapLink,
) -> usize {
    let mut removed = 0;
    while let Some(leaf) = find_leaf(spaces, root) {
        if let Some(space) = spaces.iter_mut().find(|s| s.id == leaf.space) {
            space.table.remove(leaf.cap);
        }
        removed += 1;
    }
    removed
}

/// Returns a capability in the subtree rooted at `root` that has no children.
fn find_leaf<O: Copy, const N: usize>(spaces: &[&mut CapSpace<O, N>], root: CapLink) -> Option<CapLink> {
    let mut found = None;
    for space in spaces {
        space.table.for_each(|cap_ref, _| {
            let link = CapLink { space: space.id, cap: cap_ref };
            if found.is_none() && descends_across(spaces, link, root) && !has_child(spaces, link) {
                found = Some(link);
            }
        });
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    // the test harness links std, so we can use std helpers here even though
    // the library itself is no_std.
    extern crate std;

    /// A tiny object handle for tests: just an id.
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
        assert_eq!(space.lookup(ro).unwrap().parent, Some(CapLink { space: space.id(), cap: full }));
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

    #[test]
    fn copy_into_attenuates_and_links_back() {
        let mut a: CapSpace<Obj, 4> = CapSpace::with_id(SpaceId(1));
        let mut b: CapSpace<Obj, 4> = CapSpace::with_id(SpaceId(2));
        let src = a.insert(7, Rights::all()).unwrap();
        let copy = a.copy_into(src, &mut b, 3, Rights::READ).unwrap();
        assert_eq!(copy.slot(), 3);
        let cap = b.lookup(copy).unwrap();
        assert_eq!((cap.object, cap.rights), (7, Rights::READ));
        assert_eq!(cap.parent, Some(CapLink { space: SpaceId(1), cap: src }));
    }

    #[test]
    fn copy_into_refuses_a_space_with_the_same_id() {
        let mut a: CapSpace<Obj, 4> = CapSpace::with_id(SpaceId(1));
        let mut b: CapSpace<Obj, 4> = CapSpace::with_id(SpaceId(1));
        let src = a.insert(7, Rights::all()).unwrap();
        assert_eq!(a.copy_into(src, &mut b, 0, Rights::all()), Err(CopyError::SameSpace));
    }

    #[test]
    fn revoke_across_reaches_copies_in_other_spaces() {
        let mut a: CapSpace<Obj, 4> = CapSpace::with_id(SpaceId(1));
        let mut b: CapSpace<Obj, 4> = CapSpace::with_id(SpaceId(2));
        let root = a.insert(7, Rights::all()).unwrap();
        let child = a.mint(root, Rights::READ_WRITE).unwrap();
        // a copy of the child in b, and a copy of that copy back in a.
        let in_b = a.copy_into(child, &mut b, 0, Rights::all()).unwrap();
        b.copy_into(in_b, &mut a, 3, Rights::READ).unwrap();
        // an unrelated original in b survives.
        let other = b.insert(9, Rights::all()).unwrap();
        let removed = revoke_across(&mut [&mut a, &mut b], CapLink { space: SpaceId(1), cap: root });
        assert_eq!(removed, 4);
        assert!(a.is_empty());
        assert_eq!(b.len(), 1);
        assert!(b.lookup(other).is_some());
    }

    #[test]
    fn revoking_a_copy_leaves_its_source() {
        let mut a: CapSpace<Obj, 4> = CapSpace::with_id(SpaceId(1));
        let mut b: CapSpace<Obj, 4> = CapSpace::with_id(SpaceId(2));
        let src = a.insert(7, Rights::all()).unwrap();
        let copy = a.copy_into(src, &mut b, 0, Rights::all()).unwrap();
        let removed = revoke_across(&mut [&mut a, &mut b], CapLink { space: SpaceId(2), cap: copy });
        assert_eq!(removed, 1);
        assert!(a.lookup(src).is_some());
        assert!(b.is_empty());
    }

    #[test]
    fn init_in_place_builds_an_empty_space() {
        let mut slot = core::mem::MaybeUninit::<CapSpace<Obj, 8>>::uninit();
        // SAFETY: the MaybeUninit is valid for writes of the space and aligned.
        unsafe { CapSpace::init_in_place(slot.as_mut_ptr()) };
        // SAFETY: init_in_place initialized every field.
        let space = unsafe { slot.assume_init_mut() };
        assert!(space.is_empty());
        let r = space.insert(3, Rights::all()).unwrap();
        assert_eq!(space.lookup(r).unwrap().object, 3);
        assert_eq!(space.len(), 1);
    }

    #[test]
    fn mint_badged_stamps_and_children_inherit() {
        let mut space: CapSpace<Obj, 8> = CapSpace::new();
        let root = space.insert(1, Rights::all()).unwrap();
        let badged = space.mint_badged(root, Rights::WRITE, Badge(42)).unwrap();
        assert_eq!(space.lookup(badged).unwrap().badge, Badge(42));
        assert_eq!(space.lookup(badged).unwrap().rights, Rights::WRITE);
        // a plain mint from the badged cap keeps the badge.
        let child = space.mint(badged, Rights::all()).unwrap();
        assert_eq!(space.lookup(child).unwrap().badge, Badge(42));
        // the root stays unbadged.
        assert_eq!(space.lookup(root).unwrap().badge, Badge::NONE);
    }

    #[test]
    fn mint_badged_refuses_rebadging() {
        let mut space: CapSpace<Obj, 8> = CapSpace::new();
        let root = space.insert(1, Rights::all()).unwrap();
        let badged = space.mint_badged(root, Rights::all(), Badge(1)).unwrap();
        assert_eq!(
            space.mint_badged(badged, Rights::all(), Badge(2)),
            Err(MintError::AlreadyBadged)
        );
    }

    #[test]
    fn revoke_removes_badged_children() {
        let mut space: CapSpace<Obj, 8> = CapSpace::new();
        let root = space.insert(1, Rights::all()).unwrap();
        let a = space.mint_badged(root, Rights::WRITE, Badge(1)).unwrap();
        let b = space.mint_badged(root, Rights::WRITE, Badge(2)).unwrap();
        assert_eq!(space.revoke(root), 3);
        assert!(space.lookup(a).is_none());
        assert!(space.lookup(b).is_none());
    }
}

/// Bounded proofs of the capability-space invariants.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Minting never grants a right the source did not have.
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

    /// Check() passes only when the live capability holds all required rights.
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

    /// A removed capability is never accepted by check, for any rights.
    #[kani::proof]
    fn removed_cap_never_checks() {
        let mut space: CapSpace<u32, 4> = CapSpace::new();
        let r = space.insert(kani::any(), Rights::all()).unwrap();
        space.remove(r);
        let required = Rights::from_bits_truncate(kani::any());
        assert!(!space.check(r, required));
    }

    /// The global no-amplification property, the headline security guarantee:
    /// along a derivation CHAIN of arbitrary masks, no descendant holds a right
    /// its root ancestor lacked. mint_never_escalates proves one link; this
    /// proves the transitive closure over a three-deep chain (root -> child ->
    /// grandchild), which by induction stands for any depth (each mint only
    /// attenuates, and contains is transitive, proved in cap_rights). A 4-slot
    /// space holds the whole chain; any mint may legitimately fail with
    /// SpaceFull, so each link is guarded rather than unwrapped.
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

    /// The operational form of no-amplification: if any descendant in a mint
    /// chain passes check(required) (i.e. is permitted to perform an operation),
    /// then the root ancestor also holds `required`. So a derived capability can
    /// never authorize an operation the original could not: delegation cannot
    /// manufacture authority. This is the property a confused-deputy attack would
    /// have to violate.
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

    /// A badge, once set, is never changed: a child of a badged cap carries the
    /// same badge, and re-badging it is refused. This stops a client from
    /// impersonating another client to a server.
    #[kani::proof]
    fn badge_is_immutable_once_set() {
        let mut space: CapSpace<u32, 4> = CapSpace::new();
        let root = space.insert(kani::any(), Rights::from_bits_truncate(kani::any())).unwrap();
        let b1 = Badge(kani::any());
        kani::assume(!b1.is_empty());
        let badged = space.mint_badged(root, Rights::from_bits_truncate(kani::any()), b1).unwrap();
        if let Ok(child) = space.mint(badged, Rights::from_bits_truncate(kani::any())) {
            assert!(space.lookup(child).unwrap().badge == b1);
            assert!(
                space.mint_badged(child, Rights::all(), Badge(kani::any()))
                    == Err(MintError::AlreadyBadged)
            );
        }
    }

    /// A copy into another space never grants a right the source lacked.
    #[kani::proof]
    fn copy_never_escalates() {
        let mut a: CapSpace<u32, 2> = CapSpace::with_id(SpaceId(1));
        let mut b: CapSpace<u32, 2> = CapSpace::with_id(SpaceId(2));
        let src_rights = Rights::from_bits_truncate(kani::any());
        let mask = Rights::from_bits_truncate(kani::any());
        let src = a.insert(kani::any(), src_rights).unwrap();
        if let Ok(copy) = a.copy_into(src, &mut b, kani::any(), mask) {
            let rights = b.lookup(copy).unwrap().rights;
            assert!(src_rights.contains(rights));
            assert!(mask.contains(rights));
        }
    }

    /// Revoking an original removes every copy of it in another space, and of
    /// those copies, while an unrelated capability survives.
    #[kani::proof]
    #[kani::unwind(8)]
    fn revoke_across_removes_every_copy() {
        let mut a: CapSpace<u32, 3> = CapSpace::with_id(SpaceId(1));
        let mut b: CapSpace<u32, 3> = CapSpace::with_id(SpaceId(2));
        let root = a.insert(kani::any(), Rights::from_bits_truncate(kani::any())).unwrap();
        let copy = a.copy_into(root, &mut b, 0, Rights::from_bits_truncate(kani::any())).unwrap();
        let _ = b.mint(copy, Rights::from_bits_truncate(kani::any()));
        let other = b.insert_at(2, kani::any(), Rights::all()).unwrap();
        revoke_across(&mut [&mut a, &mut b], CapLink { space: SpaceId(1), cap: root });
        assert!(a.is_empty());
        assert!(b.len() == 1);
        assert!(b.lookup(other).is_some());
    }

    /// Badging is still a mint: it never grants a right the source lacked.
    #[kani::proof]
    fn mint_badged_never_escalates() {
        let mut space: CapSpace<u32, 4> = CapSpace::new();
        let src_rights = Rights::from_bits_truncate(kani::any());
        let mask = Rights::from_bits_truncate(kani::any());
        let src = space.insert(kani::any(), src_rights).unwrap();
        if let Ok(child) = space.mint_badged(src, mask, Badge(kani::any())) {
            let child_rights = space.lookup(child).unwrap().rights;
            assert!(src_rights.contains(child_rights));
            assert!(mask.contains(child_rights));
        }
    }
}
