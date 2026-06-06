//! Capability rights -- a monotone permission bitset.
//!
//! A [`Rights`] value is a set of permissions that may be attached to a
//! capability. The four defined bits match the seL4 rights model:
//! `READ` (receive/read), `WRITE` (send/write), `GRANT` (delegate full
//! authority), and `GRANT_REPLY` (delegate reply-only).
//!
//! # Invariant
//!
//! Every `Rights` value contains only the four defined bits; the upper four
//! bits of the inner `u8` are always zero. [`Rights::from_bits_truncate`]
//! enforces this on construction by masking the input to `ALL`.
//!
//! # Attenuation is monotone
//!
//! [`Rights::attenuate`] computes the bitwise intersection of two `Rights`
//! values. Because intersection can only clear bits, never set them:
//!
//! - `a.attenuate(mask)` is a subset of `a` (no rights are added to `a`).
//! - `a.attenuate(mask)` is a subset of `mask` (no rights exceed the mask).
//! - `a.attenuate(mask).bits() <= a.bits()` (the raw value is non-increasing).
//!
//! This is the core correctness property of derived capabilities: a holder
//! may only pass on a subset of the rights they themselves possess.

/// A set of capability permissions.
///
/// Internally a `u8` with only the lower four bits ever set. Construct
/// values with the associated constants ([`Rights::NONE`], [`Rights::ALL`],
/// etc.) or with [`Rights::from_bits_truncate`] when parsing external input.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Rights(u8);

impl Rights {
    // -----------------------------------------------------------------------
    // bit constants
    // -----------------------------------------------------------------------

    /// No rights: the empty permission set.
    pub const NONE: Self = Self(0);

    /// Permission to receive from / read the object.
    pub const READ: Self = Self(1 << 0);

    /// Permission to send to / write the object.
    pub const WRITE: Self = Self(1 << 1);

    /// Permission to delegate full authority over this capability.
    pub const GRANT: Self = Self(1 << 2);

    /// Permission to delegate a reply-only derivative of this capability.
    pub const GRANT_REPLY: Self = Self(1 << 3);

    /// All four defined rights bits set.
    pub const ALL: Self = Self(0b0000_1111);

    /// Read and write permissions combined.
    pub const READ_WRITE: Self = Self((1 << 0) | (1 << 1));

    // mask of the four valid bits; used by from_bits_truncate.
    const VALID_MASK: u8 = 0b0000_1111;

    // -----------------------------------------------------------------------
    // constructors
    // -----------------------------------------------------------------------

    /// Returns the empty `Rights` set (no permissions).
    #[inline]
    #[must_use]
    pub const fn empty() -> Self {
        Self::NONE
    }

    /// Returns the full `Rights` set (all four permissions).
    #[inline]
    #[must_use]
    pub const fn all() -> Self {
        Self::ALL
    }

    /// Constructs `Rights` from a raw `u8`, silently discarding any bits
    /// outside the four defined positions.
    ///
    /// This is the canonical constructor when parsing external or
    /// untrusted input: high bits are stripped so the invariant holds.
    #[inline]
    #[must_use]
    pub const fn from_bits_truncate(bits: u8) -> Self {
        Self(bits & Self::VALID_MASK)
    }

    // -----------------------------------------------------------------------
    // accessors
    // -----------------------------------------------------------------------

    /// Returns the raw `u8` representation. The upper four bits are always
    /// zero.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Returns `true` if this set has no permissions.
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if every bit in `other` is also set in `self`.
    ///
    /// Passing [`Rights::NONE`] always returns `true`; passing a set with
    /// bits not present in `self` returns `false`.
    #[inline]
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns `true` if `self` and `other` share at least one common bit.
    #[inline]
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    // -----------------------------------------------------------------------
    // set operations
    // -----------------------------------------------------------------------

    /// Returns the union of `self` and `other` (bitwise OR).
    #[inline]
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns the intersection of `self` and `other` (bitwise AND).
    #[inline]
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    // -----------------------------------------------------------------------
    // attenuation
    // -----------------------------------------------------------------------

    /// Returns the rights that remain after applying `mask`.
    ///
    /// `attenuate` is the canonical operation for minting a derived
    /// capability: the caller specifies the maximum rights they are willing
    /// to grant (`mask`), and the result is the intersection with the rights
    /// they actually hold (`self`). The result is always a subset of both
    /// operands, so this operation can never add permissions.
    ///
    /// # Monotonicity
    ///
    /// For all `Rights` values `a` and `mask`:
    ///
    /// - `a.attenuate(mask).bits() <= a.bits()` (no rights added to `a`).
    /// - `a.attenuate(mask)` is contained in `a`.
    /// - `a.attenuate(mask)` is contained in `mask`.
    ///
    /// These properties are proved by the Kani harnesses in this module.
    #[inline]
    #[must_use]
    pub const fn attenuate(self, mask: Self) -> Self {
        Self(self.0 & mask.0)
    }
}

// ---------------------------------------------------------------------------
// unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::Rights;

    // ---- contains / intersects ---------------------------------------------

    #[test]
    fn contains_self_is_true() {
        let r = Rights::READ_WRITE;
        assert!(r.contains(r));
    }

    #[test]
    fn contains_subset_is_true() {
        assert!(Rights::ALL.contains(Rights::READ));
        assert!(Rights::ALL.contains(Rights::WRITE));
        assert!(Rights::ALL.contains(Rights::GRANT));
        assert!(Rights::ALL.contains(Rights::GRANT_REPLY));
        assert!(Rights::READ_WRITE.contains(Rights::READ));
        assert!(Rights::READ_WRITE.contains(Rights::WRITE));
    }

    #[test]
    fn contains_superset_is_false() {
        assert!(!Rights::READ.contains(Rights::READ_WRITE));
        assert!(!Rights::NONE.contains(Rights::READ));
    }

    #[test]
    fn contains_none_is_always_true() {
        // the empty set is a subset of every set.
        assert!(Rights::NONE.contains(Rights::NONE));
        assert!(Rights::READ.contains(Rights::NONE));
        assert!(Rights::ALL.contains(Rights::NONE));
    }

    #[test]
    fn intersects_overlapping_is_true() {
        assert!(Rights::READ_WRITE.intersects(Rights::READ));
        assert!(Rights::ALL.intersects(Rights::GRANT));
    }

    #[test]
    fn intersects_disjoint_is_false() {
        assert!(!Rights::READ.intersects(Rights::WRITE));
        assert!(!Rights::GRANT.intersects(Rights::GRANT_REPLY));
        assert!(!Rights::NONE.intersects(Rights::ALL));
    }

    // ---- union / intersection ----------------------------------------------

    #[test]
    fn union_combines_bits() {
        let r = Rights::READ.union(Rights::WRITE);
        assert_eq!(r, Rights::READ_WRITE);
    }

    #[test]
    fn union_with_none_is_identity() {
        assert_eq!(Rights::READ_WRITE.union(Rights::NONE), Rights::READ_WRITE);
    }

    #[test]
    fn union_with_all_is_all() {
        assert_eq!(Rights::READ.union(Rights::ALL), Rights::ALL);
    }

    #[test]
    fn intersection_common_bits() {
        let a = Rights::READ.union(Rights::GRANT);
        let b = Rights::READ.union(Rights::WRITE);
        assert_eq!(a.intersection(b), Rights::READ);
    }

    #[test]
    fn intersection_with_none_is_empty() {
        assert_eq!(Rights::ALL.intersection(Rights::NONE), Rights::NONE);
        assert!(Rights::ALL.intersection(Rights::NONE).is_empty());
    }

    #[test]
    fn intersection_with_all_is_identity() {
        assert_eq!(Rights::READ_WRITE.intersection(Rights::ALL), Rights::READ_WRITE);
    }

    // ---- attenuate ---------------------------------------------------------

    #[test]
    fn attenuate_reduces_to_mask() {
        // send-only attenuated by read-only gives empty.
        assert_eq!(Rights::WRITE.attenuate(Rights::READ), Rights::NONE);
    }

    #[test]
    fn attenuate_all_by_read_gives_read() {
        assert_eq!(Rights::ALL.attenuate(Rights::READ), Rights::READ);
    }

    #[test]
    fn attenuate_by_none_gives_empty() {
        assert_eq!(Rights::ALL.attenuate(Rights::NONE), Rights::NONE);
        assert_eq!(Rights::READ_WRITE.attenuate(Rights::NONE), Rights::NONE);
    }

    #[test]
    fn attenuate_by_all_is_identity() {
        assert_eq!(Rights::READ_WRITE.attenuate(Rights::ALL), Rights::READ_WRITE);
    }

    #[test]
    fn attenuate_result_subset_of_self() {
        let result = Rights::ALL.attenuate(Rights::READ_WRITE);
        assert!(Rights::ALL.contains(result));
    }

    #[test]
    fn attenuate_result_subset_of_mask() {
        let result = Rights::ALL.attenuate(Rights::READ_WRITE);
        assert!(Rights::READ_WRITE.contains(result));
    }

    #[test]
    fn attenuate_is_idempotent() {
        let a = Rights::ALL;
        let b = Rights::READ_WRITE;
        let once = a.attenuate(b);
        let twice = once.attenuate(b);
        assert_eq!(once, twice);
    }

    #[test]
    fn attenuate_commutes() {
        let a = Rights::ALL;
        let b = Rights::READ;
        assert_eq!(a.attenuate(b), b.attenuate(a));
    }

    // ---- empty / all edge cases --------------------------------------------

    #[test]
    fn empty_is_empty() {
        assert!(Rights::empty().is_empty());
        assert_eq!(Rights::empty(), Rights::NONE);
        assert_eq!(Rights::empty().bits(), 0);
    }

    #[test]
    fn all_is_not_empty() {
        assert!(!Rights::all().is_empty());
        assert_eq!(Rights::all(), Rights::ALL);
    }

    #[test]
    fn all_contains_every_defined_right() {
        assert!(Rights::ALL.contains(Rights::READ));
        assert!(Rights::ALL.contains(Rights::WRITE));
        assert!(Rights::ALL.contains(Rights::GRANT));
        assert!(Rights::ALL.contains(Rights::GRANT_REPLY));
    }

    // ---- from_bits_truncate ------------------------------------------------

    #[test]
    fn from_bits_truncate_drops_high_bits() {
        // bit 4 and above must be stripped.
        let r = Rights::from_bits_truncate(0b1111_0001);
        assert_eq!(r, Rights::READ);
        assert_eq!(r.bits(), 0x01);
    }

    #[test]
    fn from_bits_truncate_preserves_valid_bits() {
        let r = Rights::from_bits_truncate(0b0000_1111);
        assert_eq!(r, Rights::ALL);
    }

    #[test]
    fn from_bits_truncate_zero_is_none() {
        assert_eq!(Rights::from_bits_truncate(0), Rights::NONE);
    }

    // ---- const-eval (confirms const fn) ------------------------------------

    #[test]
    fn const_eval_works() {
        const R: Rights = Rights::READ.union(Rights::WRITE);
        const A: Rights = Rights::ALL.attenuate(R);
        const C: bool = A.contains(Rights::READ);
        const E: bool = A.is_empty();

        assert_eq!(R, Rights::READ_WRITE);
        assert_eq!(A, Rights::READ_WRITE);
        const { assert!(C) }
        const { assert!(!E) }
    }
}

// ---------------------------------------------------------------------------
// Kani bounded proof harnesses
// ---------------------------------------------------------------------------

#[cfg(kani)]
mod kani_proofs {
    use super::Rights;

    // helper: produce an arbitrary Rights with the invariant enforced.
    fn any_rights() -> Rights {
        Rights::from_bits_truncate(kani::any::<u8>())
    }

    /// `a.attenuate(b)` is contained in both `a` and `b`, and its raw bits
    /// are no greater than `a`'s raw bits.
    #[kani::proof]
    fn attenuation_is_monotone() {
        let a = any_rights();
        let b = any_rights();
        let result = a.attenuate(b);

        // result is a subset of a.
        assert!(a.contains(result));
        // result is a subset of b.
        assert!(b.contains(result));
        // raw value is non-increasing with respect to a.
        assert!(result.bits() <= a.bits());
    }

    /// Attenuating by the empty set always yields the empty set.
    #[kani::proof]
    fn attenuation_of_empty_is_empty() {
        let a = any_rights();
        assert_eq!(a.attenuate(Rights::empty()), Rights::empty());
    }

    /// Attenuating by `ALL` is the identity for any valid `Rights`.
    #[kani::proof]
    fn attenuation_by_all_is_identity() {
        let a = any_rights();
        assert_eq!(a.attenuate(Rights::all()), a);
    }

    /// Applying the same mask twice is the same as applying it once.
    #[kani::proof]
    fn attenuation_is_idempotent() {
        let a = any_rights();
        let b = any_rights();
        let once = a.attenuate(b);
        let twice = once.attenuate(b);
        assert_eq!(once, twice);
    }

    /// Attenuation is commutative (it is bitwise AND).
    #[kani::proof]
    fn attenuation_commutes() {
        let a = any_rights();
        let b = any_rights();
        assert_eq!(a.attenuate(b), b.attenuate(a));
    }

    /// Containment is transitive: if `a` contains `b` and `b` contains `c`, then
    /// `a` contains `c`. This is the foundational lemma behind the global
    /// no-amplification property: along a capability derivation chain each link
    /// is a subset of its parent (`attenuation_is_monotone`), so by transitivity
    /// the deepest descendant is a subset of the root. The chain form is proved
    /// over the real `CapSpace::mint` in `cap_space::kani_proofs`; this discharges
    /// the underlying set-theoretic step on the rights lattice itself.
    #[kani::proof]
    fn contains_is_transitive() {
        let a = any_rights();
        let b = any_rights();
        let c = any_rights();
        if a.contains(b) && b.contains(c) {
            assert!(a.contains(c));
        }
    }
}
