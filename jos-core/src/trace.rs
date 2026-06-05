//! Structured capability trace events: the record/replay vocabulary.
//!
//! Every capability-mediated operation is, by the microkernel's design, an
//! explicit kernel-mediated invocation (VISION: the kernel is a mandatory
//! chokepoint). This module gives that chokepoint a structured vocabulary: a
//! [`CapOp`] (what was requested), a [`CapOutcome`] (what the verified core
//! returned), and a [`TraceEvent`] pairing them with a sequence number.
//!
//! These types wear two hats, and both are load-bearing for Phase 3:
//!
//! - **Workload alphabet.** The deterministic-simulation harness draws a stream
//!   of [`CapOp`]s from a seeded [`crate::rng::KernelRng`] and applies them to a
//!   [`crate::cap_space::CapSpace`]. The op set is exactly the space's mutating
//!   and query operations.
//! - **Record/replay log.** An ordered sequence of [`TraceEvent`]s is a complete
//!   record of everything that happened to a capability space. Reset the space
//!   to empty and re-apply the ops in `seq` order and you reconstruct the exact
//!   final state. This is the "IPC log = replay" property (VISION star 5)
//!   applied first to the capability table, the simplest deterministic core.
//!
//! # Addressing model
//!
//! Capabilities are named by **slot index**, not by an in-memory `CapRef`. This
//! matches the syscall boundary, where userspace presents a plain slot index
//! that the kernel resolves against the current `CSpace` per call (via
//! [`CapSpace::ref_at`](crate::cap_space::CapSpace::ref_at)). A slot index is
//! also stable across a record/replay reset, where a `CapRef`'s generation
//! would not be, so it is the right thing to log.
//!
//! # Serialization
//!
//! The types are plain data (no references, no platform-width fields: slots are
//! `u32`, object tokens and sequence numbers `u64`), so they are shaped for
//! wire/snapshot serialization. The actual `postcard` derives are deferred to
//! keep `jos-core` dependency-free; adding `#[derive(Serialize, Deserialize)]`
//! behind a feature is a later, purely additive step.

use crate::cap_rights::Rights;

/// An opaque identity for the kernel object a capability names, as it appears in
/// a trace.
///
/// In the kernel this is a reduction of an `ObjectId` (for example its address);
/// in the simulation harness it is a synthetic id assigned to each created
/// object. The trace only needs object *identity* (to tell whether two
/// capabilities name the same object), not the object's representation, so a
/// single `u64` token suffices and keeps the trace independent of kernel layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectToken(pub u64);

/// A capability-mediated operation: the request half of a [`TraceEvent`].
///
/// The variants are exactly the operations a [`CapSpace`](crate::cap_space::CapSpace)
/// exposes. Slot-addressed (see the module's addressing model). IPC operations
/// (send/recv over an endpoint capability) join this enum in the IPC simulation
/// slice; this first cut covers the capability table itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapOp {
    /// Install an original capability (no parent) for `object` with `rights`,
    /// at the lowest free slot.
    Insert {
        /// The object the new capability names.
        object: ObjectToken,
        /// The rights the new capability carries.
        rights: Rights,
    },
    /// Derive a child of the capability at slot `source`, attenuated by `mask`,
    /// into the lowest free slot.
    Mint {
        /// Slot of the source (parent) capability.
        source: u32,
        /// Rights mask intersected with the source's rights.
        mask: Rights,
    },
    /// Remove the single capability at `slot` (no subtree).
    Remove {
        /// Slot of the capability to remove.
        slot: u32,
    },
    /// Revoke the capability at `slot` and its entire derivation subtree.
    Revoke {
        /// Slot of the subtree root to revoke.
        slot: u32,
    },
    /// Query whether the capability at `slot` is live and carries `required`.
    /// A pure read: it never changes the space.
    Check {
        /// Slot of the capability to check.
        slot: u32,
        /// Rights the check requires.
        required: Rights,
    },
}

impl CapOp {
    /// Returns `true` if applying this op can change the capability space.
    ///
    /// [`Check`](CapOp::Check) is the only pure query; every other op may
    /// install or remove capabilities. Used by the harness and by replay to
    /// tell state-changing events from observations.
    #[must_use]
    pub const fn is_mutating(self) -> bool {
        !matches!(self, CapOp::Check { .. })
    }
}

/// Why a capability operation did not take effect.
///
/// Mirrors the error cases the verified [`CapSpace`](crate::cap_space::CapSpace)
/// operations return ([`MintError`](crate::cap_space::MintError) and the full
/// [`insert`](crate::cap_space::CapSpace::insert) case), collapsed to the
/// reasons that matter to a trace consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The addressed source slot held no live capability (a stale or empty
    /// slot). Corresponds to `MintError::InvalidSource`.
    StaleSlot,
    /// The capability space had no free slot for the new capability.
    /// Corresponds to `MintError::SpaceFull` (and the full [`insert`] case).
    ///
    /// [`insert`]: crate::cap_space::CapSpace::insert
    SpaceFull,
}

/// The result half of a [`TraceEvent`]: what the verified core returned.
///
/// Each [`CapOp`] maps onto exactly one outcome shape, so a `(CapOp, CapOutcome)`
/// pair is a faithful record of one invocation:
///
/// - `Insert` / `Mint` succeed as [`Installed`](CapOutcome::Installed) (carrying
///   the destination slot) or fail as [`Refused`](CapOutcome::Refused).
/// - `Remove` / `Revoke` report a [`Removed`](CapOutcome::Removed) count
///   (`Remove` is 0 or 1; `Revoke` is the subtree size).
/// - `Check` reports [`Checked`](CapOutcome::Checked) with the boolean verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapOutcome {
    /// A capability was installed or derived at the given slot.
    Installed {
        /// Slot the new capability landed in.
        slot: u32,
    },
    /// A number of capabilities were removed (0 for a no-op remove of a stale
    /// slot; the subtree size for a revoke).
    Removed {
        /// How many capabilities the operation removed.
        count: u32,
    },
    /// A [`Check`](CapOp::Check) returned this verdict.
    Checked {
        /// `true` iff the capability was live and held the required rights.
        allowed: bool,
    },
    /// The operation was refused and the space is unchanged.
    Refused(Refusal),
}

impl CapOutcome {
    /// Returns `true` if this outcome is a [`Refused`](CapOutcome::Refused).
    #[must_use]
    pub const fn is_refused(self) -> bool {
        matches!(self, CapOutcome::Refused(_))
    }
}

/// One entry in a capability trace: an operation, its outcome, and a monotone
/// sequence number giving total order.
///
/// The sequence number is assigned by whoever records the event (the harness,
/// or the kernel's per-CPU trace buffer); it is strictly increasing within a
/// single log, so sorting by `seq` reconstructs the order of invocation. Replay
/// applies the `op`s in `seq` order to a fresh space; the recorded `outcome`s
/// are the oracle the replay must reproduce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceEvent {
    /// Monotone sequence number; total order within one log.
    pub seq: u64,
    /// The operation that was invoked.
    pub op: CapOp,
    /// What the verified core returned for it.
    pub outcome: CapOutcome,
}

impl TraceEvent {
    /// Builds a trace event from its parts.
    #[must_use]
    pub const fn new(seq: u64, op: CapOp, outcome: CapOutcome) -> Self {
        Self { seq, op, outcome }
    }
}

// ---------------------------------------------------------------------------
// unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{CapOp, CapOutcome, ObjectToken, Refusal, TraceEvent};
    use crate::cap_rights::Rights;

    #[test]
    fn check_is_the_only_non_mutating_op() {
        let mutating = [
            CapOp::Insert {
                object: ObjectToken(1),
                rights: Rights::all(),
            },
            CapOp::Mint {
                source: 0,
                mask: Rights::READ,
            },
            CapOp::Remove { slot: 3 },
            CapOp::Revoke { slot: 0 },
        ];
        for op in mutating {
            assert!(op.is_mutating(), "{op:?} should be mutating");
        }
        let check = CapOp::Check {
            slot: 0,
            required: Rights::READ,
        };
        assert!(!check.is_mutating());
    }

    #[test]
    fn is_refused_classifies_outcomes() {
        assert!(CapOutcome::Refused(Refusal::SpaceFull).is_refused());
        assert!(CapOutcome::Refused(Refusal::StaleSlot).is_refused());
        assert!(!CapOutcome::Installed { slot: 0 }.is_refused());
        assert!(!CapOutcome::Removed { count: 2 }.is_refused());
        assert!(!CapOutcome::Checked { allowed: false }.is_refused());
    }

    #[test]
    fn event_is_plain_copyable_data() {
        // a TraceEvent is Copy: storing one in a log and keeping the original is
        // a copy, not a move. (this is what lets a harness push events into a
        // Vec while still inspecting them.)
        let ev = TraceEvent::new(
            7,
            CapOp::Insert {
                object: ObjectToken(0xAB),
                rights: Rights::READ_WRITE,
            },
            CapOutcome::Installed { slot: 2 },
        );
        let copy = ev;
        assert_eq!(ev, copy);
        assert_eq!(ev.seq, 7);
        assert_eq!(copy.outcome, CapOutcome::Installed { slot: 2 });
    }

    #[test]
    fn object_token_orders_and_compares() {
        // object tokens compare by identity, so a trace consumer can tell
        // whether two capabilities name the same object.
        assert_eq!(ObjectToken(5), ObjectToken(5));
        assert_ne!(ObjectToken(5), ObjectToken(6));
        assert!(ObjectToken(1) < ObjectToken(2));
    }
}
