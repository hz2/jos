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
// SyscallEvent
// ---------------------------------------------------------------------------

/// A record of one system call crossing the kernel's syscall boundary.
///
/// Where [`TraceEvent`] is the host-side, model-level record the DST harness
/// produces, this is the record the *kernel itself* emits: one event per
/// invocation of the syscall dispatcher, the mandatory chokepoint every
/// capability operation from userspace passes through. A per-CPU ring buffer of
/// these is jos's structured trace, and an ordered sequence of them is the
/// record half of record/replay on real hardware.
///
/// The fields are the raw ABI values rather than decoded enums, deliberately:
/// the kernel logs exactly what crossed the boundary (the syscall number and
/// its register arguments, plus the value returned in `rax`), so the trace is a
/// faithful, replayable record independent of how the kernel happens to
/// interpret those bits today. A consumer that wants the decoded form maps
/// `syscall` through the kernel's `Syscall` enum. All fields are `u64` (no
/// platform-width or pointer types), so the event is fixed-size and shaped for
/// wire or snapshot serialization, like the rest of this module.
///
/// Under the `postcard` feature it derives `serde::Serialize` /
/// `Deserialize`, so [`codec`] can encode it for off-box capture. The derive is
/// feature-gated so the default, Kani, and Miri builds stay dependency-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "postcard", derive(serde::Serialize, serde::Deserialize))]
pub struct SyscallEvent {
    /// Monotone per-buffer sequence number; gives total order within one trace.
    pub seq: u64,
    /// The raw syscall number presented in `rax` (maps to the kernel's
    /// `Syscall` enum; an unknown number is recorded verbatim, not dropped).
    pub syscall: u64,
    /// The three register arguments (`rdi`, `rsi`, `rdx`) as presented.
    pub args: [u64; 3],
    /// The value returned to userspace in `rax`.
    pub result: u64,
}

impl SyscallEvent {
    /// Builds a syscall event from its parts.
    #[must_use]
    pub const fn new(seq: u64, syscall: u64, args: [u64; 3], result: u64) -> Self {
        Self {
            seq,
            syscall,
            args,
            result,
        }
    }
}

// ---------------------------------------------------------------------------
// postcard codec (feature-gated, for off-box capture)
// ---------------------------------------------------------------------------

/// Serialization of trace events for off-box capture, over `postcard`.
///
/// `postcard` is a compact, `no_std`, allocation-free wire format: a
/// [`SyscallEvent`] encodes to a handful of bytes (its `u64` fields become
/// LEB128 varints), with no schema or framing assumptions baked in. This module
/// wraps the slice-based encode/decode (no heap, suitable for the kernel) and
/// adds COBS framing, which delimits records with a zero byte so a stream of
/// events can be split back apart on the receiving side.
///
/// The whole module is gated behind the `postcard` feature, so it exists only
/// when a consumer (the kernel's off-box trace dump) opts in; the default,
/// Kani, and Miri builds never pull `serde` or `postcard`.
#[cfg(feature = "postcard")]
pub mod codec {
    use super::SyscallEvent;

    /// A safe upper bound on the encoded size of one [`SyscallEvent`], framed.
    ///
    /// A `SyscallEvent` is six `u64` fields (`seq`, `syscall`, three `args`,
    /// `result`). `postcard` encodes each `u64` as a LEB128 varint of at most 10
    /// bytes, so the plain encoding is at most 60 bytes. COBS framing adds at
    /// most one overhead byte per 254 bytes plus a trailing delimiter, so 64
    /// bytes is a comfortable ceiling for one framed event. A caller sizing a
    /// per-event scratch buffer can use this constant.
    pub const MAX_FRAMED_EVENT_LEN: usize = 64;

    /// Encodes `event` into `buf` (no framing), returning the written prefix.
    ///
    /// # Errors
    ///
    /// Returns the `postcard` error if `buf` is too small (it must hold the
    /// varint encoding; see [`MAX_FRAMED_EVENT_LEN`] for a safe size).
    pub fn encode<'a>(
        event: &SyscallEvent,
        buf: &'a mut [u8],
    ) -> postcard::Result<&'a mut [u8]> {
        postcard::to_slice(event, buf)
    }

    /// Decodes one [`SyscallEvent`] from `bytes` (no framing).
    ///
    /// # Errors
    ///
    /// Returns the `postcard` error if `bytes` is not a valid encoding.
    pub fn decode(bytes: &[u8]) -> postcard::Result<SyscallEvent> {
        postcard::from_bytes(bytes)
    }

    /// Encodes `event` into `buf` as a COBS-framed record, returning the framed
    /// bytes (including the trailing zero delimiter).
    ///
    /// COBS framing lets a receiver split a concatenated stream of events back
    /// into records by scanning for the zero delimiter, which is what makes a
    /// drained trace buffer reconstructable off-box.
    ///
    /// # Errors
    ///
    /// Returns the `postcard` error if `buf` is too small.
    pub fn encode_framed<'a>(
        event: &SyscallEvent,
        buf: &'a mut [u8],
    ) -> postcard::Result<&'a mut [u8]> {
        postcard::to_slice_cobs(event, buf)
    }

    /// Decodes the first COBS-framed [`SyscallEvent`] from `bytes`, returning it
    /// along with the remaining bytes after the frame.
    ///
    /// Call repeatedly, feeding back the returned remainder, to decode a stream
    /// of framed events. `bytes` is mutated in place (COBS decoding is
    /// destructive), so pass a scratch copy if the original must be preserved.
    ///
    /// # Errors
    ///
    /// Returns the `postcard` error if no complete, valid frame is present.
    pub fn decode_framed(bytes: &mut [u8]) -> postcard::Result<(SyscallEvent, &mut [u8])> {
        postcard::take_from_bytes_cobs(bytes)
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
    fn events_compare_unequal_when_any_field_differs() {
        // equality must discriminate on every field: a record/replay diff or a
        // trace consumer relies on two events being unequal when their seq, op,
        // OR outcome differs, not just when the whole struct happens to match. a
        // derived PartialEq that ignored a field would pass a naive "build one,
        // copy it, compare" test but fail here.
        let base = TraceEvent::new(
            7,
            CapOp::Insert {
                object: ObjectToken(0xAB),
                rights: Rights::READ_WRITE,
            },
            CapOutcome::Installed { slot: 2 },
        );
        // differs only in seq.
        let other_seq = TraceEvent::new(8, base.op, base.outcome);
        assert_ne!(base, other_seq, "events with different seq must differ");
        // differs only in the op's rights field.
        let other_op = TraceEvent::new(
            base.seq,
            CapOp::Insert {
                object: ObjectToken(0xAB),
                rights: Rights::READ, // was READ_WRITE
            },
            base.outcome,
        );
        assert_ne!(base, other_op, "events with different op must differ");
        // differs only in the outcome's slot.
        let other_outcome =
            TraceEvent::new(base.seq, base.op, CapOutcome::Installed { slot: 3 });
        assert_ne!(base, other_outcome, "events with different outcome must differ");
        // and an identical rebuild compares equal (the positive half).
        let same = TraceEvent::new(7, base.op, base.outcome);
        assert_eq!(base, same);
    }

    #[test]
    fn object_token_orders_and_compares() {
        // object tokens compare by identity, so a trace consumer can tell
        // whether two capabilities name the same object.
        assert_eq!(ObjectToken(5), ObjectToken(5));
        assert_ne!(ObjectToken(5), ObjectToken(6));
        assert!(ObjectToken(1) < ObjectToken(2));
    }

    #[test]
    fn syscall_event_carries_raw_abi_values() {
        use super::SyscallEvent;
        // a syscall event records the raw boundary values verbatim, so a replay
        // can re-present the identical (number, args) and expect the same result.
        let ev = SyscallEvent::new(3, 7, [0xAA, 0xBB, 0xCC], 0xD00D);
        let copy = ev; // Copy, like the rest of the trace vocabulary.
        assert_eq!(ev, copy);
        assert_eq!(ev.seq, 3);
        assert_eq!(ev.syscall, 7);
        assert_eq!(ev.args, [0xAA, 0xBB, 0xCC]);
        assert_eq!(ev.result, 0xD00D);
    }
}

// postcard round-trip tests, compiled only when the feature (and so the codec)
// is present. they link std via the test harness; the library stays no_std.
#[cfg(all(test, feature = "postcard"))]
mod codec_tests {
    use super::codec::{self, MAX_FRAMED_EVENT_LEN};
    use super::SyscallEvent;
    extern crate std;
    use std::vec::Vec;

    #[test]
    fn plain_round_trip_recovers_the_event() {
        let ev = SyscallEvent::new(42, 4, [0x1111, 0x2222, 0x3333], 0xDEAD_BEEF);
        let mut buf = [0u8; MAX_FRAMED_EVENT_LEN];
        let encoded = codec::encode(&ev, &mut buf).expect("encode fits");
        let decoded = codec::decode(encoded).expect("decode succeeds");
        assert_eq!(decoded, ev, "plain round trip must recover the exact event");
    }

    #[test]
    fn framed_round_trip_recovers_the_event() {
        let ev = SyscallEvent::new(7, 2, [0, u64::MAX, 1], 0);
        let mut buf = [0u8; MAX_FRAMED_EVENT_LEN];
        let framed = codec::encode_framed(&ev, &mut buf).expect("encode fits");
        // a COBS frame ends in a zero delimiter and contains no interior zeros.
        assert_eq!(framed.last(), Some(&0), "COBS frame ends in a zero delimiter");
        let (decoded, rest) = codec::decode_framed(framed).expect("decode one frame");
        assert_eq!(decoded, ev);
        assert!(rest.is_empty(), "a single frame leaves no trailing bytes");
    }

    #[test]
    fn a_stream_of_framed_events_splits_back_apart() {
        // the off-box case: many events concatenated as COBS frames, decoded one
        // at a time by feeding the remainder back in. this is what reconstructs a
        // drained trace buffer on the receiving side.
        let events = [
            SyscallEvent::new(0, 0, [1, 2, 3], 6),
            SyscallEvent::new(1, 4, [0, 0, 0], 0),
            SyscallEvent::new(2, 3, [u64::MAX, 0, 7], u64::MAX),
        ];
        let mut stream: Vec<u8> = Vec::new();
        for ev in &events {
            let mut buf = [0u8; MAX_FRAMED_EVENT_LEN];
            let framed = codec::encode_framed(ev, &mut buf).expect("encode fits");
            stream.extend_from_slice(framed);
        }
        // decode the concatenated stream back into the original sequence.
        let mut remaining = stream.as_mut_slice();
        let mut recovered = Vec::new();
        while !remaining.is_empty() {
            let (ev, rest) = codec::decode_framed(remaining).expect("decode a frame");
            recovered.push(ev);
            remaining = rest;
        }
        assert_eq!(recovered, events, "the stream must split back into the originals");
    }

    #[test]
    fn worst_case_event_fits_the_size_bound() {
        // every field at u64::MAX is the largest varint encoding; it must still
        // fit MAX_FRAMED_EVENT_LEN, the constant callers size scratch buffers by.
        let ev = SyscallEvent::new(u64::MAX, u64::MAX, [u64::MAX; 3], u64::MAX);
        let mut buf = [0u8; MAX_FRAMED_EVENT_LEN];
        let framed = codec::encode_framed(&ev, &mut buf).expect("worst case must fit the bound");
        assert!(framed.len() <= MAX_FRAMED_EVENT_LEN);
        let (decoded, _) = codec::decode_framed(framed).expect("decode");
        assert_eq!(decoded, ev);
    }
}
