//! Deterministic fault injection for the capability-space DST harness.
//!
//! `TigerBeetle`'s deterministic simulation testing rests on running the system
//! across thousands of reproducible scenarios in which the simulated
//! environment is hostile: it drops, delays, reorders, duplicates, and corrupts
//! the messages flowing through it. For jos, the "messages" are capability
//! operations arriving from an untrusted caller across the syscall boundary, so
//! fault injection here is also a security stress test: the verified core must
//! uphold its safety invariants no matter what sequence it is fed.
//!
//! A [`FaultInjector`] transforms an incoming stream of [`CapOp`]s into a
//! *realized* stream by applying faults drawn from a seeded [`KernelRng`]. The
//! same seed always produces the same fault schedule, so a failure found under
//! simulation reproduces exactly. The injector sits above both the
//! implementation and the harness's shadow model and feeds them the identical
//! realized stream, so the differential oracle (model predicts, implementation
//! must match) holds even under faults: a dropped op reaches neither side, a
//! reordered or duplicated op is seen identically by both, and a corrupted op
//! carries the same mangled fields to both. Note that a capability *reference*
//! (`CapRef`) cannot be forged at all (its fields are private), so the strongest
//! corruption an attacker controls is the slot *index* in an operation; the core
//! resolves that index per call and rejects anything stale or out of range.
//!
//! # Invariant
//!
//! - The total per-mille weight of the four fault kinds is at most `1000`;
//!   [`FaultConfig::new`] rejects any configuration that exceeds it, and the
//!   presets satisfy it by construction.
//! - The delay queue holds at most [`DELAY_MAX`] entries. A delay that would
//!   overflow it degrades to immediate passthrough rather than dropping the op.
//! - A single [`FaultInjector::process`] call returns at most [`DELIVER_MAX`]
//!   operations (up to [`DELAY_MAX`] released from the delay queue, plus a
//!   duplicated incoming op), so [`SmallOpVec`] never overflows.

use crate::cap_rights::Rights;
use crate::rng::KernelRng;
use crate::trace::{CapOp, ObjectToken};

/// Maximum number of operations the delay queue can hold at once.
pub const DELAY_MAX: usize = 4;

/// Maximum number of operations a single [`FaultInjector::process`] call can
/// return: every delay-queue entry released at once ([`DELAY_MAX`]) plus a
/// duplicated incoming operation (two copies, hence `+ 2 - 1 = + 1`... see
/// below).
///
/// The worst case is all [`DELAY_MAX`] delayed ops becoming ready in the same
/// step alongside a duplicated incoming op (two copies), so the bound is
/// `DELAY_MAX + 2`.
pub const DELIVER_MAX: usize = DELAY_MAX + 2;

// ---------------------------------------------------------------------------
// FaultKind
// ---------------------------------------------------------------------------

/// The category of fault applied to a capability operation.
///
/// Reorder is not a distinct kind: it emerges from [`Delay`](FaultKind::Delay),
/// since a delayed op is released after later ops that were not delayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    /// The operation is discarded before reaching either the implementation or
    /// the shadow model. Neither side processes it, so they stay in step.
    Drop,
    /// The operation is withheld for one or more logical steps, then released.
    /// Both sides receive it at the same realized step.
    Delay,
    /// The operation is delivered twice in succession. Both sides apply it
    /// twice.
    Duplicate,
    /// One field of the operation is perturbed (a slot index set out of range,
    /// or a rights mask changed) before delivery. Both sides receive the same
    /// corrupted operation.
    CorruptOp,
}

// ---------------------------------------------------------------------------
// FaultConfig
// ---------------------------------------------------------------------------

/// Probability weights controlling a fault-injection run.
///
/// Each probability is in per-mille (parts per thousand, `0..=1000`), so `50`
/// means "5% of operations". Integer weights keep the arithmetic exact over
/// [`KernelRng::below`] and free of floating point, which jos avoids in the
/// pure core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultConfig {
    /// Per-mille probability that an operation is dropped entirely.
    pub drop_ppm: u16,
    /// Per-mille probability that an operation is delayed (and so possibly
    /// reordered behind later operations).
    pub delay_ppm: u16,
    /// Per-mille probability that an operation is delivered twice.
    pub duplicate_ppm: u16,
    /// Per-mille probability that an operation's fields are corrupted before
    /// delivery.
    pub corrupt_op_ppm: u16,
    /// Maximum number of logical steps an operation may be delayed, in
    /// `1..=DELAY_MAX`. A value of `0` is treated as `1`.
    pub max_delay_steps: u8,
}

impl FaultConfig {
    /// No faults: every operation is delivered exactly once, in order.
    ///
    /// This is the baseline. A run under `CLEAR_SKY` must reproduce exactly the
    /// behaviour of the fault-free [`dst_capspace`](../../tests/dst_capspace.rs)
    /// harness.
    pub const CLEAR_SKY: Self = Self {
        drop_ppm: 0,
        delay_ppm: 0,
        duplicate_ppm: 0,
        corrupt_op_ppm: 0,
        max_delay_steps: 1,
    };

    /// Moderate faults: drops, delays, reorders, and duplicates, but no field
    /// corruption. `TigerBeetle`'s "Stormy" regime.
    pub const STORMY: Self = Self {
        drop_ppm: 80,
        delay_ppm: 120,
        duplicate_ppm: 60,
        corrupt_op_ppm: 0,
        max_delay_steps: 4,
    };

    /// Aggressive faults, including field corruption. `TigerBeetle`'s
    /// "Apocalyptic" regime. The differential oracle still holds (both sides see
    /// the same corrupted operations); this regime exists to hammer the core's
    /// handling of malformed and adversarial input.
    pub const APOCALYPTIC: Self = Self {
        drop_ppm: 150,
        delay_ppm: 150,
        duplicate_ppm: 100,
        corrupt_op_ppm: 100,
        max_delay_steps: 4,
    };

    /// Creates a configuration, returning `None` if the four fault weights sum
    /// to more than `1000` per-mille (which would leave no room for
    /// passthrough and is almost certainly a mistake).
    #[must_use]
    pub const fn new(
        drop_ppm: u16,
        delay_ppm: u16,
        duplicate_ppm: u16,
        corrupt_op_ppm: u16,
        max_delay_steps: u8,
    ) -> Option<Self> {
        let config = Self {
            drop_ppm,
            delay_ppm,
            duplicate_ppm,
            corrupt_op_ppm,
            max_delay_steps,
        };
        if config.fault_weight_sum() <= 1000 {
            Some(config)
        } else {
            None
        }
    }

    /// Returns the combined per-mille weight of the four fault kinds.
    ///
    /// Accumulated in `u32` so four `u16` weights cannot overflow even before
    /// the `<= 1000` check rejects an out-of-range configuration.
    #[must_use]
    pub const fn fault_weight_sum(&self) -> u32 {
        self.drop_ppm as u32
            + self.delay_ppm as u32
            + self.duplicate_ppm as u32
            + self.corrupt_op_ppm as u32
    }
}

// ---------------------------------------------------------------------------
// SmallOpVec
// ---------------------------------------------------------------------------

/// A fixed-capacity, heap-free vector of up to [`DELIVER_MAX`] operations.
///
/// [`FaultInjector::process`] returns one of these: the operations to deliver
/// to both the implementation and the shadow model this step. It is `Copy`
/// (a small array of `Copy` data), so it is returned by value.
#[derive(Debug, Clone, Copy)]
pub struct SmallOpVec {
    ops: [Option<CapOp>; DELIVER_MAX],
    len: usize,
}

impl SmallOpVec {
    /// Creates an empty vector.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ops: [None; DELIVER_MAX],
            len: 0,
        }
    }

    /// Appends `op`.
    ///
    /// # Panics
    ///
    /// Panics if the vector already holds [`DELIVER_MAX`] operations. By
    /// construction [`FaultInjector::process`] never pushes more than that, so
    /// this is an internal-consistency assertion, not a reachable error.
    pub fn push(&mut self, op: CapOp) {
        assert!(self.len < DELIVER_MAX, "SmallOpVec overflow");
        self.ops[self.len] = Some(op);
        self.len += 1;
    }

    /// Returns the number of operations held.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if no operations are held.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterates the held operations in order.
    pub fn iter(&self) -> impl Iterator<Item = CapOp> + '_ {
        // entries 0..len are always Some by construction, so filter_map yields
        // exactly those, never silently swallowing one.
        self.ops[..self.len].iter().filter_map(|slot| *slot)
    }
}

impl Default for SmallOpVec {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FaultInjector
// ---------------------------------------------------------------------------

// one operation pending delayed delivery: the op plus the number of steps left
// before it is released. only indices 0..delay_len of the queue are Some.
#[derive(Debug, Clone, Copy)]
struct DelayEntry {
    op: CapOp,
    remaining: u8,
}

/// Applies a [`FaultConfig`] to a stream of operations, deterministically, from
/// a seeded [`KernelRng`].
///
/// Holds a small bounded delay queue (no heap), so reordering and delayed
/// delivery persist across [`process`](Self::process) calls while the whole
/// schedule stays a pure function of the seed.
pub struct FaultInjector {
    config: FaultConfig,
    delay_queue: [Option<DelayEntry>; DELAY_MAX],
    delay_len: usize,
}

impl FaultInjector {
    /// Creates an injector for `config`.
    #[must_use]
    pub const fn new(config: FaultConfig) -> Self {
        Self {
            config,
            delay_queue: [None; DELAY_MAX],
            delay_len: 0,
        }
    }

    /// Returns the configuration this injector applies.
    #[inline]
    #[must_use]
    pub const fn config(&self) -> FaultConfig {
        self.config
    }

    /// Processes one incoming operation and returns the operations to deliver
    /// to both the implementation and the shadow model this step.
    ///
    /// The result may hold zero operations (the incoming op was dropped and no
    /// delayed op came due), one (passthrough, or a single delayed release), or
    /// several (a delayed op released alongside the incoming one, or a
    /// duplicate). All randomness is drawn from `rng` in a fixed order, so the
    /// realized stream is a pure function of the seed.
    #[must_use]
    pub fn process(&mut self, op: CapOp, rng: &mut impl KernelRng) -> SmallOpVec {
        let mut out = SmallOpVec::new();
        // release any delayed ops that come due this step, before the incoming
        // one, so the realized order is stable.
        self.flush_ready(&mut out);

        let roll = rng.below(1000);
        let cfg = &self.config;
        // cumulative per-mille thresholds; the trailing range is passthrough.
        let drop_to = u64::from(cfg.drop_ppm);
        let delay_to = drop_to + u64::from(cfg.delay_ppm);
        let dup_to = delay_to + u64::from(cfg.duplicate_ppm);
        let corrupt_to = dup_to + u64::from(cfg.corrupt_op_ppm);

        if roll < drop_to {
            // drop: deliver only what the delay queue released.
        } else if roll < delay_to {
            // delay: buffer for 1..=max_delay_steps, or pass through if the
            // queue is full (documented degradation, never a silent drop).
            if !self.try_delay(op, rng) {
                out.push(op);
            }
        } else if roll < dup_to {
            out.push(op);
            out.push(op);
        } else if roll < corrupt_to {
            out.push(Self::corrupt_op(op, rng));
        } else {
            out.push(op);
        }
        out
    }

    // decrements every queued entry and releases (pushes to `out`) those that
    // reach zero, removing them from the queue. preserves the "0..delay_len are
    // Some" shape via a swap-remove with the last live entry.
    fn flush_ready(&mut self, out: &mut SmallOpVec) {
        let mut i = 0;
        while i < self.delay_len {
            let entry = self.delay_queue[i].as_mut().expect("0..delay_len are Some");
            // remaining is >= 1 for any queued entry, so this never underflows.
            entry.remaining -= 1;
            if entry.remaining == 0 {
                let op = entry.op;
                out.push(op);
                self.delay_len -= 1;
                if i == self.delay_len {
                    self.delay_queue[i] = None;
                } else {
                    self.delay_queue[i] = self.delay_queue[self.delay_len].take();
                }
                // do not advance i: a swapped-in entry now occupies it (or the
                // loop ends because i == delay_len).
            } else {
                i += 1;
            }
        }
    }

    // tries to buffer `op` for a randomized delay. returns false (caller passes
    // the op through) when the queue is full.
    fn try_delay(&mut self, op: CapOp, rng: &mut impl KernelRng) -> bool {
        if self.delay_len >= DELAY_MAX {
            return false;
        }
        let max = u64::from(self.config.max_delay_steps.max(1));
        // remaining in 1..=max, so the op is released between the next step and
        // `max` steps out.
        #[allow(clippy::cast_possible_truncation)]
        let remaining = (1 + rng.below(max)) as u8;
        self.delay_queue[self.delay_len] = Some(DelayEntry { op, remaining });
        self.delay_len += 1;
        true
    }

    /// Corrupts one field of `op`, deterministically from `rng`.
    ///
    /// Slot and source indices are set to an arbitrary 32-bit value (so many
    /// land out of range, exercising the core's bounds and staleness checks);
    /// rights and masks are set to an arbitrary valid [`Rights`] value; object
    /// tokens are set to an arbitrary identity. Both the implementation and the
    /// shadow model receive the identical corrupted op, so the differential
    /// oracle still applies: the model predicts from the same mangled fields the
    /// implementation acts on.
    #[must_use]
    pub fn corrupt_op(op: CapOp, rng: &mut impl KernelRng) -> CapOp {
        match op {
            CapOp::Insert { object, rights } => {
                if rng.next_bool() {
                    CapOp::Insert {
                        object,
                        rights: random_rights(rng),
                    }
                } else {
                    CapOp::Insert {
                        object: ObjectToken(rng.next_u64()),
                        rights,
                    }
                }
            }
            CapOp::Mint { source, mask } => {
                if rng.next_bool() {
                    CapOp::Mint {
                        source: random_slot_word(rng),
                        mask,
                    }
                } else {
                    CapOp::Mint {
                        source,
                        mask: random_rights(rng),
                    }
                }
            }
            CapOp::Remove { .. } => CapOp::Remove {
                slot: random_slot_word(rng),
            },
            CapOp::Revoke { .. } => CapOp::Revoke {
                slot: random_slot_word(rng),
            },
            CapOp::Check { slot, required } => {
                if rng.next_bool() {
                    CapOp::Check {
                        slot: random_slot_word(rng),
                        required,
                    }
                } else {
                    CapOp::Check {
                        slot,
                        required: random_rights(rng),
                    }
                }
            }
        }
    }
}

// an arbitrary 32-bit slot index, drawn so that out-of-range values are common
// (the interesting corruption: the core must reject them via ref_at).
#[allow(clippy::cast_possible_truncation)]
fn random_slot_word(rng: &mut impl KernelRng) -> u32 {
    rng.next_u64() as u32
}

// an arbitrary valid Rights value (one of the 16 subsets of the four bits).
#[allow(clippy::cast_possible_truncation)]
fn random_rights(rng: &mut impl KernelRng) -> Rights {
    Rights::from_bits_truncate(rng.below(16) as u8)
}

// ---------------------------------------------------------------------------
// unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{FaultConfig, FaultInjector, SmallOpVec, DELAY_MAX, DELIVER_MAX};
    use crate::rng::SimRng;
    use crate::trace::{CapOp, ObjectToken};
    extern crate std;
    use crate::cap_rights::Rights;
    use std::vec::Vec;

    fn an_insert() -> CapOp {
        CapOp::Insert {
            object: ObjectToken(1),
            rights: Rights::all(),
        }
    }

    #[test]
    fn new_rejects_oversaturated_config() {
        assert!(FaultConfig::new(400, 400, 200, 1, 4).is_none());
        assert!(FaultConfig::new(250, 250, 250, 250, 4).is_some()); // sums to 1000
        assert!(FaultConfig::new(0, 0, 0, 0, 1).is_some());
    }

    #[test]
    fn presets_are_valid() {
        assert!(FaultConfig::CLEAR_SKY.fault_weight_sum() <= 1000);
        assert!(FaultConfig::STORMY.fault_weight_sum() <= 1000);
        assert!(FaultConfig::APOCALYPTIC.fault_weight_sum() <= 1000);
    }

    #[test]
    fn clear_sky_is_pure_passthrough() {
        let mut inj = FaultInjector::new(FaultConfig::CLEAR_SKY);
        let mut rng = SimRng::new(123);
        for _ in 0..1000 {
            let out = inj.process(an_insert(), &mut rng);
            assert_eq!(out.len(), 1, "CLEAR_SKY must deliver each op exactly once");
            assert_eq!(out.iter().next(), Some(an_insert()));
        }
    }

    #[test]
    fn process_never_exceeds_deliver_max() {
        // hammer the injector under the most aggressive preset and confirm a
        // single step never returns more than DELIVER_MAX ops (the SmallOpVec
        // bound, and the no-lost-op property of the delay queue).
        let mut inj = FaultInjector::new(FaultConfig::APOCALYPTIC);
        let mut rng = SimRng::new(7);
        for _ in 0..20_000 {
            let out = inj.process(an_insert(), &mut rng);
            assert!(out.len() <= DELIVER_MAX);
        }
    }

    #[test]
    fn dropped_and_delayed_reduce_immediate_delivery() {
        // under Stormy, over many steps, strictly fewer ops come out than go in
        // on the immediate path (some are dropped, some buffered), proving the
        // faults actually fire.
        let mut inj = FaultInjector::new(FaultConfig::STORMY);
        let mut rng = SimRng::new(2024);
        let steps = 5000;
        let mut delivered = 0usize;
        for _ in 0..steps {
            delivered += inj.process(an_insert(), &mut rng).len();
        }
        // drops remove ops, so total delivered is below the input count even
        // accounting for the duplicates that add some back.
        assert!(delivered < steps, "expected drops to reduce delivery: {delivered} of {steps}");
        assert!(delivered > steps / 2, "delivery collapsed unexpectedly: {delivered}");
    }

    #[test]
    fn corrupt_op_keeps_the_variant_but_changes_a_field() {
        // corruption preserves the operation KIND (a corrupted Insert is still
        // an Insert) but, over many samples, changes a field at least sometimes.
        let mut rng = SimRng::new(99);
        let original = an_insert();
        let mut any_changed = false;
        for _ in 0..200 {
            let c = FaultInjector::corrupt_op(original, &mut rng);
            assert!(matches!(c, CapOp::Insert { .. }), "kind must be preserved");
            if c != original {
                any_changed = true;
            }
        }
        assert!(any_changed, "corruption never changed the op");
    }

    #[test]
    fn delayed_ops_are_eventually_released_not_lost() {
        // feed one op that gets delayed, then idle the injector (feeding drops
        // only would still flush the queue). count total deliveries: the delayed
        // op must come out. use a delay-only config so nothing is dropped.
        let cfg = FaultConfig::new(0, 1000, 0, 0, u8::try_from(DELAY_MAX).unwrap()).unwrap();
        let mut inj = FaultInjector::new(cfg);
        let mut rng = SimRng::new(55);
        let mut total = 0usize;
        // every op is delayed; over enough steps, everything buffered is
        // eventually released, so deliveries track inputs minus what is still
        // in flight (at most DELAY_MAX).
        let steps = 100;
        for _ in 0..steps {
            total += inj.process(an_insert(), &mut rng).len();
        }
        // drain: keep flushing with a no-op-but-droppable feed is not possible
        // (every feed is delayed too), so just assert most were delivered and
        // the queue never lost more than its capacity.
        assert!(total >= steps - DELAY_MAX, "delayed ops were lost: {total} of {steps}");
        assert!(total <= steps, "more ops delivered than submitted: {total}");
    }

    #[test]
    fn small_op_vec_push_and_iter() {
        let mut v = SmallOpVec::new();
        assert!(v.is_empty());
        v.push(an_insert());
        v.push(CapOp::Remove { slot: 3 });
        assert_eq!(v.len(), 2);
        let collected: Vec<CapOp> = v.iter().collect();
        assert_eq!(collected, std::vec![an_insert(), CapOp::Remove { slot: 3 }]);
    }

    #[test]
    fn injector_is_deterministic() {
        // the realized stream is a pure function of the seed: two injectors fed
        // the same ops with same-seeded rngs produce identical output.
        let run = |seed: u64| -> Vec<usize> {
            let mut inj = FaultInjector::new(FaultConfig::APOCALYPTIC);
            let mut rng = SimRng::new(seed);
            (0..500).map(|_| inj.process(an_insert(), &mut rng).len()).collect()
        };
        assert_eq!(run(42), run(42));
    }
}

// ---------------------------------------------------------------------------
// bounded proofs
// ---------------------------------------------------------------------------
//
// these cover the pure, multiply-free properties: the config sum bound and the
// SmallOpVec capacity bound. they deliberately avoid driving `process` with a
// symbolic rng, because below() contains a 64-bit multiply that bit-blasts into
// a CBMC hang (see rng.rs and memory/dst-and-tracing.md); below()'s own range
// is already proved there.
#[cfg(kani)]
mod kani_proofs {
    use super::{FaultConfig, SmallOpVec, DELIVER_MAX};
    use crate::trace::CapOp;

    // new() accepts a config iff the four fault weights sum to <= 1000, and the
    // sum is computed without overflow (u32 accumulation of four u16s).
    #[kani::proof]
    fn new_accepts_exactly_when_sum_in_bound() {
        let d: u16 = kani::any();
        let l: u16 = kani::any();
        let p: u16 = kani::any();
        let c: u16 = kani::any();
        let sum = u32::from(d) + u32::from(l) + u32::from(p) + u32::from(c);
        match FaultConfig::new(d, l, p, c, 1) {
            Some(cfg) => {
                assert!(sum <= 1000);
                assert!(cfg.fault_weight_sum() == sum);
            }
            None => assert!(sum > 1000),
        }
    }

    // pushing up to DELIVER_MAX ops keeps len within capacity, so process (which
    // never pushes more than DELIVER_MAX) can never overflow the vector.
    #[kani::proof]
    #[kani::unwind(8)] // DELIVER_MAX + 2
    fn small_op_vec_respects_capacity() {
        let mut v = SmallOpVec::new();
        let n: usize = kani::any();
        kani::assume(n <= DELIVER_MAX);
        for _ in 0..n {
            v.push(CapOp::Remove { slot: 0 });
        }
        assert!(v.len() == n);
        assert!(v.len() <= DELIVER_MAX);
    }
}
