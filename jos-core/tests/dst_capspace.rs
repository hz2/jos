//! Deterministic Simulation Testing for the capability space (Phase 3 spine).
//!
//! This is the first concrete realization of the VISION's simulation pillar
//! (north star 5): drive the verified [`CapSpace`] with a seeded random stream
//! of capability operations and check it, after every step, against an
//! *independently implemented* shadow model. This is spec-as-oracle / model-
//! based testing: a bug in the optimized array-with-generations implementation
//! is unlikely to be mirrored by an identical bug in the slot-keyed model that
//! resolves parent links by linear search, so a divergence between them is a
//! real defect. The whole run is a pure function of its seed, so any failure
//! reproduces exactly: re-run with `DST_SEED=<n>`.
//!
//! What it exercises, per step:
//! - **State agreement**: impl and model agree on which slots are live and on
//!   every live capability's object, rights, and parent (full structural eq).
//! - **Allocation discipline**: an insert/mint lands in the slot the model
//!   independently predicts (lowest free).
//! - **No rights escalation**: a minted child's rights are a subset of its
//!   source's (asserted by reconstructing the derivation in the model).
//! - **Differential revoke**: the subtree [`CapSpace::revoke`] removes is
//!   exactly the set an independent graph walk over parent links predicts.
//! - **Global staleness**: every `CapRef` ever removed stays dead forever, even
//!   after its physical slot is reused (the core revocation guarantee, tested
//!   across long histories rather than a single op).
//!
//! It also demonstrates **record/replay** (north star 5: the op log is a
//! complete record): replaying a recorded [`TraceEvent`] op stream onto a fresh
//! space reproduces every recorded outcome and the identical final state.
//!
//! Counts shrink under Miri (which interprets every operation) so the UB-check
//! run stays tractable; the native run is a wide seed sweep.

use jos_core::cap_rights::Rights;
use jos_core::cap_space::{CapSpace, MintError};
use jos_core::cap_table::CapRef;
use jos_core::rng::{KernelRng, SimRng};
use jos_core::trace::{CapOp, CapOutcome, ObjectToken, Refusal, TraceEvent};

// capacity of the simulated capability space. small enough that the space fills
// and churns (so the full / stale-slot-reuse paths are hit often), large enough
// for multi-level derivation trees to form.
const N: usize = 16;

// run sizes. Miri interprets every instruction, so it gets a tiny sweep; the
// native run is wide. STEPS is deliberately larger than N so the space fills,
// empties, and reuses slots many times within one run.
#[cfg(miri)]
const SEEDS: u64 = 2;
#[cfg(not(miri))]
const SEEDS: u64 = 256;

#[cfg(miri)]
const STEPS: usize = 30;
#[cfg(not(miri))]
const STEPS: usize = 400;

// ---------------------------------------------------------------------------
// small conversions (slots are bounded by N, so these never truncate)
// ---------------------------------------------------------------------------

fn as_u32(x: usize) -> u32 {
    u32::try_from(x).expect("slot/count fits in u32 (bounded by N)")
}

// ---------------------------------------------------------------------------
// the shadow model
// ---------------------------------------------------------------------------

// one live capability as the model tracks it. deliberately a different shape
// from the implementation's `Slot` (no generation counter; the parent is the
// full `CapRef` we passed at mint, resolved later by search), so the model is an
// independent oracle rather than a copy of the code under test.
#[derive(Clone, Copy, Debug)]
struct ModelCap {
    // the CapRef the implementation handed back when this cap was created. while
    // the cap is live this equals `space.ref_at(slot)`, which the invariants check.
    own_ref: CapRef,
    object: ObjectToken,
    rights: Rights,
    // the source CapRef this cap was minted from (None for an original). a
    // generation-bearing ref, so a removed-and-reused parent slot does not
    // silently re-parent this cap.
    parent: Option<CapRef>,
}

// the simulation: the implementation under test, the independent model, and the
// bookkeeping that makes failures reproducible.
struct Sim {
    seed: u64,
    rng: SimRng,
    space: CapSpace<ObjectToken, N>,
    model: [Option<ModelCap>; N],
    // monotone source of fresh object identities, so every Insert names a
    // distinct object and the model can tell objects apart.
    next_object: u64,
    // every CapRef ever removed (by remove or revoke). none may ever resolve
    // again: the global staleness invariant checks this each step.
    retired: Vec<CapRef>,
    seq: u64,
    log: Vec<TraceEvent>,
}

impl Sim {
    fn new(seed: u64) -> Self {
        Self {
            seed,
            rng: SimRng::new(seed),
            space: CapSpace::new(),
            model: [None; N],
            next_object: 1,
            retired: Vec::new(),
            seq: 0,
            log: Vec::new(),
        }
    }

    // -- model queries (independent of the implementation) ------------------

    // the lowest free slot, as the model sees occupancy. the implementation's
    // insert/mint pick the lowest free slot too, so this predicts the
    // destination, and the invariants prove the two free-sets stay identical.
    fn model_lowest_free(&self) -> Option<usize> {
        (0..N).find(|&s| self.model[s].is_none())
    }

    // the live slot whose capability's own_ref equals `r`, if any. the model's
    // way of resolving a CapRef to a slot: a linear search by stored ref, where
    // the implementation indexes by slot and checks the generation. a stale ref
    // (its slot reused, generation advanced) matches nothing, exactly as it
    // resolves to nothing in the implementation.
    fn live_slot_with_ref(&self, r: CapRef) -> Option<usize> {
        (0..N).find(|&s| self.model[s].is_some_and(|c| c.own_ref == r))
    }

    // does the live cap in `leaf` descend from (or equal) the cap named by
    // `root_ref`? an independent reimplementation of CapSpace::descends_from:
    // walk parent CapRefs, resolving each to a slot by search, bounded by N so a
    // corrupt cycle cannot hang.
    fn model_descends_from(&self, leaf: usize, root_ref: CapRef) -> bool {
        let mut cur = leaf;
        for _ in 0..=N {
            let Some(cap) = self.model[cur] else {
                return false;
            };
            if cap.own_ref == root_ref {
                return true;
            }
            match cap.parent {
                None => return false,
                Some(pref) => match self.live_slot_with_ref(pref) {
                    Some(ps) => cur = ps,
                    None => return false, // parent gone: leaf is orphaned, not a descendant
                },
            }
        }
        false
    }

    // the set of slots a revoke rooted at `root_slot` should remove: every live
    // cap that descends from the root (including the root). empty if the root
    // slot is itself empty.
    fn model_revoke_set(&self, root_slot: usize) -> Vec<usize> {
        let Some(root) = self.model[root_slot] else {
            return Vec::new();
        };
        (0..N)
            .filter(|&s| self.model[s].is_some() && self.model_descends_from(s, root.own_ref))
            .collect()
    }

    // -- workload generation -------------------------------------------------

    fn fresh_object(&mut self) -> ObjectToken {
        let t = ObjectToken(self.next_object);
        self.next_object += 1;
        t
    }

    fn random_rights(&mut self) -> Rights {
        // a uniform choice among all 16 subsets of the four defined bits;
        // from_bits_truncate masks to the valid bits.
        let bits = u8::try_from(self.rng.below(16)).expect("below(16) < 16");
        Rights::from_bits_truncate(bits)
    }

    fn random_slot(&mut self) -> u32 {
        // a slot in [0, N): naturally hits both live and empty slots, so the
        // remove/revoke/check-on-empty paths are exercised alongside the live ones.
        as_u32(usize::try_from(self.rng.below(N as u64)).expect("below(N) < N"))
    }

    // draws the next operation. the weighting builds derivation trees (insert +
    // mint dominate) while still tearing them down (remove + revoke) and reading
    // them back (check), so the space is constantly filling, churning, and
    // reusing slots.
    fn gen_op(&mut self) -> CapOp {
        let roll = self.rng.below(100);
        if roll < 35 {
            CapOp::Insert {
                object: self.fresh_object(),
                rights: self.random_rights(),
            }
        } else if roll < 70 {
            CapOp::Mint {
                source: self.random_slot(),
                mask: self.random_rights(),
            }
        } else if roll < 82 {
            CapOp::Remove {
                slot: self.random_slot(),
            }
        } else if roll < 92 {
            CapOp::Revoke {
                slot: self.random_slot(),
            }
        } else {
            CapOp::Check {
                slot: self.random_slot(),
                required: self.random_rights(),
            }
        }
    }

    // -- the step: predict, apply, assert, commit, check invariants ---------

    fn step(&mut self, op: CapOp) {
        let outcome = match op {
            CapOp::Insert { object, rights } => {
                let predicted = self
                    .model_lowest_free()
                    .map_or(CapOutcome::Refused(Refusal::SpaceFull), |s| {
                        CapOutcome::Installed { slot: as_u32(s) }
                    });
                let actual = apply_op(&mut self.space, op);
                self.assert_outcome(op, predicted, actual);
                if let CapOutcome::Installed { slot } = actual {
                    let r = self.space.ref_at(slot as usize).expect("installed slot is live");
                    self.model[slot as usize] = Some(ModelCap {
                        own_ref: r,
                        object,
                        rights,
                        parent: None,
                    });
                }
                actual
            }
            CapOp::Mint { source, mask } => {
                let src = self.model[source as usize];
                let predicted = match src {
                    None => CapOutcome::Refused(Refusal::StaleSlot),
                    Some(_) => self
                        .model_lowest_free()
                        .map_or(CapOutcome::Refused(Refusal::SpaceFull), |s| {
                            CapOutcome::Installed { slot: as_u32(s) }
                        }),
                };
                let actual = apply_op(&mut self.space, op);
                self.assert_outcome(op, predicted, actual);
                if let CapOutcome::Installed { slot } = actual {
                    let parent = src.expect("mint succeeded so source was live");
                    // no rights escalation: the child is the source attenuated by
                    // the mask, hence a subset of the source's rights.
                    let derived = parent.rights.attenuate(mask);
                    assert!(
                        parent.rights.contains(derived),
                        "seed={} seq={}: mint escalated rights: parent={:?} child={:?}",
                        self.seed,
                        self.seq,
                        parent.rights,
                        derived,
                    );
                    let r = self.space.ref_at(slot as usize).expect("minted slot is live");
                    self.model[slot as usize] = Some(ModelCap {
                        own_ref: r,
                        object: parent.object,
                        rights: derived,
                        parent: Some(parent.own_ref),
                    });
                }
                actual
            }
            CapOp::Remove { slot } => {
                let s = slot as usize;
                let victim = self.model[s];
                let predicted = CapOutcome::Removed {
                    count: u32::from(victim.is_some()),
                };
                let actual = apply_op(&mut self.space, op);
                self.assert_outcome(op, predicted, actual);
                if let Some(cap) = victim {
                    self.retired.push(cap.own_ref);
                    self.model[s] = None;
                }
                actual
            }
            CapOp::Revoke { slot } => {
                let s = slot as usize;
                // predict the removed set BEFORE the implementation mutates,
                // while every parent link is still intact (the same ordering
                // CapSpace::revoke relies on internally).
                let set = self.model_revoke_set(s);
                let predicted = CapOutcome::Removed {
                    count: as_u32(set.len()),
                };
                let actual = apply_op(&mut self.space, op);
                self.assert_outcome(op, predicted, actual);
                for &rs in &set {
                    let r = self.model[rs].expect("revoke-set slot is live").own_ref;
                    self.retired.push(r);
                    self.model[rs] = None;
                }
                actual
            }
            CapOp::Check { slot, required } => {
                let s = slot as usize;
                let predicted_allowed =
                    self.model[s].is_some_and(|c| c.rights.contains(required));
                let actual = apply_op(&mut self.space, op);
                self.assert_outcome(
                    op,
                    CapOutcome::Checked {
                        allowed: predicted_allowed,
                    },
                    actual,
                );
                actual
            }
        };

        self.seq += 1;
        self.log.push(TraceEvent::new(self.seq, op, outcome));
        self.check_invariants();
    }

    fn assert_outcome(&self, op: CapOp, expected: CapOutcome, actual: CapOutcome) {
        assert_eq!(
            actual, expected,
            "seed={} seq={}: outcome mismatch for {op:?}: impl={actual:?} model={expected:?}",
            self.seed, self.seq,
        );
    }

    // the spec-as-oracle assertions, run after every step.
    fn check_invariants(&self) {
        // 1. occupied-count agreement and the N bound.
        let model_len = self.model.iter().filter(|c| c.is_some()).count();
        assert_eq!(
            self.space.len(),
            model_len,
            "seed={} seq={}: len disagrees: impl={} model={model_len}",
            self.seed,
            self.seq,
            self.space.len(),
        );
        assert!(
            self.space.len() <= N,
            "seed={} seq={}: len {} exceeds capacity {N}",
            self.seed,
            self.seq,
            self.space.len(),
        );

        // 2. full structural agreement, slot by slot: same liveness, and for a
        //    live slot the same object, rights, and parent. this single check
        //    subsumes "did the right thing happen to the table" for every op.
        for s in 0..N {
            match (self.space.ref_at(s), self.model[s]) {
                (None, None) => {}
                (Some(r), Some(mc)) => {
                    assert_eq!(
                        r, mc.own_ref,
                        "seed={} seq={}: slot {s} ref disagrees: impl={r:?} model={:?}",
                        self.seed, self.seq, mc.own_ref,
                    );
                    let cap = self
                        .space
                        .lookup(r)
                        .expect("ref_at returned a live ref, so lookup must succeed");
                    assert_eq!(
                        cap.object, mc.object,
                        "seed={} seq={}: slot {s} object disagrees",
                        self.seed, self.seq,
                    );
                    assert_eq!(
                        cap.rights, mc.rights,
                        "seed={} seq={}: slot {s} rights disagree",
                        self.seed, self.seq,
                    );
                    assert_eq!(
                        cap.parent, mc.parent,
                        "seed={} seq={}: slot {s} parent disagrees",
                        self.seed, self.seq,
                    );
                }
                (impl_live, model_live) => panic!(
                    "seed={} seq={}: slot {s} liveness disagrees: impl_live={} model_live={}",
                    self.seed,
                    self.seq,
                    impl_live.is_some(),
                    model_live.is_some(),
                ),
            }
        }

        // 3. global staleness: every retired CapRef stays dead forever, even
        //    after its physical slot is reused by a new capability. this is the
        //    revocation guarantee, checked across the whole history.
        for &r in &self.retired {
            assert!(
                self.space.lookup(r).is_none(),
                "seed={} seq={}: retired ref {r:?} resurrected",
                self.seed,
                self.seq,
            );
        }
    }

    fn run(&mut self, steps: usize) {
        for _ in 0..steps {
            let op = self.gen_op();
            self.step(op);
        }
    }
}

// the implementation side of one operation, shared by recording and replay so
// there is a single source of truth for "what the kernel does with this op".
// resolves a slot index to a live CapRef the way the syscall boundary does
// (ref_at per call), then invokes the verified CapSpace and maps the result to a
// CapOutcome.
fn apply_op(space: &mut CapSpace<ObjectToken, N>, op: CapOp) -> CapOutcome {
    match op {
        CapOp::Insert { object, rights } => match space.insert(object, rights) {
            Ok(r) => CapOutcome::Installed { slot: as_u32(r.slot()) },
            Err(_) => CapOutcome::Refused(Refusal::SpaceFull),
        },
        CapOp::Mint { source, mask } => match space.ref_at(source as usize) {
            None => CapOutcome::Refused(Refusal::StaleSlot),
            Some(src) => match space.mint(src, mask) {
                Ok(r) => CapOutcome::Installed { slot: as_u32(r.slot()) },
                Err(MintError::SpaceFull) => CapOutcome::Refused(Refusal::SpaceFull),
                Err(MintError::InvalidSource) => CapOutcome::Refused(Refusal::StaleSlot),
            },
        },
        CapOp::Remove { slot } => match space.ref_at(slot as usize) {
            None => CapOutcome::Removed { count: 0 },
            Some(r) => {
                space.remove(r);
                CapOutcome::Removed { count: 1 }
            }
        },
        CapOp::Revoke { slot } => match space.ref_at(slot as usize) {
            None => CapOutcome::Removed { count: 0 },
            Some(r) => CapOutcome::Removed {
                count: as_u32(space.revoke(r)),
            },
        },
        CapOp::Check { slot, required } => {
            let allowed = match space.ref_at(slot as usize) {
                None => false,
                Some(r) => space.check(r, required),
            };
            CapOutcome::Checked { allowed }
        }
    }
}

// a cross-space-comparable view of a capability space: per slot, the live
// capability's object, rights, and parent SLOT (not CapRef: generations differ
// between an original run and a replay, but slot indices are reproduced exactly
// by the same op sequence, so the slot is the stable identity to compare).
fn snapshot(
    space: &CapSpace<ObjectToken, N>,
) -> Vec<Option<(ObjectToken, Rights, Option<usize>)>> {
    (0..N)
        .map(|s| {
            space.ref_at(s).map(|r| {
                let cap = space.lookup(r).expect("ref_at slot is live");
                (cap.object, cap.rights, cap.parent.map(|p| p.slot()))
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// the main event: a seed sweep, each seed driving the verified CapSpace against
// the independent model for STEPS operations. DST_SEED=<n> runs just that seed
// (for reproducing a reported failure). A failure panics with the seed and the
// sequence number, which together pin the exact operation.
#[test]
fn spec_as_oracle_seed_sweep() {
    if let Ok(s) = std::env::var("DST_SEED") {
        let seed: u64 = s.parse().expect("DST_SEED must parse as u64");
        let mut sim = Sim::new(seed);
        sim.run(STEPS);
        return;
    }
    for seed in 0..SEEDS {
        let mut sim = Sim::new(seed);
        sim.run(STEPS);
    }
}

// the harness is itself deterministic: the same seed yields the identical trace.
// this is what makes a reported seed a faithful reproduction (and guards against
// accidental nondeterminism creeping into the harness, e.g. iteration order).
#[test]
fn harness_is_deterministic() {
    let seeds = if cfg!(miri) { 2 } else { 32 };
    for seed in 0..seeds {
        let mut a = Sim::new(seed);
        let mut b = Sim::new(seed);
        a.run(STEPS);
        b.run(STEPS);
        assert_eq!(a.log, b.log, "harness nondeterministic at seed {seed}");
    }
}

// record/replay (north star 5): the recorded op stream, replayed onto a fresh
// space, reproduces every recorded outcome and the identical final state. this
// is "reset to the initial state and replay the log" made concrete on the
// capability table, the simplest piece of the deterministic core.
#[test]
fn record_replay_reconstructs_state() {
    let seeds = if cfg!(miri) { 2 } else { 64 };
    for seed in 0..seeds {
        let mut sim = Sim::new(seed);
        sim.run(STEPS);

        // replay the op log onto a fresh space; each outcome must match the
        // record, op for op.
        let mut replay: CapSpace<ObjectToken, N> = CapSpace::new();
        for ev in &sim.log {
            let outcome = apply_op(&mut replay, ev.op);
            assert_eq!(
                outcome, ev.outcome,
                "seed={seed}: replay diverged at seq {}: op={:?} record={:?} replay={outcome:?}",
                ev.seq, ev.op, ev.outcome,
            );
        }

        // and the reconstructed state is identical to the original's final state.
        assert_eq!(
            snapshot(&replay),
            snapshot(&sim.space),
            "seed={seed}: replayed final state differs from recorded final state",
        );
    }
}
