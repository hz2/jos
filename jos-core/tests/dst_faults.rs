//! Deterministic Simulation Testing under TigerBeetle-style fault regimes.
//!
//! This extends the spec-as-oracle harness (`dst_capspace.rs`) with a hostile,
//! lossy environment. Capability operations are drawn from a seeded `SimRng`
//! and then passed through a `FaultInjector` that may drop, delay, reorder,
//! duplicate, or corrupt them before they reach the verified `CapSpace`. The
//! three regimes follow TigerBeetle's progression:
//!
//! - `ClearSky`: no faults. Must reproduce the fault-free harness exactly.
//! - `Stormy`: drops, delays, reorders, duplicates. The differential oracle
//!   holds on the realized stream; the safety invariants hold throughout.
//! - `Apocalyptic`: all of the above plus field corruption (mangled slot
//!   indices and rights masks). Still differential, because both the
//!   implementation and the independent shadow model see the identical realized
//!   stream; the regime stresses the core's handling of malformed input.
//!
//! Because the operations arrive from an untrusted caller across what would be
//! the syscall boundary, this doubles as a security stress test. The headline
//! invariant is the seL4 unforgeability property: a capability reference cannot
//! be fabricated (its fields are private), and a stale or out-of-range slot
//! index must always be rejected, never honored, no matter how it was corrupted.
//!
//! The whole run is a pure function of `(seed, regime)`. Reproduce any failure
//! with `DST_REGIME=stormy DST_SEED=<n> cargo test -p jos-core --test dst_faults`.

use std::env;

use jos_core::cap_rights::Rights;
use jos_core::cap_space::{CapSpace, MintError};
use jos_core::cap_table::CapRef;
use jos_core::fault::{FaultConfig, FaultInjector};
use jos_core::rng::{KernelRng, SimRng};
use jos_core::trace::{CapOp, CapOutcome, ObjectToken, Refusal, TraceEvent};

// capacity of the simulated capability space (matches dst_capspace.rs).
const N: usize = 16;

// run sizes. Miri interprets every op, so it gets a tiny sweep; the native run
// is wide. faults drop and buffer ops, so a step does not always reach the core,
// hence a few more steps than the fault-free harness to do comparable work.
#[cfg(miri)]
const SEEDS: u64 = 2;
#[cfg(not(miri))]
const SEEDS: u64 = 128;

#[cfg(miri)]
const STEPS: usize = 30;
#[cfg(not(miri))]
const STEPS: usize = 500;

fn as_u32(x: usize) -> u32 {
    u32::try_from(x).expect("slot/count fits in u32 (bounded by N)")
}

// ---------------------------------------------------------------------------
// the shadow model (an independent oracle, identical in spirit to
// dst_capspace.rs: a different shape from the implementation, so a shared bug
// is unlikely)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct ModelCap {
    own_ref: CapRef,
    object: ObjectToken,
    rights: Rights,
    parent: Option<CapRef>,
}

// the implementation side of one already-realized operation, shared by the
// harness and (conceptually) replay. resolves a slot index to a live CapRef the
// way the syscall boundary does, then maps the verified CapSpace result to a
// CapOutcome. A corrupted (out-of-range) slot simply fails to resolve.
fn apply_op(space: &mut CapSpace<ObjectToken, N>, op: CapOp) -> CapOutcome {
    match op {
        CapOp::Insert { object, rights } => match space.insert(object, rights) {
            Ok(r) => CapOutcome::Installed { slot: as_u32(r.slot()) },
            Err(_) => CapOutcome::Refused(Refusal::SpaceFull),
        },
        CapOp::Mint { source, mask } => match resolve(space, source) {
            None => CapOutcome::Refused(Refusal::StaleSlot),
            Some(src) => match space.mint(src, mask) {
                Ok(r) => CapOutcome::Installed { slot: as_u32(r.slot()) },
                Err(MintError::SpaceFull) => CapOutcome::Refused(Refusal::SpaceFull),
                Err(MintError::InvalidSource) => CapOutcome::Refused(Refusal::StaleSlot),
            },
        },
        CapOp::Remove { slot } => match resolve(space, slot) {
            None => CapOutcome::Removed { count: 0 },
            Some(r) => {
                space.remove(r);
                CapOutcome::Removed { count: 1 }
            }
        },
        CapOp::Revoke { slot } => match resolve(space, slot) {
            None => CapOutcome::Removed { count: 0 },
            Some(r) => CapOutcome::Removed { count: as_u32(space.revoke(r)) },
        },
        CapOp::Check { slot, required } => {
            let allowed = resolve(space, slot).is_some_and(|r| space.check(r, required));
            CapOutcome::Checked { allowed }
        }
    }
}

// resolves a (possibly corrupted, possibly out-of-range) slot index to a live
// CapRef. A slot >= N never resolves; this is where a corrupted slot index is
// rejected at the boundary.
fn resolve(space: &CapSpace<ObjectToken, N>, slot: u32) -> Option<CapRef> {
    let slot = usize::try_from(slot).ok()?;
    if slot >= N {
        return None;
    }
    space.ref_at(slot)
}

// ---------------------------------------------------------------------------
// the fault simulation
// ---------------------------------------------------------------------------

struct FaultSim {
    seed: u64,
    regime: &'static str,
    rng: SimRng,
    injector: FaultInjector,
    space: CapSpace<ObjectToken, N>,
    model: [Option<ModelCap>; N],
    next_object: u64,
    retired: Vec<CapRef>,
    // per-slot generation floor: the generation never decreases, so this only
    // rises. proves the anti-resurrection property at the data-structure level.
    generation_floor: [u32; N],
    seq: u64,
    // a compact realized-op log: enough to prove the run is deterministic
    // (same seed + regime => identical realized stream and outcomes).
    log: Vec<TraceEvent>,
}

impl FaultSim {
    fn new(seed: u64, config: FaultConfig, regime: &'static str) -> Self {
        Self {
            seed,
            regime,
            rng: SimRng::new(seed),
            injector: FaultInjector::new(config),
            space: CapSpace::new(),
            model: [None; N],
            next_object: 1,
            retired: Vec::new(),
            generation_floor: [0; N],
            seq: 0,
            log: Vec::new(),
        }
    }

    // -- workload generation (well-formed ops; the injector corrupts them) ---

    fn fresh_object(&mut self) -> ObjectToken {
        let t = ObjectToken(self.next_object);
        self.next_object += 1;
        t
    }

    fn random_rights(&mut self) -> Rights {
        let bits = u8::try_from(self.rng.below(16)).expect("below(16) < 16");
        Rights::from_bits_truncate(bits)
    }

    fn random_slot(&mut self) -> u32 {
        as_u32(usize::try_from(self.rng.below(N as u64)).expect("below(N) < N"))
    }

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
            CapOp::Remove { slot: self.random_slot() }
        } else if roll < 92 {
            CapOp::Revoke { slot: self.random_slot() }
        } else {
            CapOp::Check {
                slot: self.random_slot(),
                required: self.random_rights(),
            }
        }
    }

    // -- one logical step: generate, inject faults, realize each delivered op -

    fn step(&mut self) {
        let op = self.gen_op();
        let delivered = self.injector.process(op, &mut self.rng);
        for realized in delivered.iter() {
            self.step_realized(realized);
        }
        // the unforgeability probe runs every step, independent of whether any
        // op was delivered: stale refs must stay dead at all times.
        self.unforgeability_probe();
    }

    // applies one realized op to BOTH the implementation and the independent
    // model, asserting they agree (the differential oracle) and that the safety
    // invariants hold. structurally mirrors dst_capspace.rs::Sim::step, the
    // proven slice-1 logic, but over a realized (post-fault) op.
    fn step_realized(&mut self, op: CapOp) {
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
                // a corrupted source slot may be out of range; the model
                // resolves it the same way the implementation does.
                let src = self.model_resolve(source);
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
                    let derived = parent.rights.attenuate(mask);
                    // no rights escalation, even from a corrupted mask: attenuate
                    // can only clear bits, so the child is a subset of the parent.
                    assert!(
                        parent.rights.contains(derived),
                        "{} seed={} seq={}: mint escalated rights: parent={:?} child={:?}",
                        self.regime, self.seed, self.seq, parent.rights, derived,
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
                let s = self.model_slot_in_range(slot);
                let victim = s.and_then(|s| self.model[s]);
                let predicted = CapOutcome::Removed {
                    count: u32::from(victim.is_some()),
                };
                let actual = apply_op(&mut self.space, op);
                self.assert_outcome(op, predicted, actual);
                if let (Some(s), Some(cap)) = (s, victim) {
                    self.retired.push(cap.own_ref);
                    self.model[s] = None;
                }
                actual
            }
            CapOp::Revoke { slot } => {
                let s = self.model_slot_in_range(slot);
                let set = s.map_or_else(Vec::new, |s| self.model_revoke_set(s));
                let predicted = CapOutcome::Removed { count: as_u32(set.len()) };
                let actual = apply_op(&mut self.space, op);
                self.assert_outcome(op, predicted, actual);
                for rs in set {
                    let r = self.model[rs].expect("revoke-set slot is live").own_ref;
                    self.retired.push(r);
                    self.model[rs] = None;
                }
                actual
            }
            CapOp::Check { slot, required } => {
                let predicted_allowed = self
                    .model_resolve(slot)
                    .is_some_and(|c| c.rights.contains(required));
                let actual = apply_op(&mut self.space, op);
                self.assert_outcome(
                    op,
                    CapOutcome::Checked { allowed: predicted_allowed },
                    actual,
                );
                actual
            }
        };

        self.seq += 1;
        self.log.push(TraceEvent::new(self.seq, op, outcome));
        self.check_invariants();
    }

    // -- model queries -------------------------------------------------------

    fn model_lowest_free(&self) -> Option<usize> {
        (0..N).find(|&s| self.model[s].is_none())
    }

    // an in-range slot index, or None if the (possibly corrupted) index is out
    // of range. the model's mirror of the implementation's bounds check.
    fn model_slot_in_range(&self, slot: u32) -> Option<usize> {
        let s = usize::try_from(slot).ok()?;
        (s < N).then_some(s)
    }

    // resolves a slot index to the live model cap there, mirroring resolve().
    fn model_resolve(&self, slot: u32) -> Option<ModelCap> {
        self.model_slot_in_range(slot).and_then(|s| self.model[s])
    }

    fn live_slot_with_ref(&self, r: CapRef) -> Option<usize> {
        (0..N).find(|&s| self.model[s].is_some_and(|c| c.own_ref == r))
    }

    fn model_descends_from(&self, leaf: usize, root_ref: CapRef) -> bool {
        let mut cur = leaf;
        for _ in 0..=N {
            let Some(cap) = self.model[cur] else { return false };
            if cap.own_ref == root_ref {
                return true;
            }
            match cap.parent {
                None => return false,
                Some(pref) => match self.live_slot_with_ref(pref) {
                    Some(ps) => cur = ps,
                    None => return false,
                },
            }
        }
        false
    }

    fn model_revoke_set(&self, root_slot: usize) -> Vec<usize> {
        let Some(root) = self.model[root_slot] else { return Vec::new() };
        (0..N)
            .filter(|&s| self.model[s].is_some() && self.model_descends_from(s, root.own_ref))
            .collect()
    }

    // -- assertions ----------------------------------------------------------

    fn assert_outcome(&self, op: CapOp, expected: CapOutcome, actual: CapOutcome) {
        assert_eq!(
            actual, expected,
            "{} seed={} seq={}: outcome mismatch for {op:?}: impl={actual:?} model={expected:?}",
            self.regime, self.seed, self.seq,
        );
    }

    // the safety invariants, checked after every realized op. these are the
    // intrinsic guarantees that must hold under ANY input, plus the differential
    // structural agreement that holds because both sides see the same stream.
    fn check_invariants(&mut self) {
        // I1: capacity bound, and len agreement with the model.
        let model_len = self.model.iter().filter(|c| c.is_some()).count();
        assert_eq!(
            self.space.len(), model_len,
            "{} seed={} seq={}: len disagrees: impl={} model={model_len}",
            self.regime, self.seed, self.seq, self.space.len(),
        );
        assert!(
            self.space.len() <= N,
            "{} seed={} seq={}: len {} exceeds capacity {N}",
            self.regime, self.seed, self.seq, self.space.len(),
        );

        // D2: full structural agreement slot by slot. plus I3: per-slot
        // generation is monotonic non-decreasing (the floor only rises).
        for s in 0..N {
            if let Some(r) = self.space.ref_at(s) {
                assert!(
                    r.generation() >= self.generation_floor[s],
                    "{} seed={} seq={}: slot {s} generation went backwards: {} < floor {}",
                    self.regime, self.seed, self.seq, r.generation(), self.generation_floor[s],
                );
                self.generation_floor[s] = r.generation();
            }
            match (self.space.ref_at(s), self.model[s]) {
                (None, None) => {}
                (Some(r), Some(mc)) => {
                    assert_eq!(
                        r, mc.own_ref,
                        "{} seed={} seq={}: slot {s} ref disagrees",
                        self.regime, self.seed, self.seq,
                    );
                    let cap = self.space.lookup(r).expect("live ref must look up");
                    assert_eq!(
                        cap.object, mc.object,
                        "{} seed={} seq={}: slot {s} object disagrees",
                        self.regime, self.seed, self.seq,
                    );
                    assert_eq!(
                        cap.rights, mc.rights,
                        "{} seed={} seq={}: slot {s} rights disagree",
                        self.regime, self.seed, self.seq,
                    );
                    assert_eq!(
                        cap.parent, mc.parent,
                        "{} seed={} seq={}: slot {s} parent disagrees",
                        self.regime, self.seed, self.seq,
                    );
                }
                (impl_live, model_live) => panic!(
                    "{} seed={} seq={}: slot {s} liveness disagrees: impl={} model={}",
                    self.regime, self.seed, self.seq,
                    impl_live.is_some(), model_live.is_some(),
                ),
            }
        }

        // I2: global staleness. every retired ref stays dead forever, across
        // slot reuse. the core revocation/unforgeability guarantee.
        for &r in &self.retired {
            assert!(
                self.space.lookup(r).is_none(),
                "{} seed={} seq={}: retired ref {r:?} resurrected",
                self.regime, self.seed, self.seq,
            );
        }
    }

    // I5: the unforgeability property. every retired CapRef, presented to the
    // read paths, is rejected for ALL rights, even after its slot is reused by a
    // live capability. A held-but-stale reference grants nothing. (CapRefs with
    // novel slot/generation pairs cannot be constructed in safe code at all, so
    // the reachable adversary input is exactly a once-valid, now-stale ref plus
    // the corrupted slot indices CorruptOp already feeds through gen_op.)
    fn unforgeability_probe(&self) {
        for &r in &self.retired {
            assert!(
                self.space.lookup(r).is_none(),
                "{} seed={} seq={}: forged/stale ref {r:?} resolved",
                self.regime, self.seed, self.seq,
            );
            assert!(
                !self.space.check(r, Rights::all()),
                "{} seed={} seq={}: forged/stale ref {r:?} passed a rights check",
                self.regime, self.seed, self.seq,
            );
            assert!(
                !self.space.check(r, Rights::NONE),
                "{} seed={} seq={}: forged/stale ref {r:?} passed an empty-rights check",
                self.regime, self.seed, self.seq,
            );
        }
    }

    fn run(&mut self, steps: usize) {
        for _ in 0..steps {
            self.step();
        }
    }
}

// ---------------------------------------------------------------------------
// regime helpers
// ---------------------------------------------------------------------------

fn config_for(regime: &str) -> FaultConfig {
    match regime {
        "clear_sky" | "clearsky" => FaultConfig::CLEAR_SKY,
        "stormy" => FaultConfig::STORMY,
        "apocalyptic" => FaultConfig::APOCALYPTIC,
        other => panic!("unknown DST_REGIME {other:?}; use clear_sky|stormy|apocalyptic"),
    }
}

fn sweep(regime: &'static str, config: FaultConfig) {
    // reproduce a single reported failure when DST_SEED is set.
    if let Ok(s) = env::var("DST_SEED") {
        let seed: u64 = s.parse().expect("DST_SEED must parse as u64");
        FaultSim::new(seed, config, regime).run(STEPS);
        return;
    }
    for seed in 0..SEEDS {
        FaultSim::new(seed, config, regime).run(STEPS);
    }
}

// honor DST_REGIME by skipping the other regimes' sweeps, so a reported
// (regime, seed) pair reproduces in isolation.
fn regime_selected(regime: &str) -> bool {
    env::var("DST_REGIME").map_or(true, |r| r.eq_ignore_ascii_case(regime))
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// ClearSky: no faults. The full differential oracle plus all safety invariants.
// This is also the proof that the fault harness, with the injector configured to
// do nothing, agrees with the fault-free slice-1 harness.
#[test]
fn clear_sky_full_oracle() {
    if regime_selected("clear_sky") {
        sweep("clear_sky", FaultConfig::CLEAR_SKY);
    }
}

// Stormy: drop/delay/reorder/duplicate. The differential oracle holds on the
// realized stream; the safety invariants hold throughout.
#[test]
fn stormy_survives_lossy_transport() {
    if regime_selected("stormy") {
        sweep("stormy", FaultConfig::STORMY);
    }
}

// Apocalyptic: adds field corruption (mangled slot indices and rights). The
// core must still uphold every invariant, and a corrupted/stale reference must
// never be honored.
#[test]
fn apocalyptic_survives_corruption() {
    if regime_selected("apocalyptic") {
        sweep("apocalyptic", FaultConfig::APOCALYPTIC);
    }
}

// the harness is a pure function of (seed, regime): two runs produce the
// identical realized stream and outcomes. this is what makes a reported
// (regime, seed) a faithful reproduction.
#[test]
fn fault_harness_is_deterministic() {
    let seeds = if cfg!(miri) { 2 } else { 24 };
    for regime in ["clear_sky", "stormy", "apocalyptic"] {
        if !regime_selected(regime) {
            continue;
        }
        let config = config_for(regime);
        for seed in 0..seeds {
            let mut a = FaultSim::new(seed, config, regime);
            let mut b = FaultSim::new(seed, config, regime);
            a.run(STEPS);
            b.run(STEPS);
            assert_eq!(a.log, b.log, "{regime} nondeterministic at seed {seed}");
        }
    }
}

// a sanity check that the regimes actually differ: under Stormy/Apocalyptic the
// realized stream diverges from the generated stream (faults fire), whereas
// under ClearSky it is identical. guards against the injector silently doing
// nothing (which would make the fault tests vacuous).
#[test]
fn regimes_actually_inject_faults() {
    if cfg!(miri) {
        return; // the statistical argument needs more steps than Miri affords
    }
    // ClearSky: realized op count equals generated op count (one per step).
    let mut clear = FaultSim::new(1, FaultConfig::CLEAR_SKY, "clear_sky");
    clear.run(STEPS);
    assert_eq!(clear.log.len(), STEPS, "ClearSky must deliver one op per step");

    // Stormy: faults drop and buffer ops, so the realized count differs.
    let mut stormy = FaultSim::new(1, FaultConfig::STORMY, "stormy");
    stormy.run(STEPS);
    assert_ne!(
        stormy.log.len(), STEPS,
        "Stormy realized exactly STEPS ops; faults may not be firing",
    );
}
