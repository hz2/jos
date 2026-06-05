# Deterministic Simulation Testing and Tracing

## The thesis

jos bets that formal verification and deterministic simulation are
**complementary halves of one correctness story**, not competing approaches.
Verification proves the logic is right for all inputs in a bounded domain.
Simulation stress-tests the logic against thousands of randomly-generated input
sequences that no human would think to write. Neither is sufficient alone;
together they cover different parts of the correctness surface and each makes
the other cheaper to apply.

The capability microkernel architecture makes both unusually cheap:

- The kernel core is a pure function of its state and input messages. It has no
  ambient I/O, no hidden clocks, no background threads. Every interaction is an
  explicit, kernel-mediated capability invocation.
- Because all external input arrives through a single chokepoint, recording
  "everything that happened" is recording the capability invocation log -- there
  is no other source of non-determinism to capture.
- A bounded, heap-free kernel with finite interfaces is exactly the kind of
  system SMT-based tools can reach.

The architecture does not trade one property off against the other. It gives you
both.

## The four DST pillars

The FoundationDB / TigerBeetle / Antithesis school of deterministic simulation
rests on four pillars. All four fall out of the jos architecture without
additional machinery:

1. **Deterministic single-threaded core.** The async executor controls every
   yield point. There is no scheduling non-determinism: the next task to run is
   always the one at the head of the verified `RunQueue`, and the executor never
   preempts. The kernel core is already a pure `(State, Message) -> (State,
   [Message])` function.

2. **Single seeded RNG.** The `KernelRng` HAL trait (`jos-core::rng`) is the
   single source of randomness. In production the kernel passes a hardware
   generator (RDRAND/RDSEED, a future `kernel/` impl). In simulation it passes
   a `SimRng` seeded from a known `u64`. Same seed, same stream, every run.
   The kernel core never seeds an RNG from entropy.

3. **Simulated time.** A `KernelClock` trait (the `KernelRng` mirror, landing in
   the next DST slice) replaces wall-clock calls with injected values. The
   kernel core never calls `Instant::now()` directly.

4. **Injected faults.** The simulated IPC/HAL layer can drop, delay, reorder,
   duplicate, or corrupt messages. In the jos model, faults are delivered
   through the same HAL trait boundary. The kernel core cannot distinguish
   simulated hostile input from real input -- this is the design goal.

Replay is trivial: reset the capability space to empty and replay the op log in
sequence order. The log is a complete record because the capability invocation
chokepoint is the only place non-determinism can enter.

## The verification ladder

jos approaches correctness incrementally. Each rung is independently valuable
and is never discarded when the next is added:

| Rung | Tool | What it catches |
|---|---|---|
| 0. Hygiene | `overflow-checks`, clippy pedantic, `deny(unsafe_op_in_unsafe_fn)` | Trivial arithmetic overflow, bad unsafe idioms |
| 1. Kani | Bounded model checking | Index-out-of-bounds, panic-freedom, arithmetic correctness for all inputs in a bounded range |
| 2. Typestate | Rust type system | Illegal state transitions made unrepresentable at zero runtime cost |
| 3. DST | Seeded simulation + spec-as-oracle | Logic bugs across long random histories; invariant violations under slot reuse |
| 4. Loom | Exhaustive interleaving | Data races and ordering violations in lock-free / locked structures |
| 5. Verus | SMT functional correctness | Full correctness of allocator, page tables, IPC, and capability table |
| 6. Spec-as-oracle | Independent reference model | Divergence between optimized impl and a simpler independent model |

The ladder is not a waterfall: rung 0 is already on in CI, rung 1 harnesses
exist for every `jos-core` module, and rung 3 (DST slice 1) is done.

## DST slice 1: what was built

DST slice 1 landed in `jos-core` as three modules in June 2026.

### `jos-core/src/rng.rs`

The `KernelRng` trait declares one required method (`next_u64`) and provides
`below` and `next_bool` as default methods built on it. `below(bound)` uses
Lemire's multiply-shift mapping: the high 64 bits of the 128-bit product
`x * bound`, computed via a pure `const fn map_below`. For `bound >= 1` the
result is strictly less than `bound`; for `bound == 0` it returns `0`. No
division, no rejection loop.

`SimRng` is a `SplitMix64` generator: a single `u64` state advanced by a
fixed odd increment (the golden-ratio constant `0x9E37_79B9_7F4A_7C15`) and
passed through a two-round bit-mixing finalizer. It passes BigCrush, has no
weak seeds, and is trivially seedable. Every arithmetic step uses wrapping
operations because jos builds with `overflow-checks = true` in all profiles and
the mixing relies on defined 2^64 wraparound.

`SimRng` is deliberately not `Copy`. A generator is a moving cursor over its
stream; a silent copy would replay the same words, breaking reproducibility. To
fork a stream intentionally, clone explicitly.

9 unit tests, 2 Kani harnesses (`below_is_in_range` and `below_zero_maps_to_zero`).

### `jos-core/src/trace.rs`

Structured trace events for capability operations. Three types:

- `CapOp` -- the request: `Insert`, `Mint`, `Remove`, `Revoke`, `Check`. All
  address capabilities by slot index (`u32`), matching the syscall boundary.
- `CapOutcome` -- the result: `Installed { slot }`, `Removed { count }`,
  `Checked { allowed }`, or `Refused(Refusal)`.
- `TraceEvent { seq, op, outcome }` -- one log entry with a monotone sequence
  number.

Slot-addressing (not `CapRef`) is the right thing to log for two reasons: it
matches the syscall model (user space presents a plain index), and slot indices
are stable across a record/replay reset while a `CapRef`'s generation is not.

All types are plain `Copy` data with no references or platform-width fields,
shaped for future `postcard` serialization. The `postcard` derives are deferred
to keep `jos-core` dependency-free; adding them is a later feature-gate step.

### `jos-core/tests/dst_capspace.rs`

The spec-as-oracle `CapSpace` harness. A seeded `SimRng` draws a weighted
stream of `CapOp` values (insert and mint dominate to build derivation trees;
remove, revoke, and check tear down and read back) and applies each one to a
real `CapSpace<ObjectToken, 16>`. After every step the harness checks the
implementation against an independent shadow model.

The harness runs 256 seeds of 400 steps each natively, and 2 seeds of 30
steps under Miri. `DST_SEED=<n>` re-runs a single seed to reproduce a
reported failure.

## The spec-as-oracle pattern

The shadow model is `[Option<ModelCap>; N]` -- a flat array of the model's
per-slot view. It has a deliberately different shape from the implementation:

- No generation counter. The model tracks live-or-empty by presence in the
  array.
- Parent stored as the source `CapRef` (generation-bearing), resolved to a
  slot by linear search, rather than the impl's slot-indexed generation-
  checked lookup.

That independence is the point. A bug in the optimized array-with-generations
implementation is unlikely to be mirrored by an identical bug in the naive
model that resolves parent links by brute-force scan. A divergence between them
is a real defect.

Per-step checks (`check_invariants`):

- **Outcome agreement.** The impl and model predict the same `CapOutcome`.
- **Full structural equality.** Every slot agrees on liveness, object identity,
  rights, and parent link.
- **No rights escalation.** A minted child's rights are a subset of its
  source's, verified by reconstructing the derivation from model state.
- **Differential revoke.** The subtree `CapSpace::revoke` removes is exactly
  the set an independent parent-link BFS over the model predicts.
- **Global staleness.** Every `CapRef` ever retired (by remove or revoke) is
  collected in a `retired: Vec<CapRef>` and must never resolve again, across
  slot reuse, for the entire run. This tests the revocation guarantee over long
  histories, not just a single operation.

The `apply_op` function is the single source of truth for "what the kernel does
with an op": it resolves a slot index to a live `CapRef` via `ref_at` (exactly
as the syscall boundary does), invokes the verified `CapSpace`, and maps the
result to a `CapOutcome`. Both the recording path and the replay path call the
same function, so record/replay agreement is not an artifact of code sharing.

## Record / replay

The `record_replay_reconstructs_state` test demonstrates north star 5 concretely:

1. Run a simulation, collecting every `TraceEvent` in a log.
2. Create a fresh `CapSpace` and replay the `op` fields from the log in `seq`
   order using `apply_op`.
3. Assert that every replayed `CapOutcome` matches the recorded one.
4. Assert that a slot-keyed snapshot of the replayed final state equals a
   snapshot of the original final state.

Step 4 compares by slot index rather than by `CapRef` because generations
differ between an original run and a replay (the starting generation of a reused
slot depends on how many times it was vacated, which is reproduced by the same
op sequence but starts at generation 0 in the fresh replay space). Slot indices
are the stable identity.

## Reproducing a failure

Any failure in the seed sweep prints the seed and the sequence number of the
failing step:

```
seed=42 seq=137: slot 5 liveness disagrees: impl_live=true model_live=false
```

To reproduce it exactly:

```bash
DST_SEED=42 cargo test -p jos-core dst_capspace
```

The run is a pure function of its seed. Same seed, same op stream, same failure.

## Kani gotcha: 64-bit multiply hang

CBMC (the backend Kani uses) bit-blasts multipliers into SAT clauses. A 64x64
multiply with both operands symbolic explodes to O(n^2) clauses -- a fully
symbolic `bound` in the `below_is_in_range` harness hung CBMC past 13 minutes
(the same class of hang the `run_queue` proofs document for CBMC with
insufficiently bounded unwind depths).

The fix: make the multiplier's constant operand concrete. The `below_is_in_range`
harness loops over each concrete `bound` in `[1, BOUND_MAX]` (128 values,
covering every bound the DST harness actually draws), so `x * bound` folds to
shift-add. `x` stays fully symbolic, so the result is universally quantified
over all 64-bit words for each concrete bound.

Rule: never feed a symbolic 64-bit value into both operands of `*` in a Kani
harness. Make the constant operand concrete.

## Fault regimes (DST slice 2)

DST slice 2 adds TigerBeetle-style fault regimes (`jos_core::fault`). A
`FaultInjector` transforms an incoming operation stream into a realized stream
by applying faults drawn from the seeded RNG, modeled on the ClearSky / Stormy /
Apocalyptic progression:

- **ClearSky.** No faults. The baseline: every operation is delivered exactly
  once, in order, and the full differential oracle holds.

- **Stormy.** Drops, delays, reorders, and duplicates, but no corruption. A
  dropped operation reaches neither side; a delayed one is released later
  (possibly behind operations that were not delayed); a duplicate is applied
  twice.

- **Apocalyptic.** Adds field corruption: mangled slot indices and rights masks.
  The "environment is adversarial and lossy" regime.

The key design point is that faults are injected at the transport layer, above
both the implementation and the shadow model, so the differential oracle holds
on the realized stream even under Apocalyptic corruption: both sides see the
identical realized operations, including corrupted ones. A capability reference
cannot be forged at all (its fields are private), so the strongest corruption an
attacker controls is the slot index in an operation, which the core resolves per
call and rejects when stale or out of range. That rejection, a stale or forged
reference never being honored, is the seL4 unforgeability property under fault
injection, and the `dst_faults` harness probes it on every step.

## IPC message conservation (DST slice 3)

DST slice 3 lifts the capacity-1 synchronous endpoint rendezvous out of
`kernel/src/cap.rs` into a pure, host-testable, Kani-verified state machine
(`jos_core::endpoint`); the kernel's `EndpointInner` now delegates to it and
keeps only the parked peers' `Waker`s. The rendezvous invariants (capacity-1,
a sender and a receiver are never parked at once, a taken message equals the
deposited one) are proven in `jos-core` rather than only asserted by the QEMU
tests.

On top of that, `dst_ipc` drives many senders and receivers contending several
capacity-1 endpoints under a seeded schedule, and proves conservation: no
message is lost, duplicated, or corrupted. Every message that enters the
pipeline ends up received, in an endpoint slot, or waiting in a sender outbox,
and nowhere else. The slice-2 fault regimes apply at the message layer (sends
are dropped, delayed, duplicated, and corrupted), with conservation anchored on
the realized stream just as the capability oracle is.

## In-kernel tracing

Tracing is now wired into the kernel itself, not just the host harness. Because
every capability operation from userspace crosses the syscall dispatcher, that
dispatcher is a mandatory chokepoint, and `dispatch_syscall` taps it: each call
records a `jos_core::trace::SyscallEvent` (the raw boundary values, the syscall
number, its register arguments, and the `rax` result, plus a monotone sequence
number) into a per-CPU ring buffer.

The buffer (`kernel/src/trace.rs`) wraps the Kani-verified `RingBuffer` with an
overwrite-oldest policy and a monotone sequence counter, so a busy syscall stream
keeps the most recent window rather than going deaf, and an ordered drain yields
the events in the order they happened. That ordered drain is the record half of
record/replay on real hardware: the visible "traceable" half of the
verify-and-simulate story, made concrete against the running kernel rather than
only the host model.

## Still ahead

A `KernelClock` seam (the deterministic injected clock, mirroring `KernelRng`)
for time-driven scenarios such as timeouts; record/replay built on the live
trace (reset and re-present the recorded `SyscallEvent` stream); and optional
`postcard` serialization of the trace for off-box capture (the events are
already fixed-size and serialization-shaped).

[^1]: [FoundationDB deterministic simulation](https://apple.github.io/foundationdb/testing.html)
[^2]: [TigerBeetle VOPR](https://github.com/tigerbeetle/tigerbeetle/blob/main/src/vopr.zig)
[^3]: [Antithesis deterministic hypervisor](https://antithesis.com/blog/deterministic_hypervisor/)
[^4]: [Kani model checker](https://model-checking.github.io/kani/)
