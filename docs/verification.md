# Verification

What jos proves, with which tool, and what is next. Move a target to "Proved"
in the same commit that lands its harness. Deterministic simulation testing,
the other half of the correctness story, is in [`dst.md`](dst.md).

## Toolchain

| tool | scope | run |
|------|-------|-----|
| Miri | undefined behavior in jos-core's unsafe code | `scripts/check.sh miri` |
| Kani | bounded model checking of invariants | `scripts/check.sh kani [harness]` |
| Verus | unbounded functional correctness, ghost state | `scripts/check.sh verus` |

All three need hardware-free code, which is why `jos-core` is a separate crate.
Kani harnesses live in a `#[cfg(kani)] mod kani_proofs` at the bottom of the
file they prove. Verus proofs live in `jos-core/src/proof.rs`, compiled only
under `cfg(verus_keep_ghost)`; `scripts/check.sh verus` runs the verifier on that module
inside the verify shell.

Every harness gets a negative control when it lands: break the property,
confirm the proof fails, revert.

## Proved

| id | claim | tool | where |
|----|-------|------|-------|
| MEM-1 | objects placed in one untyped region never overlap; the watermark stays in bounds; starts are aligned | Kani + Verus (4 lemmas) | `placement.rs`, `proof.rs` |
| CAP-1 | no authority amplification: along any mint chain no descendant holds, or can check, a right its root lacked | Kani | `cap_space.rs` |
| IPC-BADGE | a badge is set at most once and inherited unchanged; badged mints never escalate; the endpoint delivers the sender's badge with the message | Kani | `cap_space.rs`, `endpoint.rs` |
| REPLY-1 | a reply object accepts at most one answer per bound caller and never delivers to an unbound one | Kani | `reply.rs` |
| IPCBUF-1 | message words survive the trip through IPC buffers: the receiver sees word 0 and the sender's words 1 to 3; with no sender buffer it sees zeros, never stale data | Kani | `ipc_buffer.rs` |
| EP-1 | endpoint rendezvous: sender and receiver never both parked; parking is self-guarding; messages are neither fabricated nor corrupted | Kani | `endpoint.rs` |
| NTFN-1 | notification state machine invariants | Kani | `notification.rs` |
| CLOCK-1 | `KernelClock` is monotone; deadlines are never in the past | Kani | `clock.rs` |
| SCHED-1 | round robin serves all N threads in N steps (starvation-freedom) | Kani | `sched_policy.rs`, `run_queue.rs` |
| IPC-1 | deadlock-freedom under receive-with-timeout | DST | `jos-core/tests/dst_recv_timeout.rs` |
| ARITH-1 | Verus build plumbing works without breaking test, Miri, or Kani | Verus | `proof.rs` |

## Active (in priority order)

### JPC-1: IPC deadlock-freedom (Verus)

A blocking send and a blocking receive on the same endpoint cannot both wait
forever; the rendezvous always makes progress. The state machine in
`endpoint.rs` is already Kani-checked for bounded sequences; the Verus proof
makes it unbounded, with ghost state for the parked peers.

### JPC-2: IPC buffer frames cannot alias kernel memory

The kernel reaches IPC buffers through registered frames, not user pointers, so
the obligation moves to registration: a buffer can only be registered from a
Frame capability, so it can never name a kernel object or another thread's
private memory. Today only kernel setup code registers buffers; this lands with
the registration syscall (Kani for the frame checks, an integration test for
the end-to-end path).

### ARITH-2: frame allocator refinement

The frame allocator meets an abstract spec: allocations never alias, the free
list is never corrupted, double free panics. Verus spec plus a Kani bounded
free-list invariant.

### ARITH-3: trace encoding round trip

The postcard trace format round-trips without loss, and the decoder never
panics on kernel-produced bytes. Kani.

## Backlog

- **ELF-1**: the ELF64 header parser never reads out of bounds on any input
  (Kani plus a fuzz target). Lands with the loader.
- **BLOCK-1**: a pure model of the blocking-IPC direct-handoff tables so the
  syscall path gets the same coverage as the async path.
- **LOCK-1**: the lock-order graph (WITNESS-style checker) rejects every cycle.
- **CAP-SPEC**: a Verus specification of the whole capability state machine
  that the kernel is proven to implement (the seL4-style goal).
- **TUE**: post-quantum crypto capability; key material never leaves its page.
- **CMP2**: carbon-aware scheduling tiers respect a capability-granted flag.
