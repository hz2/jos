# The Capability Microkernel Core

## What a capability is

A capability in jos is an unforgeable owned token of authority. Holding one is
what grants permission to invoke an operation on a kernel object -- there is no
ambient authority, no UID-based checks, no global permission table.

The keystone insight is that **Rust module privacy gives the unforgeability
property for free**. In seL4, unforgeability is a manual Isabelle proof: the C
implementation is audited to ensure nothing outside the kernel constructs a
valid CNode slot pointer. In jos, it falls out of the language. `CapRef`'s
`slot` and `generation` fields are private to `jos-core::cap_table`; no code
outside that module can construct or name a value of that type. Safe Rust
simply cannot forge a capability. The type system is the proof.

This is also why `cap-std` (the Bytecode Alliance crate) is a shipping
demonstration that capability-based access control is natural Rust, not a
stretch.

## The five object types

Everything the kernel manages is one of these:

| Type | Module | Size / align | Role |
|---|---|---|---|
| `Untyped` | `cap.rs` / `untyped.rs` | `2^size_bits` bytes, naturally aligned | Raw memory region; all other objects carved from it |
| `PageTable` | `cap.rs` | 4096 / 4096 bytes | One x86_64 page-table frame; used as PML4 root or intermediate table |
| `CNode` (CSpace) | `cap.rs` | 4096 / 4096 bytes | A `KernelCNode` holding a `KernelCapSpace`; the per-task capability table |
| `Tcb` | `cap.rs` | 512 / 64 bytes | Thread control block: saved register context plus CSpace and VSpace roots |
| `Endpoint` | `cap.rs` | 128 / 64 bytes | Synchronous IPC endpoint with parked-sender and parked-receiver waker slots |

`Endpoint` and `Tcb` are cache-line (64-byte) aligned with a larger size: in
both cases size and alignment are powers of two and alignment divides size, so
a 64-aligned watermark satisfies the placement constraint. `PageTable` and `CNode` are page-sized and
page-aligned so they can serve directly as hardware page-table frames or be
addressed by a plain page index. Every size and alignment is a compile-time
constant in `jos-core::untyped` and is independently checked by `size_of`
assertions in `kernel::cap`.

## The untyped-memory model

jos follows seL4's "kernel never allocates after boot" discipline. There is no
kernel heap. Instead, a static byte array (`&'static mut [u8]`) serves as the
initial untyped region. Objects are carved from it via a watermark allocator:
`retype_fits` (in `jos-core::untyped`) computes whether an object of a given
type fits at the current watermark and returns the new watermark if it does.
The kernel then calls `place` (from `jos-core::placement`) to write the
initialized object into those bytes and records the address as an `ObjectId`.

The watermark only advances; there is no individual free. Reclaiming memory
requires retyping the whole region, which is deferred. This means the kernel's
memory layout is fixed and completely enumerable -- exactly the bounded,
finite structure that makes formal verification tractable, and that gave the
seL4 proof its resource-accounting completeness.

`retype_fits` is pure logic with no hardware dependency. It is exercised under
`cargo test`, Miri, and Kani (three harnesses: result in range, placement
aligned, function total / never panics). The `UntypedRegion` struct that wraps
the actual bytes and drives `place` lives in `kernel/src/cap.rs` and is not
Miri/Kani-testable because it holds a raw pointer to kernel memory.

## Rights and monotone attenuation

Each capability carries a `Rights` value: a `u8` bitset with four defined bits.

| Bit | Constant | Meaning |
|---|---|---|
| 0 | `READ` | Receive from / read the object |
| 1 | `WRITE` | Send to / write the object |
| 2 | `GRANT` | Delegate full authority over this capability |
| 3 | `GRANT_REPLY` | Delegate a reply-only derivative |

`Rights::attenuate(mask)` computes the bitwise intersection of the holder's
rights and the mask. Intersection can only clear bits, never set them, so the
result is always a subset of both operands. This is the monotone attenuation
property: a holder can only pass on a subset of the rights they themselves
possess. Kani verifies this with five harnesses (monotone, empty-attenuates-to-
empty, attenuate-by-ALL-is-identity, idempotent, commutative).

When minting a derived capability, `CapSpace::mint` records the source
`CapRef` as `parent`, building the capability derivation tree that revocation
traverses.

## Generation-counted CapRefs and O(1) revocation

`CapRef` is a `(slot: usize, generation: u32)` pair. `CapTable::insert`
returns one; every subsequent `get`, `remove`, or `check` call revalidates it
against the slot's current generation before touching anything.

When a capability is removed, the slot's generation counter is incremented.
Every `CapRef` minted before that removal becomes permanently stale: slot
reuse does not let old tokens reach the new occupant. This is O(1) revocation
-- no CDT walk, no broadcast to holders.

`CapSpace::revoke` extends this to subtrees: it first marks the full
derivation subtree (following `parent` links while they are still live), then
sweeps them out. The mark-before-sweep order is required because removing a
node destroys its `parent` link. The scan is O(N) per tree level, which is
acceptable for the small N a capability space uses and keeps the logic
verifiable.

`CapSpace::ref_at(slot)` reconstructs a live `CapRef` from a plain slot index
against the current generation. This is how the syscall boundary works: user
space presents a plain integer slot index, and the kernel resolves it per-call.
A revoked-and-reused slot yields a ref for its new occupant, never a stale one.

## The jos-core / kernel split and why it exists

jos separates its capability logic into two crates:

- `jos-core` -- pure, `no_std`, zero hardware dependency. Contains
  `cap_rights`, `cap_table`, `cap_space`, `untyped`, `placement`, `rng`,
  `trace`, `ring_buffer`, `run_queue`, `pte`, and related modules. No `asm!`,
  no MMIO, no raw physical pointers. 173 tests, 47 Kani harnesses, Miri-clean.

- `kernel` -- the binary that actually runs. `kernel/src/cap.rs` provides
  `ObjectId`, `UntypedRegion`, `Endpoint`, `PageTable`, `Tcb`, `KernelCNode`,
  and the `cap_send`/`cap_recv`/`revoke_and_wake` IPC glue. This is where
  `asm!`, MMIO, placement into real memory, and hardware-specific code live.

Three independent constraints force this split:

1. **Verus toolchain.** Verus pins a specific Rust toolchain version (around
   1.86) that conflicts with the kernel's nightly. Verus also hard-blocks on
   `asm!`: any block of assembly in scope prevents the verifier from processing
   the file. Pure logic must live in its own crate to be verifiable.

2. **Miri.** Miri cannot interpret the kernel binary: the first `asm!`
   instruction stops the interpreter, and physical-address pointer casts are
   not modeled. `cargo miri test` on `jos-core` gives genuine UB detection on
   the logic crate with zero effort. That is only possible because the crate
   has no hardware dependency.

3. **Deterministic Simulation Testing.** DST requires injecting faults,
   simulating time, and seeding all randomness from a single known value. That
   demands a clean trait boundary between the kernel core and the hardware it
   runs on. The `KernelRng` trait (`jos-core::rng`) is the prototype; a
   `KernelClock` trait follows in the next DST slice. Without the split, none
   of the simulation machinery can run on the host.

The `jos-core` crate is what the Verus, Miri, and DST toolchains all see.
`kernel` is the hardware-specific shell that instantiates it.

## Capability-mediated IPC

jos uses synchronous rendezvous IPC modeled on seL4. An `Endpoint` object holds
the rendezvous state (`Idle` or `SendBlocked`) plus one parked message and two
`Waker` slots (one per direction) for the async executor.

The non-blocking primitives are `cap_send` and `cap_recv` in
`kernel/src/cap.rs`. Both call `resolve_endpoint`, which:

1. looks up the `CapRef` in the `KernelCapSpace` (rejects stale refs),
2. checks that the capability carries the required right (`WRITE` for send,
   `READ` for receive),
3. checks that the named object is actually an `Endpoint`.

The deposit or take then happens under the endpoint's `Mutex`. On success, any
parked counterpart waker is taken from the lock and fired after the lock is
released, keeping the wake off the locked path.

The async wrappers (`send`/`recv` futures) park the task's `Waker` inside the
endpoint on `Full`/`Empty` and yield `Poll::Pending`. They re-validate the
capability on every poll via `resolve_endpoint`, so revoking a capability while
a task is blocked on it causes the next poll to return `IpcError::InvalidCap`
rather than hang. `revoke_and_wake` closes the gap for already-parked futures:
it collects endpoint objects in the revoke subtree before removing capabilities,
then fires their wakers after the generations are bumped.

## Syscall boundary

Syscalls address capabilities by plain `u64` slot index. The kernel resolves
the index to a live `CapRef` via `CapSpace::ref_at` on every call. This means
the resolution is always current: if a capability was revoked between two
syscalls, the next call sees an empty slot and returns an error rather than
reaching a stale object. There is no cached `CapRef` in user space that could
outlive the capability it names.

## Divergences from seL4

jos intentionally departs from seL4 in three places:

- **Generation-counted CapRefs instead of CDT-walk revocation.** seL4 maintains
  a Capability Derivation Tree and walks it on revoke. jos bumps a per-slot
  generation counter on remove, so the common revocation case is O(1) without
  a CDT walk. The subtree revoke still does a scan, but it traverses the
  in-table `parent` links rather than a separate CDT.

- **Two-level addressing (global object table + per-CSpace cap table).** seL4
  addresses objects via raw CNode pointers traversed from a root CNode. jos
  uses `ObjectId` (a `usize` address plus a kind tag) as the stable object
  handle stored in a capability, and a `CapSpace<ObjectId, N>` as the per-task
  capability table. This avoids raw-pointer aliasing in the verified core: the
  `jos-core` crate never sees a real pointer, only an opaque `Copy` handle.

- **Rust privacy as the unforgeability mechanism.** seL4 relies on a kernel
  written in restricted C where capability fields are never exposed. jos relies
  on Rust's module privacy: `CapRef` fields are private to their module and
  cannot be named, let alone constructed, in safe code outside it. The property
  is enforced by the language rather than by auditor discipline.

[^1]: [seL4 capabilities tutorial](https://docs.sel4.systems/Tutorials/capabilities.html)
[^2]: [seL4 untyped memory tutorial](https://docs.sel4.systems/Tutorials/untyped.html)
[^3]: [Atmosphere: a Rust microkernel verified with Verus](https://github.com/mars-research/atmosphere)
[^4]: [cap-std](https://github.com/bytecodealliance/cap-std)
