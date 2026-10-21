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
| IPCBUF-1 | message words survive the trip through IPC buffers: the receiver sees word 0 and the sender's words 1 to 3; with no sender buffer it sees zeros, never stale data; delivery clears `caps_received` and leaves the capability fields alone, and slot fields decode zero as none | Kani | `ipc_buffer.rs` |
| MAP-1 | the mapping registry never holds two mappings of the same object, over any sequence of records and forgets; a recorded mapping is found and removed exactly | Kani | `mapping.rs` |
| CAP-2 | a copy into another capability space never gains a right; revoking an original removes every copy of it in another space, and copies of those, while unrelated capabilities survive | Kani | `cap_space.rs` |
| CAP-3 | revoking any capability removes exactly its subtree and nothing else, checked against the harness's own record of parents: in one space for any shape three mints build, and across two spaces for any two derivations by mint or copy (a cross-space chain, or two children); every derivation names its source's object; releasing a space relinks what was derived through it to its nearest ancestor outside, so revoking that ancestor with the space gone still removes it | Kani | `cap_space.rs` |
| EP-1 | endpoint rendezvous: sender and receiver never both parked; parking is self-guarding; messages are neither fabricated nor corrupted | Kani | `endpoint.rs` |
| NTFN-1 | notification state machine invariants | Kani | `notification.rs` |
| CLOCK-1 | `KernelClock` is monotone; deadlines are never in the past | Kani | `clock.rs` |
| SCHED-1 | round robin serves all N threads in N steps (starvation-freedom); removing a thread takes out exactly that one and keeps the others in order, and the queue invariant holds across enqueue, dequeue, and remove | Kani | `sched_policy.rs`, `run_queue.rs` |
| INV-1 | the ring buffer and run queue declare their representation invariants (`kani::Invariant`), and every push, pop, enqueue, dequeue, and remove keeps them from any valid state, not only from states a few operations past empty | Kani | `ring_buffer.rs`, `run_queue.rs` |
| PTE-SPLIT | splitting a 2 MiB page into 512 4 KiB entries preserves every translation in it and its present, writable, user, and no-execute bits (what makes a guard page safe to carve out of the identity map) | Kani | `pte.rs` |
| BOOT-1 | the multiboot2 parser never leaves the info structure: on every 64-byte input, each tag the walk yields is the 8-aligned tag the format places where the previous one ended, decoded from its own header, and lies inside the first `total_size` bytes; the walk stops only at an end tag, a tag smaller than its header, or a tag running past `total_size`, yields fewer than `total_size / 8` tags, and stays stopped; memory map entries (every 56-byte payload) and module addresses and command lines (every 24-byte payload) are exactly the bytes the format places inside their own tag | Kani | `multiboot2.rs` |
| BOOT-2 | the usable memory list holds exactly the free pages (inside an available range, below the identity-map limit, touching no reserved range) as sorted, page-aligned, maximal runs; with too little room it still holds only free pages, sorted with gaps, and reports the bytes it dropped (one available and one reserved range below 4 GiB, any limit) | Kani | `boot_regions.rs` |
| ELF-1 | the ELF loader's parser never panics or reads outside the image (every 120-byte image with its program header table where linkers put it; every dynamic section inside 64 bytes, for any two segments and any base); every relocation it accepts writes eight bytes inside a writable segment, at the base plus `r_offset`, and stores the base plus `r_addend`; it refuses exactly the images with a writable and executable segment (any flags) and exactly the segments that share a page (any addresses and sizes) | Kani | `elf.rs` |
| BLOCK-1 | the tables of threads parked in blocking IPC behave as a list in park order over every five-step sequence of parks and takes on a two-entry table: a park fails exactly when the thread is parked already or the table is full; a take by endpoint, by expired deadline, or by thread returns the first matching waiter in park order (so a newcomer in a reused entry still queues last) or nothing, and each waiter leaves exactly once | Kani | `wait_table.rs` |
| LINE-1 | the console line editor, over every six-byte input on a three-byte line: each byte changes the line exactly as the edit it returns says (typed adds that byte at the end, erased removes one, cleared and interrupted empty it, full and the rest leave it alone), a kept character keeps its value, and the line never outgrows its capacity and holds only printable ASCII | Kani | `line.rs` |
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
private memory. `SetIpcBuffer` now enforces this and
`ipc_buffer_registration` and `frame_revoke` test it end to end; the proof
obligation that remains is a model of registration in jos-core that Kani can
check. Frames are placed with `place_zeroed`, which shares MEM-1's verified
arithmetic, so the non-overlap half already holds.

### ARITH-2: frame allocator refinement

The frame allocator meets an abstract spec: allocations never alias, the free
list is never corrupted, double free panics. Verus spec plus a Kani bounded
free-list invariant.

### ARITH-3: trace encoding round trip

The postcard trace format round-trips without loss, and the decoder never
panics on kernel-produced bytes. Kani.

## Backlog

- **LOCK-1**: the lock-order graph (WITNESS-style checker) rejects every cycle.
- **CAP-SPEC**: a Verus specification of the whole capability state machine
  that the kernel is proven to implement (the seL4-style goal).
- **TUE**: post-quantum crypto capability; key material never leaves its page.
- **CMP2**: carbon-aware scheduling tiers respect a capability-granted flag.
