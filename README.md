# jos (Jason's Operating System)

A capability-based microkernel in Rust that aims to be **verified by construction**
and **deterministically simulable** -- a small, security-first kernel where
capabilities, formal verification, and simulation testing are the same architectural
decision seen from different angles.

It runs on `x86_64` under QEMU today.

## The idea

> All authority and communication flow through explicit, kernel-mediated capability
> invocations.

A capability is an unforgeable token of authority: there is no ambient authority, so a
component can only use what it was explicitly handed. The keystone insight, already
realized in the code, is that **Rust's module privacy gives seL4's unforgeability
property for free**: a capability reference can only be produced by inserting into a
real table, and its fields are private, so a "fake" one cannot be constructed in safe
code. The type system *is* the proof.

That one decision pays off five ways at once: security (no confused-deputy bugs),
isolation (userspace drivers, restartable), idiomatic Rust (a capability is an owned,
rights-typed value), verifiability (a small core with no kernel heap is SMT-reachable),
and traceability (every interaction is a kernel-mediated chokepoint to tap, mock, and
record).

## North stars

1. **Capability microkernel** -- unforgeable owned tokens, no ambient authority,
   userspace drivers.
2. **Async-first** -- `async`/`await` as the kernel's scheduler, structured concurrency.
3. **Plan 9-style namespaces** -- everything a capability-mediated file (future).
4. **Verifiable by construction** -- finite interfaces, no kernel heap, a pure-logic
   core reachable by Kani and Miri; verification grows with the code.
5. **Traceable / simulable / mockable** -- a deterministic core with time, randomness,
   and I/O injected behind traits; the event log is a record/replay log.
6. **Idiomatic, ergonomic Rust** -- typestate, owned peripherals, `unsafe` confined,
   newtypes.

The formal docs are under [`docs/`](docs/).

## Status

**Phase 3 (ring-3 userspace, per-thread kernel stacks, preemptive scheduling) is
complete.** Phase 4 (blocking IPC, formal verification layers) is in progress.

What works today:

- Boot via a hand-rolled multiboot2 + GRUB long-mode trampoline (no bootloader crate);
  GDT/TSS, IDT, PIC timer and keyboard, paging, a frame allocator, and a kernel heap.
- The five seL4 object types (Untyped, page table, CNode/CSpace, TCB, Endpoint), carved
  from untyped memory with no post-boot kernel allocation.
- Capabilities with phantom-typed rights, monotone attenuation, and O(1)
  generation-counted revocation.
- Userspace: ring-3 via `iretq`, `SYSCALL`/`SYSRET` boundary, per-thread kernel stacks
  and capability spaces, IPC and `retype`/`invoke` syscalls, W^X page permissions.
- Preemptive round-robin scheduler: a naked timer stub saves the full GPR set as an
  `IrqFrame`, the Rust handler context-switches by overwriting the frame in-place.
  Pluggable via the `SchedPolicy` trait in `jos-core`.
- Blocking IPC syscalls (send/recv rendezvous): parked threads sleep in a kernel hlt
  loop and are woken by the timer when a partner arrives.
- Deterministic simulation testing of the verified core: a seeded RNG, a spec-as-oracle
  capability-space harness, TigerBeetle-style fault regimes, and IPC message-conservation
  testing, all reproducible from a seed.
- Kani bounded proofs: untyped spatial non-overlap (MEM-1), run-queue invariants,
  clock monotonicity, and round-robin starvation-freedom.
- In-kernel structured tracing: every syscall recorded into a ring buffer.

## Layout

```
jos-core/   pure no_std logic with no hardware dependencies. builds for the host, so it
            is exercised under cargo test, Miri, and Kani. capability tables, rights,
            untyped arithmetic, page-table math, the endpoint state machine, the RNG and
            fault models, and the DST harnesses live here.
kernel/     the bootable kernel: assembly, MMIO, and the hardware glue around jos-core.
            builds bare-metal via kernel/.cargo/config.toml (a custom x86_64 target).
docs/       formal technical docs (see below).
docs/VISION.md  design rationale and roadmap (also in docs/ below).
```

The split is load-bearing: the verifiable logic lives in `jos-core` because Miri cannot
run the kernel (the first `asm!` stops it) and Verus pins a conflicting toolchain. The
same split is what deterministic simulation needs, so jos adopts it from the start.

## The verification ladder

jos's distinctive bet is that **formal verification and deterministic simulation are two
halves of one correctness story**, and the architecture makes both cheap. The rungs,
each independently valuable:

- **Hygiene** -- `overflow-checks` in every profile, `#![deny(unsafe_op_in_unsafe_fn)]`,
  clippy pedantic, and `cargo miri test` on the pure-logic crate.
- **Kani** -- bounded model checking of the core arithmetic and data-structure
  invariants (rights attenuation, the capability table, untyped/page-table math, the
  endpoint rendezvous).
- **Deterministic simulation** -- seeded, reproducible workloads checked against an
  independent model, with injected faults.

A working discipline worth calling out: new oracles and proofs are checked for
**non-vacuity** with a deliberate negative control (break the invariant, confirm the test
fails, revert), so a passing test actually means something.

## Building and running

Everything runs inside the Nix dev shell. See [`docs/building-and-running.md`](docs/building-and-running.md)
for the full story; the short version:

```bash
nix develop --command cargo test -p jos-core            # host logic: tests
nix develop --command cargo miri test -p jos-core       # undefined-behavior checks
nix develop .#verify --command cargo kani -p jos-core   # bounded proofs
nix develop --command bash -c 'cd kernel && cargo test' # boot each test under QEMU
```

## Docs

- [`docs/capabilities.md`](docs/capabilities.md) -- the capability microkernel core.
- [`docs/dst.md`](docs/dst.md) -- deterministic simulation testing and tracing.
- [`docs/building-and-running.md`](docs/building-and-running.md) -- toolchain, target,
  boot, and the test harness.
- [`docs/testing.md`](docs/testing.md), [`docs/vga.md`](docs/vga.md) -- focused notes.

## References

[^3]: https://wiki.osdev.org/Expanded_Main_Page
[^4]: seL4 (capabilities, untyped memory): https://sel4.systems/
