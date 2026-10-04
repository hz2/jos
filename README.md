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

**Phases 0 to 3 are done; phase 4 (real IPC, userspace, drivers) is about a
quarter of the way.** jos boots, enters ring 3, and runs capability-checked
syscalls on top of a verified pure-logic core. It does not yet load programs
from ELF images or run userspace servers; see [`TODO.md`](TODO.md) for the next
steps and [`docs/roadmap.md`](docs/roadmap.md) for the full plan.

What works today:

- Boot via a hand-rolled multiboot2 + GRUB long-mode trampoline (no bootloader crate);
  GDT/TSS, IDT, PIC timer and keyboard, paging, a frame allocator, and a kernel heap.
- The seL4 object types (Untyped, page table, CNode/CSpace, TCB, Endpoint,
  Notification), carved from untyped memory with no post-boot kernel allocation.
- Capabilities with monotone rights attenuation, O(1) generation-counted
  revocation, and seL4-style badges: a server mints one badged endpoint cap per
  client, the badge can be set only once, and it arrives with every message.
- Userspace: ring 3 via `iretq`, a `SYSCALL`/`SYSRET` boundary, per-thread kernel
  stacks and capability spaces, IPC / `mint` / `retype` / `invoke` syscalls, W^X
  user pages.
- Hardware guards: SMEP and SMAP are on, and the kernel touches user pages only
  inside an explicit `stac`/`clac` window.
- Preemptive round-robin scheduler: a naked timer stub saves the full GPR set as an
  `IrqFrame` and the Rust handler context-switches by rewriting it in place.
  Pluggable via the `SchedulingPolicy` trait in `jos-core`.
- Blocking IPC syscalls (send/recv rendezvous) and async IPC with
  receive-with-timeout and revocation that cancels blocked waiters.
- Deterministic simulation testing of the verified core: a seeded RNG, a
  spec-as-oracle capability-space harness, fault regimes, and IPC
  message-conservation checks, all reproducible from a seed.
- Kani proofs: untyped spatial non-overlap, global no-authority-amplification,
  badge immutability, endpoint and notification state machines, one-shot reply,
  clock monotonicity, round-robin starvation-freedom. Verus is wired with its
  first lemmas.
- In-kernel structured tracing: every syscall recorded into a ring buffer.

What is missing (in order): `Call`/`Reply` syscalls and an IPC buffer page,
capability transfer, an ELF loader and a root task, FPU state, APIC/ACPI,
userspace drivers, SMP.

## Layout

```
jos-core/   pure no_std kernel logic with no hardware dependencies: capabilities,
            IPC state machines, untyped and page-table math, scheduling policy,
            the clock, and the simulation harnesses. builds for the host.
kernel/     the bootable kernel: assembly, MMIO, and the hardware glue around
            jos-core. builds bare-metal via kernel/.cargo/config.toml.
docs/       project documentation (see below).
scripts/    check.sh (every gate), check-style.sh, and run-qemu.sh (the cargo runner).
.githooks/  git hooks: fast gate on commit, full gate on push.
```

The split is load-bearing: the verifiable logic lives in `jos-core` because Miri
cannot run the kernel (the first `asm!` stops it) and Verus pins its own
toolchain. The same split is what deterministic simulation needs.

## The verification ladder

jos's distinctive bet is that **formal verification and deterministic simulation
are two halves of one correctness story**, and the architecture makes both cheap.
Each rung is independently valuable:

- **Hygiene**: `overflow-checks` in every profile, `#![deny(unsafe_op_in_unsafe_fn)]`,
  clippy pedantic, a `SAFETY:` comment on every `unsafe`, and Miri on jos-core.
- **Kani**: bounded proofs of the capability, IPC, memory, clock, and scheduler
  invariants.
- **Verus**: unbounded proofs, starting with untyped placement; IPC
  deadlock-freedom is next.
- **Deterministic simulation**: seeded, reproducible workloads checked against an
  independent model, with injected faults.

New oracles and proofs are checked for **non-vacuity** with a deliberate negative
control (break the invariant, confirm the check fails, revert), so a pass means
something. The full list is in [`docs/verification.md`](docs/verification.md).

## Building and running

Everything runs inside the Nix dev shell, which pins the toolchain and provides
QEMU, and GRUB. See [`docs/building-and-running.md`](docs/building-and-running.md)
for how the build and boot work.

```bash
nix develop                    # enter the shell (also enables the git hooks)
cd kernel && cargo run         # build and boot the kernel under qemu
scripts/check.sh               # list the gates
scripts/check.sh fast          # style, clippy -D warnings, host tests
scripts/check.sh qemu [test]   # boot every kernel test, or one by name
scripts/check.sh kani [name]   # bounded proofs, or one harness
scripts/check.sh ci            # everything ci runs: fast + miri + kani + qemu
```

The git hooks and CI call the same script: `pre-commit` runs the style check on
staged files plus clippy and the host tests, `commit-msg` enforces Conventional
Commits, and `pre-push` runs `scripts/check.sh ci`. QEMU runs with `-cpu max` (so SMEP/SMAP are live in
every test) and a 120-second timeout (`JOS_QEMU_TIMEOUT`), so a wedged guest
fails instead of hanging.

## Docs

| doc | covers |
|-----|--------|
| [`docs/architecture.md`](docs/architecture.md) | the principle, design, memory, IPC, paging, kernel entry paths |
| [`docs/roadmap.md`](docs/roadmap.md) | status by phase, milestones, adopted ideas, open decisions |
| [`docs/verification.md`](docs/verification.md) | what is proved and what is next |
| [`docs/capabilities.md`](docs/capabilities.md) | the capability core: rights, badges, revocation |
| [`docs/dst.md`](docs/dst.md) | deterministic simulation testing and tracing |
| [`docs/building-and-running.md`](docs/building-and-running.md) | toolchain, target, boot, the qemu runner |
| [`docs/testing.md`](docs/testing.md) | test layers and which gate runs each |
| [`TODO.md`](TODO.md) | the next concrete steps |

## References

- seL4 (capabilities, untyped memory, IPC): https://sel4.systems/
- OSDev wiki: https://wiki.osdev.org/Expanded_Main_Page
- blog_os, where jos started: https://os.phil-opp.com/
