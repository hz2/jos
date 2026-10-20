# Roadmap

The long-horizon plan, ordered by leverage. [`TODO.md`](../TODO.md) at the repo
root is the short, concrete checklist for the next few sessions; this file is
the why and the order. Read [`architecture.md`](architecture.md) first for the
principles every item serves, and [`verification.md`](verification.md) for the
proof targets that travel with each milestone.

## Where we are (2026-10)

jos boots on x86_64 under QEMU into a Rust root task loaded from an ELF boot
module, which runs in ring 3 with every initial capability and checks the
capability model end to end (`scripts/check.sh boot`), threads and faults
included: a faulting thread is stopped alone or answered by a userspace
handler, which can page memory in on demand. What is missing for a userspace
that hosts servers and tests is process spawning from userspace, a ring-3 test
runner with per-test isolation, and the host-side harness; that is the gap
this roadmap closes next.

| Phase | Scope | State |
|-------|-------|-------|
| 0 | boot (multiboot2 + own long-mode trampoline), GDT/IDT/TSS, paging, heap, serial, VGA | done |
| 1 | async executor, keyboard, PIC timer, IRQ handling | done |
| 2 | untyped memory, retype, CSpace/CNode, rights, revoke, endpoints, notifications | done |
| 3 | ring 3, SYSCALL/SYSRET, per-thread kernel stacks + CSpaces, preemptive round robin, W^X | done |
| 4 | real IPC, userspace crate + ELF + root task, drivers | in progress (~40%) |
| 5 | formal verification (Kani across jos-core, Verus spec of the cap state machine) | in progress |
| 6 | SMP, scheduling contexts, WASM sandbox, agent namespaces, PQ crypto caps | future |

Done inside phase 4 so far: blocking send/recv syscalls, badged endpoint
capabilities (`Mint` syscall, badge delivered in `rdx`), request-response IPC
(`Call` / `RecvReply` / `Reply` over a one-shot reply object whose state machine
is Kani-proved in jos-core), SMEP/SMAP with an explicit user-access window, no-execute pages
(`EFER.NXE`, which W^X mappings needed but never had), DF cleared in the naked
timer stub.

## Milestones (in order)

Each milestone ships tests (and, where the logic lives in jos-core, a Kani
harness) before the next one starts.

### M1. Real IPC (done, save JPC-1)

The base everything else stands on: servers, drivers, and the root task all
speak IPC.

- [x] badges on capabilities; `Mint` syscall; badge delivered to the receiver
- [x] `Reply` object state machine in jos-core (Kani: one reply per bind)
- [x] `Reply` kernel object + `Call` / `RecvReply` / `Reply` syscalls (seL4 MCS model)
- [x] `ReplyRecv` combined syscall (the server loop in one call)
- [x] per-thread IPC buffer frame carrying message words 1 to 3 (seL4 model:
      the kernel uses its own mapping of the registered frame)
- [x] register the IPC buffer from userspace through a Frame capability
- [x] map Frames into a VSpace from userspace (`MapPageTable` / `MapFrame`, seL4
      style: userspace supplies every page table; the kernel never allocates)
- [x] per-thread VSpaces switched on context switch
- [x] configure and start TCBs from userspace (TCB objects carry their own
      kernel stack)
- [x] copy capabilities into another thread's CNode (`CNodeCopy`)
- [x] revoke from userspace (`Revoke`), across every capability space
- [x] revoking a thread, or the CNode or VSpace it runs in, stops it (seL4
      final-capability semantics: only when no capability to the object is left)
- [x] cross-space derivation tree: parent links name a space and a slot, so
      revoking a capability reaches its copies in other CNodes (decided: a
      global tree, the seL4 model)
- [x] capability transfer over IPC: one capability per message, through the
      IPC buffer, gated by `GRANT`, linked into the derivation tree
- [ ] JPC-1: Verus proof of rendezvous deadlock-freedom

### M2. Userspace crate, ELF loader, root task (in progress)

- [x] `user/` workspace: `libjos` (a `no_std` syscall library over the shared
      `jos_core::abi`) plus the `root` binary
- [x] ELF64 load planning in jos-core (static PIE, W^X, RELATIVE relocations),
      host-fuzzed and Kani-harnessed; the kernel maps PT_LOAD segments W^X
- [x] boot hands the root task every initial untyped cap plus its own
      TCB/CSpace/VSpace, IPC buffer and BootInfo, and the Console and Machine
      capabilities (the seL4 root-server model)
- [x] load the root image from a multiboot2 module; the memory plan keeps the
      modules and the info structure out of the free memory
- [x] survivable user faults (fault endpoints, demand paging from userspace)
      and reusable thread ids
- [x] timed receives, and blocked waits that end when their endpoint goes
      away, over a verified table of parked threads (BLOCK-1)
- [x] a ring-3 test suite in the root task, each check isolated in its own
      thread with a deadline
- [x] console input (IRQ4, `console_read`) and an interactive shell in the
      root task, scripted end to end by `jig expect`
- [x] process spawning from userspace: the root task starts boot modules as
      isolated processes
- [x] `jig`, the host-side harness: parallel QEMU boots read as KTAP, JUnit,
      reproduce commands, a machine matrix
- [ ] differential testing against an executable spec

### M3. Hardware foundation

- [ ] save/restore FPU/SSE state (eager FXSAVE first, XSAVE later)
- [ ] ACPI/MADT parsing (`acpi` crate); LAPIC timer with TSC-deadline; IOAPIC
      routing; retire the 8259 PIC and PIT
- [ ] NMI and #MC on their own IST stacks (closes the user-stack window between
      `pop rsp` and `sysretq` in `syscall_entry`)
- [ ] `clac` on every interrupt entry once SMAP windows can span preemption
- [ ] keep `KernelClock` as the seam so the clock proofs hold

### M4. Capability-mediated drivers

- [ ] `IrqHandler` object: an IRQ arrives as a `Notification` signal
- [ ] `IoPortRange` and `DeviceMemory` (MMIO frames as an untyped variant)
- [ ] serial, then keyboard, moved to ring-3 drivers
- [ ] PCI enumeration; `virtio-drivers` for virtio-blk and virtio-gpu
- [ ] IOMMU (VT-d / AMD-Vi) so DMA-capable drivers are actually contained

### M5. SMP and scheduling contexts

- [ ] AP bootstrap, per-CPU `cpu_local` by APIC id, IPIs for remote wakeup
- [ ] `SchedContext` as a capability (budget + period, seL4 MCS)
- [ ] EDF / EEVDF policies behind the existing `SchedulingPolicy` trait
- [ ] lock-order checker (below) before any lock is shared across CPUs

### M6. The distinctive layer

- [ ] WASM sandbox server (`wasmi`): one CSpace per module, imports = caps
- [ ] agent capability namespaces with quota caps (CPU via SchedContext,
      memory via untyped size) and an audit trail through `trace.rs`
- [ ] shared-memory SPSC channels (io_uring / iceoryx2 style) as a Frame cap
      in two VSpaces plus a notification
- [ ] fixed-size IPC encoding (hubpack style) and an IDL for server protocols
- [ ] post-quantum crypto capability (key material never leaves its page)

## Ideas adopted from elsewhere

- **FreeBSD WITNESS** (lock-order verification): a pure lock-class graph in
  jos-core plus a debug-build wrapper around `spin::Mutex` in the kernel that
  records acquisition order per CPU and panics on a cycle. The kernel already
  documents its lock discipline (endpoint before waker, clock locks under
  `without_interrupts`); this makes it checked, and the graph logic can be
  Kani-proved. Do before SMP.
- **FreeBSD Capsicum**: rights per descriptor and a "capability mode" with no
  global namespaces. jos is already capability-native; the lesson to take is
  finer-grained, per-method rights (Capsicum has dozens; jos has four bits).
  Revisit `Rights` when servers grow real method sets.
- **FreeBSD UMA / vmem**: per-type slab caches and a resource-arena allocator.
  Relevant for the root task's userspace object allocator, not the kernel
  (the kernel never allocates).
- **RISC-V privileged spec**: `sscratch` swap on trap entry is a cleaner
  version of `swapgs`; `sstatus.SUM` is SMAP. Keep the HAL boundary shaped so
  `arch/riscv` can express both directly when multi-arch resumes.
- **Hubris (Oxide)**: static task tables and a typed IPC IDL; a good model
  for the root task's server set.

## Open decisions

1. **Bootloader**: keep the hand-rolled multiboot2 trampoline, or move to
   Limine for UEFI + SMP handoff before M5.

## How to build and test

See [`building-and-running.md`](building-and-running.md) and
[`testing.md`](testing.md). The git hooks in
`.githooks/` (enabled by the nix shell) run the fast gates on commit and the
full suite on push.
