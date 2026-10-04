# Roadmap

The long-horizon plan, ordered by leverage. [`TODO.md`](../TODO.md) at the repo
root is the short, concrete checklist for the next few sessions; this file is
the why and the order. Read [`architecture.md`](architecture.md) first for the
principles every item serves, and [`verification.md`](verification.md) for the
proof targets that travel with each milestone.

## Where we are (2026-10)

jos boots on x86_64 under QEMU, enters ring 3, and runs capability-checked
syscalls with a verified pure-logic core behind them. It cannot yet load a real
program from disk or run a userspace server talking to clients; that is the
gap this roadmap closes first.

| Phase | Scope | State |
|-------|-------|-------|
| 0 | boot (multiboot2 + own long-mode trampoline), GDT/IDT/TSS, paging, heap, serial, VGA | done |
| 1 | async executor, keyboard, PIC timer, IRQ handling | done |
| 2 | untyped memory, retype, CSpace/CNode, rights, revoke, endpoints, notifications | done |
| 3 | ring 3, SYSCALL/SYSRET, per-thread kernel stacks + CSpaces, preemptive round robin, W^X | done |
| 4 | real IPC, userspace crate + ELF + root task, drivers | in progress (~25%) |
| 5 | formal verification (Kani across jos-core, Verus spec of the cap state machine) | in progress |
| 6 | SMP, scheduling contexts, WASM sandbox, agent namespaces, PQ crypto caps | future |

Done inside phase 4 so far: blocking send/recv syscalls, badged endpoint
capabilities (`Mint` syscall, badge delivered in `rdx`), a verified one-shot
`Reply` state machine in jos-core, SMEP/SMAP with an explicit user-access
window, DF cleared in the naked timer stub.

## Milestones (in order)

Each milestone ships tests (and, where the logic lives in jos-core, a Kani
harness) before the next one starts.

### M1. Real IPC (in progress)

The base everything else stands on: servers, drivers, and the root task all
speak IPC.

- [x] badges on capabilities; `Mint` syscall; badge delivered to the receiver
- [x] `Reply` object state machine in jos-core (Kani: one reply per bind)
- [ ] `Reply` kernel object + `Call` / `ReplyRecv` syscalls (seL4 MCS model)
- [ ] per-TCB IPC buffer page (message words 1..N, read inside the SMAP window)
- [ ] capability transfer over IPC (needs the cross-CSpace derivation decision,
      see "open decisions")
- [ ] JPC-1: Verus proof of rendezvous deadlock-freedom

### M2. Userspace crate, ELF loader, root task

- [ ] `user/` workspace member: a `no_std` syscall library plus a `root` binary
- [ ] ELF64 loader (header parsing in jos-core so it can be fuzzed and Kani'd;
      PT_LOAD segments mapped with W^X)
- [ ] boot hands the root task every initial untyped cap plus its own
      TCB/CSpace/VSpace (the seL4 root-server model; matches VISION's single
      Kernel capability)
- [ ] load the root image from a multiboot2 module

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

1. **Cross-CSpace derivation**: `CapSpace` tracks parent links within one
   space, so a cap transferred over IPC cannot be revoked from the sender's
   side today. Options: a global derivation tree (seL4 CDT, most faithful), or
   a back-link (space id + ref) recorded on each transferred copy. Blocks cap
   transfer in M1.
2. **Bootloader**: keep the hand-rolled multiboot2 trampoline, or move to
   Limine for UEFI + SMP handoff before M5.

## How to build and test

See [`building-and-running.md`](building-and-running.md) and
[`testing.md`](testing.md). The git hooks in
`.githooks/` (enabled by the nix shell) run the fast gates on commit and the
full suite on push.
