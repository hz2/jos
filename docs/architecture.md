# Architecture

jos is a capability-based microkernel in Rust. This document is the design: the
principle everything follows from, what jos deliberately is not, and how the
pieces (memory, IPC, address spaces, kernel entry) fit together. The plan lives
in [`roadmap.md`](roadmap.md); proof targets in [`verification.md`](verification.md);
the capability core in depth in [`capabilities.md`](capabilities.md).

## The Principle

> All authority and communication flow through explicit, kernel-mediated
> capability invocations. There is no ambient authority.

Every object a thread can touch must be named by a capability the kernel
explicitly handed it. There is no way to access memory, communicate, or create
objects without one. Userspace drivers reach hardware only through capabilities
the kernel grants, and IPC happens only through capability-mediated endpoints.

A capability is like a Unix file descriptor, except that it cannot be guessed or
forged, every operation checks the rights it carries, and the kernel can revoke
a whole derivation tree at once. Capabilities live in a **CSpace**, a table of
slots; syscalls name them by slot number.

### Design commitments

- **The kernel never allocates** (seL4's untyped-memory discipline): kernel
  objects are carved from untyped regions that userspace retypes.
- **Verifiable by construction**: the pure logic lives in `jos-core`, which is
  hardware-free so Miri, Kani, and Verus can all run against it.
- **One architecture first**: x86_64 behind a clean HAL boundary. aarch64 and
  riscv stubs exist but wait until the core is solid.
- **Future-facing**: post-quantum crypto capabilities, agent-native capability
  sandboxing, and orthogonal persistence are aspirational, but they shape
  today's decisions.

### What jos is not

- Not a blog_os tracker. Those posts were the scaffold for phase 0, not the
  destination; prefer the capability spine over the next tutorial chapter.
- Not a Unix clone. POSIX compatibility is not a goal.
- Not vaporware. Every phase ships real, tested code.

### Inspiration

- **seL4**: untyped memory, capability derivation, IPC buffer and reply
  objects, a formal specification of the object lifecycle.
- **Fuchsia/Zircon**: handle tables, endpoint IPC, capability rights.
- **Redox**: a Rust-native microkernel with isolated drivers.
- **Hubris (Oxide)**: static task tables and a typed IPC interface language.
- **FreeBSD**: Capsicum's per-descriptor rights; WITNESS lock-order checking.
- **Atmosphere** (Verus-verified kernel) and the Miri/Kani/Verus toolchain.

## Layers

```
+-----------------------------------------------------------------+
|  ring 3 (userspace)                                              |
|    user program -- SYSCALL ------------------------------+       |
+----------------------------------------------------------|------+
|  ring 0: syscall_entry (asm)                             v       |
|    swapgs; stash user rsp; load this thread's kernel rsp         |
|    call dispatch_syscall(nr, a0, a1, a2) -> (rax, rdx)           |
|      resolve slot -> generation-checked CapRef; check Rights     |
|      ipc send/recv, mint, retype, invoke, blocking IPC           |
|    swapgs; sysretq  (or park and switch if the call blocked)     |
+-----------------------------------------------------------------+
|  kernel objects (placed in untyped memory, no heap)              |
|    Endpoint, Notification, Tcb, PageTable, CNode, Untyped        |
+-----------------------------------------------------------------+
|  jos-core (pure, hardware-free, tested on the host)              |
|    cap_table, cap_space, cap_rights   capabilities + revocation  |
|    endpoint, notification, reply      IPC state machines         |
|    untyped, placement, frame_allocator, page_table               |
|    sched_policy, run_queue, clock, timer                         |
+-----------------------------------------------------------------+
```

The split between `jos-core` and `kernel` is load-bearing: Miri cannot cross
the first `asm!` instruction and Verus pins its own toolchain, so every state
machine with a subtle invariant is written in `jos-core` first, proved there,
and wrapped by the kernel.

## Memory: the Kernel Never Allocates

1. At boot the kernel hands out capabilities to large regions of raw physical
   memory called **Untyped**.
2. `Retype(untyped_slot, type, dest_slot)` carves a typed object (Endpoint,
   Tcb, PageTable, CNode, ...) out of an Untyped region.
3. The object is placed at the region's watermark, which only moves forward,
   and a full-rights capability is installed in `dest_slot`.
4. Objects are not freed individually; reclaiming means revoking the whole
   Untyped region (future work).

Userspace owns the object lifecycle; the kernel only enforces policy. The
forward-only watermark is what makes spatial non-overlap provable (MEM-1).

```
Untyped region
  +------+------+------+------+------------------+
  |  EP  |  EP  | Tcb  |CNode |  ... free ...    |
  +------+------+------+------+------------------+
  ^                            ^
  base                         watermark (only moves forward)
```

## IPC

Endpoint IPC is a **synchronous rendezvous** in the L4 / seL4 tradition. The
endpoint holds at most one undelivered message; a sender that finds it full, or
a receiver that finds it empty, parks on the endpoint, and the counterpart wakes
it. The take-or-park step happens under one lock, so wakeups are never lost.

- **Badges**: a server mints one badged copy of its endpoint capability per
  client (`Mint` syscall). The badge can be set once and is inherited by every
  further derivation, and the receiver gets it in `rdx` with each message, so a
  server can tell clients apart and a client cannot impersonate another.
- **Receive with timeout**: a receiver can arm a deadline; whichever of message
  or timer arrives first wins, so a blocked receive never waits forever.
- **Notifications** are asynchronous: a signal ORs a badge into a word and never
  blocks; a waiter collects the coalesced bits.
- **Reply objects** (in progress): `Call` binds a one-shot reply capability the
  server answers through exactly once (the seL4 MCS model; the state machine is
  in `jos-core/src/reply.rs`).
- **Revocation**: a blocked IPC future holds a generation-checked `CapRef`.
  Revoking the capability wakes it, it finds the ref stale, and it fails with
  `InvalidCap` rather than hanging.

## Address Spaces and Paging

```
PML4 (512 entries, 512 GiB each)
  index 0    identity map of the low 1 GiB (phys == virt, 2 MiB pages)
  index 64   user window at 0x2000_0000_0000 (code + stack)
  index 256+ kernel heap / higher-half mappings
```

Each `VSpace` clones the kernel PML4 entries so the kernel stays mapped across a
CR3 switch. User code pages are W^X (writable only while being loaded, then
read-execute); stacks are non-executable. Kernel objects rely on the identity
map: an object's physical address is its virtual address.

**SMEP and SMAP** are enabled when the CPU has them (QEMU runs `-cpu max`).
Ring 0 cannot execute user pages, and touches user pages only inside
`arch::x86_64::with_user_access`, which opens the window with `stac` and closes
it with `clac`. This is the x86 counterpart of RISC-V's `sstatus.SUM`.

## Kernel Entry Paths

**Syscall** (the hardware does not switch stacks):

```
SYSCALL: rcx = user rip, r11 = user rflags, SFMASK clears IF, DF, TF, AC
  swapgs                      reach the per-CPU CpuLocal block
  stash user rsp, load gs:[kernel_rsp]
  call dispatch_syscall       result in rax, secondary result in rdx
  swapgs; sysretq             or park the thread and switch if it blocked
```

**Interrupt** (the CPU switches to `rsp0` from the TSS when coming from ring 3):

```
IRQ: CPU pushes ss, rsp, rflags, cs, rip on the rsp0 stack
  swapgs only if the saved CS is ring 3
  timer: naked stub saves all GPRs as an IrqFrame, clears DF, calls the
         scheduler, which may rewrite the frame to resume another thread
  swapgs (again only for ring 3); iretq
```

`swapgs` must pair exactly once on entry and once on exit; an unpaired swap
leaks the kernel GS base to user mode.

## Per-CPU State and Context Switch

`CpuLocal` is reached through the GS base after `swapgs`. It holds the current
thread's kernel stack top, a scratch slot for the user rsp, the current CSpace
and TCB, and the user registers captured on syscall entry (for resuming a
thread that blocked). `cpu_local::switch_to(tcb)` updates it together with the
TSS `rsp0`, so both the next syscall and the next ring-3 interrupt land on the
new thread's kernel stack.

## Generation-Counted Revocation

A `CapRef` is `(slot, generation)`. Removing a capability bumps the slot's
generation, so every outstanding ref to it goes stale in O(1); `revoke` removes
a capability and every capability derived from it. Rights only ever shrink
along a derivation chain, which is proved globally (CAP-1).

## x86_64 Reference

- **MSRs**: LSTAR (syscall entry), STAR (segment selectors), SFMASK (RFLAGS bits
  cleared on syscall), KernelGsBase (per-CPU pointer), EFER (SCE, NXE).
- **TSS**: holds `rsp0` for ring-3 interrupts and the IST stacks (double fault
  today; NMI and #MC next).
- **APIC**: per-core local APIC (timer, IPIs) plus the IOAPIC for device IRQs.
  jos still uses the 8259 PIC and PIT; moving to the APIC comes with SMP.
- **RFLAGS**: IF gates maskable interrupts (ring 3 runs with IF=1 so the timer
  can preempt); DF must be clear at every call into Rust; AC opens the SMAP
  window.
