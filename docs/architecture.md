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
|    Endpoint, Notification, Reply, Tcb, CNode, VSpace, PageTable, |
|    Frame, Untyped; plus the Console and Machine singletons       |
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

- **IPC buffer**: a message is four words. Word 0 travels in a register; words
  1 to 3 travel through each thread's IPC buffer, a frame registered in its TCB
  and mapped into its own address space. The kernel copies the sender's words
  and writes the receiver's through its own identity mapping of those frames,
  never through a user virtual address, so there is no user pointer to
  validate. A thread registers its buffer with `SetIpcBuffer`, which only
  accepts a Frame capability with `READ` and `WRITE`; frames are carved from
  untyped memory, so a buffer can never alias a kernel object, and revoking
  the capability unregisters the buffer. A thread without a buffer sends zeros
  and receives word 0 only.
- **Capability transfer**: a message can carry one capability. The sender names
  a slot in its buffer's `send_cap` field, which needs `GRANT` on the endpoint
  capability; the receiver names the slot it lands in with `recv_slot`, and the
  kernel reports in `caps_received` whether it did. The received capability is
  a copy derived from the sender's, so revoking the original reaches it. A
  receiver that accepts nothing still gets the message, only without the
  capability, and so does one whose sender revoked the capability while the
  message waited. Replies carry no capability yet.
- **Badges**: a server mints one badged copy of its endpoint capability per
  client (`Mint` syscall). The badge can be set once and is inherited by every
  further derivation, and the receiver gets it in `rdx` with each message, so a
  server can tell clients apart and a client cannot impersonate another.
- **Receive with timeout**: a receiver can arm a deadline; whichever of message
  or timer arrives first wins, so a blocked receive never waits forever.
- **Notifications** are asynchronous: a signal ORs a badge into a word and never
  blocks; a waiter collects the coalesced bits.
- **Reply objects**: a server receives with `RecvReply`, naming a reply object;
  a `Call` binds it to the caller, who blocks until the server answers through
  it exactly once with `Reply` (the seL4 MCS model; the state machine is in
  `jos-core/src/reply.rs`). A server loop uses `ReplyRecv`, which answers the
  current caller and waits for the next request in one syscall. A call that can
  never be answered, because a plain receive took it or its reply object was
  revoked, fails with `NoReply` instead of blocking forever.
- **Revocation**: a blocked IPC future holds a generation-checked `CapRef`.
  Revoking the capability wakes it, it finds the ref stale, and it fails with
  `InvalidCap` rather than hanging.

## Faults

A fault in ring 3 never stops the kernel. Every vector a thread can raise
enters one stub path; the faulting thread is parked as if it had made a `call`
on its fault endpoint (named by slot in its own capability space with
`tcb_set_fault_handler`, looked up at fault time) with the vector, address,
instruction, and error code as the message, and an answer through the reply
object resumes it at the faulting instruction with its registers untouched,
which is all a userspace pager needs. A thread nothing can answer is stopped
alone. Details: [`kernel/faults.md`](kernel/faults.md). How the blocking and
non-blocking IPC paths keep one order: [`kernel/ipc.md`](kernel/ipc.md).

## Address Spaces and Paging

```
PML4 (512 entries, 512 GiB each)
  index 0    identity map of the low 1 GiB (phys == virt, 2 MiB pages)
  index 1-255 user space: the root task's image at 0x80_0040_0000, its
             stack, IPC buffer and BootInfo at the top of that GiB
             (kernel tests use index 64, 0x2000_0000_0000)
  index 256+ kernel heap / higher-half mappings
```

Each `VSpace` clones the kernel PML4 entries so the kernel stays mapped across a
CR3 switch. Userspace builds the rest from capabilities, the seL4 way: a
`VSpace` is its own object type (a root that can never be confused with an
intermediate table), `MapPageTable` installs a PageTable capability at the first
missing level on the path to an address, and `MapFrame` maps a Frame at the
leaf, refusing writable-and-executable mappings and writable mappings through a
capability without `WRITE`. The kernel never allocates a table itself. `Unmap`
removes a mapping again (and everything beneath a table). A verified
registry (`jos-core/src/mapping.rs`) keeps each table and frame mapped at most
once, and revoking its capability unmaps it and everything beneath it, deepest
level first, so a table never comes back carrying stale entries. User code pages are W^X (writable only while being loaded, then
read-execute); stacks are non-executable. Kernel objects rely on the identity
map: an object's physical address is its virtual address.

**No-execute** (`EFER.NXE`) is enabled at init, so the `NO_EXECUTE` bit on W^X
user mappings is honored rather than being a reserved bit that faults.
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

## Starting Threads

A TCB object is 20 KiB, five pages: a header page (the saved register context,
the `CSpace` and `VSpace` roots, scheduling state), a guard page, and the
thread's own 12 KiB kernel stack, so carving one object gives a complete
thread and the kernel never allocates a stack. `retype_tcb` unmaps the guard
page from the kernel's identity map (splitting the 2 MiB page around it into
4 KiB pages, a split Kani proves changes no other translation), so a kernel
stack overflow faults there and double-faults onto its IST stack instead of
overwriting the header. The boot stack has the same guard, set up in `boot.s`. A thread that holds the capabilities starts another in
three steps, each checked on its own: `TcbConfigure` gives it a CNode and a
`VSpace`, `TcbSetIpcBuffer` registers its buffer frame, and `TcbStart` sets its
entry point and stack and hands it to the scheduler. A thread starts once.

## The Root Task

The kernel creates exactly one thread itself, the seL4 root-server model; every
other thread is started by userspace. Boot goes:

```
grub: multiboot2 kernel.elf, module2 root.elf "root <args>"
  kernel_main: init, check the loader magic, syscall MSRs
  memory plan:  available memory map areas
                - the low megabyte and the kernel image
                - the multiboot2 info structure
                - the span holding the boot modules
                clipped to the identity map (jos_core::boot_regions)
  boot allocator: page tables and the heap
  rootserver::start:
    everything the allocator did not hand out -> untyped regions
    carve from the largest: CNode, VSpace, TCB, IPC buffer, BootInfo,
                            stack, image frames, page tables
    load the ELF image (jos_core::elf), map W^X through mapping::map_*
    install the initial capabilities, fill BootInfo
    register the TCB, switch_to, iretq with every register from its context
```

The image is a static PIE built for `x86_64-unknown-none` (`user/`), loaded at
a fixed base with its `R_X86_64_RELATIVE` relocations applied in place through
the kernel's identity mapping of the fresh frames; segments are page-disjoint,
never writable and executable, and mapped with their own access. The root task
receives the capabilities `docs/syscalls.md` lists (its own TCB, CNode, VSpace,
IPC buffer and BootInfo frames, the console, the machine, and every untyped
region) and a read-only `BootInfo` page describing them. Without a `root`
module the kernel falls back to its in-kernel console.

`user/libjos` is the runtime every userspace program links: the `syscall`
stubs (declaring every register the kernel clobbers), one typed wrapper per
call over `jos_core::abi`, console output through the Console capability, the
entry point, and KTAP helpers. The root task's `hello` and `test` modes run
first-light checks from ring 3 and halt the machine with the result through
its Machine capability, which is what `scripts/check.sh boot` runs.

## Per-CPU State and Context Switch

`CpuLocal` is reached through the GS base after `swapgs`. It holds the current
thread's kernel stack top, a scratch slot for the user rsp, the current CSpace
and TCB, and the user registers captured on syscall entry (for resuming a
thread that blocked). `cpu_local::switch_to(tcb)` updates it together with the
TSS `rsp0`, so both the next syscall and the next ring-3 interrupt land on the
new thread's kernel stack. It also loads the thread's VSpace into `CR3` when it
differs from the active one, so threads in different address spaces are
isolated; every VSpace carries the kernel's own mappings, so the kernel keeps
running across the switch.

## Generation-Counted Revocation

A `CapRef` is `(slot, generation)`. Removing a capability bumps the slot's
generation, so every outstanding ref to it goes stale in O(1); `revoke` removes
a capability and every capability derived from it. The derivation tree spans
capability spaces: a capability copied into another CNode with `CNodeCopy`
links back to its source, so revoking the source removes the copy too. Rights only ever shrink
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
