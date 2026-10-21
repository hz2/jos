# TODO

The concrete next steps, highest leverage first. The milestone context lives in
`docs/roadmap.md`; verification targets in `docs/verification.md`.
Check items off in the same commit that finishes them.

## Now: userspace that is not hand-assembled (M2)

- [x] `user/` workspace built for `x86_64-unknown-none`: `libjos` (syscall
      stubs and typed wrappers over the shared `jos_core::abi`, console output,
      the entry point, KTAP helpers) and the root task
- [x] the syscall numbers, error codes, type ids and argument packing live in
      `jos_core::abi`, shared by the kernel and userspace
- [x] ELF64 load planner in jos-core (`elf.rs`): static PIE or ET_EXEC,
      page-disjoint W^X segments in a window, RELATIVE relocations only; host
      tests with seeded mutation, Kani harnesses (run them under the memory cap)
- [x] multiboot2 tags (`multiboot2.rs`) and free-memory arithmetic
      (`boot_regions.rs`) in jos-core; the memory plan reserves the boot
      modules and the info structure, which the boot allocator used to hand out
- [x] the kernel loads the root task from the `root` boot module: objects from
      untyped, W^X mappings through the registry, initial capabilities at the
      `abi::root_slot` slots, a `BootInfo` page, registered with the scheduler
- [x] Console and Machine capabilities: `console_write` (22) through the IPC
      buffer's data area, `machine_halt` (23)
- [x] `check.sh boot`: the real kernel boots the real root task in test mode
      (`check.sh matrix`, 36 machines under TCG and KVM, runs in `ci`);
      `cargo run` boots into the root task
- [x] ELF-1 and BOOT-2 proved (`docs/verification.md`), each harness small
      enough to run in a minute and 2 GB
- [x] survivable user faults: one entry stub path for every vector, seL4-style
      fault endpoints (`tcb_set_fault_handler`, 25) resolved at fault time, a
      reply resumes the faulting instruction with registers intact (userspace
      demand paging works), and a thread with no handler is stopped alone
- [x] thread ids reused behind a generation (a stale reply reaches nothing),
      `MAX_THREADS` 64, `thread_exit` (24), and a blocked thread switches
      straight to the next ready one instead of waiting for a tick
- [x] IPC: non-blocking send and receive hand off to threads parked by the
      blocking calls, receives take the slot before parked senders, and
      parked threads are served oldest first (`docs/kernel/ipc.md`)
- [x] libjos: slot allocation, retype and map helpers, thread spawning with
      thread blocks (each thread finds its IPC buffer from its stack pointer)
- [x] capacity: a CNode nothing can reach is released (reachability, so cycles
      go too) and its registry entry reused under a new id (128 entries); what
      was copied out of it is relinked to its nearest remaining ancestor; a
      revoke resolves links in constant time and needs no stack scratch; a
      bigger mapping registry (`unmap_object` keeps no stack scratch array)
- [x] `recv_timeout` (26): a ring-3 check that waits on a message that never
      comes fails fast with `TimedOut` instead of hanging the run
- [x] the blocking tables are a verified `jos_core::wait_table` (BLOCK-1): a
      `call` now reaches the longest-waiting receiver too, and revoking the
      last capability to an endpoint ends every wait on it with `BadCap`
- [x] kernel stack overflows fault on the guard page (inline stack probes);
      the deepest syscall path uses 4.9 KiB of the 12 KiB stack
- [ ] `mint` into a slot the caller names (today the kernel picks the lowest
      free one, which libjos has to claim after the fact)
- [x] a ring-3 test runner in the root task: each check in a fresh thread with
      the runner as its fault handler and a 30 s deadline, so a check that
      faults, panics, or hangs costs only its own line; `root test [filter]`,
      `root list`
- [ ] nested KTAP, once the root task's suite runs inside a larger plan (a
      process per suite, or the spec fuzzer)
- [x] userspace process spawning: boot modules mapped read-only into the root
      task, `libjos::process` builds a process (own VSpace, CNode, thread)
      with the same `jos_core::elf` planner; `user/hello` and four checks; the
      shell's `run`
- [ ] capacity for many processes: the root CNode has 64 slots and a process
      costs the root about 21, so a bigger root CNode, or a process that keeps
      most of its own capabilities (a `delete` or `move` to hand them over)
- [x] `jig`, the host harness (`tools/jig`): every kernel test and the root
      task report KTAP; parallel QEMU runs, JUnit, log tails and reproduce
      commands, `--repeat`, and a 36-machine boot matrix (cpu, memory, smp,
      machine) in `ci`
- [x] `jig expect`: scripted serial sessions that type at the root task's
      shell and wait for its output, in `check.sh shell` and ci (`cargo run`
      at a terminal is the interactive boot)
- [x] a syscall robustness fuzzer (`user/fuzz`, a sandboxed process): swarm
      mixes, schema-guided and hostile arguments, every answer checked against
      the documented result set; `check.sh fuzz` in ci. It found the bit-63
      ambiguity, now refused (`BadWord`, `BadBadge`)
- [x] an executable spec (`jos_core::spec`) of one thread's non-blocking calls
      (slots, rights, badges, mint and revoke, retype, endpoints,
      notifications), run against the live kernel by the fuzzer's
      differential storm; it found a `BadAlign` that should be `BadType`
- [ ] grow the spec: other capability spaces (`cnode_copy`), mapping, threads,
      and blocking IPC, so the differential storm covers them too
- [x] console input: COM1 interrupts (IRQ4) fill a kernel buffer that
      `console_read` (27) takes from, waiting with an optional deadline; a
      verified line editor (LINE-1) in jos-core
- [x] the root task's `shell`: help, info, mem, list, test [filter], bench,
      echo, halt; `cargo run` at a terminal boots into it
- [x] notification syscalls: `signal` (28) and `wait` (29, which polls with a
      deadline of 0), over a fourth wait table; revoking a notification ends
      its waits
- [ ] console input, and later device interrupts, delivered as notification
      signals (the `IrqHandler` object of M4)
- [x] the ambient `exit` probe (1) answers `ENOSYS` once a root task runs, so
      only the machine capability stops the machine; the fuzzer calls it

## Done: real IPC (M1), and what is left of it

- [x] `Reply` kernel object wrapping `jos_core::reply::Reply` (`ObjectType::Reply`)
- [x] `Call` (9), `RecvReply` (10), `Reply` (11) syscalls; revoking a bound reply
      fails the caller with `NoReply`
- [x] integration tests: a badged call answered once, in both handoff orders
- [x] test the `NoReply` path where a plain receive takes a call (both orders)
- [x] test the `NoReply` path where a bound reply object is revoked
- [x] `ReplyRecv` (13): answer, then receive, in one syscall
- [x] a server answering two badged clients in a `ReplyRecv` loop
- [x] per-thread IPC buffer: a registered frame (`Tcb::ipc_buffer`) carries
      message words 1 to 3 on every IPC path; the kernel uses its own mapping
      of the frame, never a user pointer
- [x] `Frame` objects (retypeable from untyped) and `SetIpcBuffer` (12), which
      only accepts a Frame cap with READ and WRITE; revoking the cap
      unregisters the buffer
- [x] `VSpace` objects and `MapPageTable` (14) / `MapFrame` (15): userspace builds
      address spaces from table and frame capabilities; a verified registry
      keeps each object mapped once, and revoking a table or frame unmaps it
      and everything beneath it
- [x] `Unmap` (16): unmap a frame or table (and everything beneath a table)
- [x] per-thread address spaces: `switch_to` loads each thread's VSpace into
      `CR3`, so threads in different VSpaces are isolated
- [x] start threads from userspace: a TCB object holds its own kernel stack,
      and `TcbConfigure` (17), `TcbSetIpcBuffer` (18), `TcbStart` (19) set up
      and launch it
- [x] `CNodeCopy` (20): copy an attenuated capability into another CNode; the
      copy stays in a global derivation tree, so revoking the source reaches it
- [x] revoking a started thread, or the CNode or VSpace it runs in, stops it for
      good once that object has no capability left (revoking a copy does not):
      it leaves the run queue and any IPC wait, and a late answer finds nothing
- [x] reuse retired thread ids: reply bindings hold a generation-checked token
- [x] the root task is registered with the scheduler like any thread, so the
      timer switches to the threads it starts
- [x] CNodes are built in place (`CapSpace::init_in_place`), so no page-sized
      object is built by value on a syscall stack any more
- [x] capability transfer with an IPC message: the sender names a slot in its
      IPC buffer (needs `GRANT` on the endpoint), the receiver names where it
      lands, and the copy stays in the derivation tree
- [ ] capability transfer on `Reply` (replies carry words only today)
- [x] `Revoke` (21): revoke a capability and everything derived from it,
      in every capability space, from userspace
- [x] `revoke_across` resolves a link in constant time and scans the spaces once
      per depth of the subtree, no longer once per removed capability
- [ ] JPC-1 Verus proof (rendezvous deadlock-freedom)

## Hardening (small, do alongside)

- [ ] FPU/SSE save on context switch (latent bug once user code touches xmm)
- [x] guard page under the boot stack, so an overflow double-faults instead of
      corrupting .bss
- [x] guard pages under TCB kernel stacks: the page below each stack is unmapped,
      so an overflow faults instead of overwriting the TCB header
- [ ] guard pages for the test harness' static kernel stacks (`KSTACKS` in
      `kernel/tests/common/threads.rs`), which are not TCB objects
- [x] NMI / #MC on IST stacks; ring 3 cannot raise an NMI
- [ ] give the blocking-IPC tables (`BLOCKED_SENDS` / `BLOCKED_RECVS`) a pure
      model in jos-core so the direct-handoff path is covered by Kani like the
      async path is
- [ ] lock-order checker (WITNESS-style), see ROADMAP

## Verification backlog

- [ ] ARITH-2: frame allocator abstract spec (Verus + Kani)
- [ ] JPC-2: prove IPC buffer registration only accepts Frame capabilities
      (implemented and tested; not yet proved)
- [ ] ARITH-3: trace encoding round-trip harness
- [x] INV-1: ring buffer and run queue invariants declared to Kani and proved
      preserved from any valid state
- [ ] declare `kani::Invariant` for `CapTable` and `CapSpace` too, so autoharness
      covers the capability API (it reports spurious failures without them)

## Testing layers

- [x] activated swarm operation mixes in every DST harness (odd seeds)
- [x] run the QEMU suite under KVM as well as TCG (`check.sh qemu-kvm`, in ci)
- [ ] a few `-cpu` models in the matrix (`JOS_QEMU_CPU`), e.g. without SMAP
- [x] QEMU record/replay (`JOS_QEMU_RR`) so a failing QEMU test replays
      instruction for instruction
- [ ] model-based kernel testing: a ring-3 syscall interpreter driven over
      serial by a host-side Hypothesis state machine, checked against a
      reference model (easier once the M2 user crate exists)

## Docs and process

- [x] git hooks (`.githooks/`): style, clippy, tests on commit; full gate on push
- [x] SMEP/SMAP on, QEMU runs `-cpu max` with a timeout
- [x] `EFER.NXE` enabled: W^X `NO_EXECUTE` user pages were malformed before
- [x] `scripts/check.sh` as the single entry point for every gate (hooks and CI call it)
- [x] docs consolidated under `docs/`
- [ ] knowledge notes on seL4, Hubris, Capsicum, APIC/ACPI in `~/srcs/knowledge`
