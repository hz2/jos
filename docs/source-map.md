# Source Map

Where each part of jos lives. Most features come in pairs: a pure model in
`jos-core` (unit-tested, Miri-checked, Kani-proved, simulated) and a thin piece
of kernel glue that applies it to real memory and hardware. When changing one
half, look at the other.

## Capabilities

| concept | model (`jos-core/src`) | kernel glue (`kernel/src`) |
|---|---|---|
| rights, attenuation | `cap_rights.rs` | |
| generation-counted slots | `cap_table.rs` | |
| capability spaces, derivation tree, copy, revoke | `cap_space.rs` | `cap.rs` (registry, `revoke_and_wake`) |
| untyped memory and retype sizes | `untyped.rs`, `placement.rs` | `cap.rs` (`UntypedRegion`) |
| kernel objects (endpoint, notification, reply, TCB, CNode, frame) | `endpoint.rs`, `notification.rs`, `reply.rs` | `cap.rs` |
| capability syscalls | | `syscall/objects.rs` |

## IPC

| concept | model | kernel glue |
|---|---|---|
| endpoint rendezvous | `endpoint.rs` | `cap.rs` (async path), `syscall/ipc.rs` (blocking path) |
| call and reply | `reply.rs` | `syscall/ipc.rs` |
| IPC buffer, capability transfer | `ipc_buffer.rs` | `syscall/ipc.rs`, `cap.rs` (`transfer_cap`) |
| notifications | `notification.rs` | `cap.rs` |

## Memory and address spaces

| concept | model | kernel glue |
|---|---|---|
| page-table indices | `page_table.rs` | |
| entry encoding, huge-page split | `pte.rs` | `guard_page.rs` |
| mapping registry | `mapping.rs` | `mapping.rs`, `syscall/vm.rs` |
| address spaces | | `vspace.rs` |
| physical frames | `frame_allocator.rs`, `bitmap.rs` | `memory.rs` |
| kernel heap | | `allocator.rs` |
| guard pages (boot stack, TCB stacks) | `pte.rs` (`split_huge_entry`) | `arch/x86_64/boot.s`, `guard_page.rs` |

## Threads, scheduling, time

| concept | model | kernel glue |
|---|---|---|
| run queue | `run_queue.rs`, `ring_buffer.rs` | |
| scheduling policy | `sched_policy.rs` | `sched.rs` (timer preemption, thread table) |
| TCB objects and thread syscalls | `untyped.rs` (layout) | `cap.rs` (`Tcb`), `syscall/thread.rs` |
| per-CPU state, context switch | | `cpu_local.rs` |
| clock and deadlines | `clock.rs`, `timer.rs` | `clock.rs` |
| in-kernel async tasks | | `executor.rs`, `keyboard.rs` |

## Boot and the CPU boundary

| piece | where |
|---|---|
| multiboot2 header, long mode, identity map | `kernel/src/arch/x86_64/boot.s` |
| boot information parsing | `kernel/src/arch/x86_64/multiboot2.rs` |
| SMEP, SMAP, NX | `kernel/src/arch/x86_64/mod.rs` |
| GDT, TSS, IST stacks | `kernel/src/gdt.rs` |
| IDT, exceptions, PIC | `kernel/src/interrupts.rs` |
| `syscall` entry stub, ABI, dispatcher | `kernel/src/syscall/mod.rs` |
| first entry to ring 3 | `kernel/src/usermode.rs` |
| serial and VGA output | `kernel/src/serial.rs`, `kernel/src/vga_buffer.rs` |

## Verification and testing

| piece | where |
|---|---|
| Kani proofs | `#[cfg(kani)] mod kani_proofs` at the bottom of each `jos-core` module |
| Verus proofs | `jos-core/src/proof.rs` |
| deterministic simulation | `jos-core/tests/dst_*.rs`, with `rng.rs`, `fault.rs`, `trace.rs` |
| QEMU integration tests | `kernel/tests/*.rs`; multi-thread ones share `kernel/tests/common/threads.rs` |
| in-kernel trace ring | `kernel/src/trace.rs` |
| gates and runner | `scripts/check.sh`, `scripts/run-qemu.sh`, `.githooks/` |

See `syscalls.md` for the user-facing ABI, `architecture.md` for how the pieces
fit, and `verification.md` for what each proof covers.
