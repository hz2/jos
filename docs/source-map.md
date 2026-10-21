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
| threads parked in blocking IPC, timeouts | `wait_table.rs` | `syscall/ipc.rs` (`BLOCKED_SENDS`, `BLOCKED_RECVS`, `expire_timed_waits`, `cancel_waits_on`) |
| call and reply | `reply.rs` | `syscall/ipc.rs` |
| IPC buffer, capability transfer | `ipc_buffer.rs` | `syscall/ipc.rs`, `cap.rs` (`transfer_cap`) |
| notifications | `notification.rs`, `wait_table.rs` | `cap.rs` (the object, the async path), `syscall/ipc.rs` (`sys_signal`, `sys_wait`, `NTFN_WAITERS`) |

## Memory and address spaces

| concept | model | kernel glue |
|---|---|---|
| page-table indices | `page_table.rs` | |
| entry encoding, huge-page split | `pte.rs` | `guard_page.rs` |
| mapping registry | `mapping.rs` | `mapping.rs`, `syscall/vm.rs` |
| address spaces | | `vspace.rs` |
| physical frames | `frame_allocator.rs`, `bitmap.rs` | `memory.rs` |
| free memory at boot (memory plan) | `boot_regions.rs` | `memory.rs` (`plan_memory`, the boot allocator) |
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
| boot information parsing | `jos-core/src/multiboot2.rs`; the kernel side only builds the slice, in `kernel/src/arch/x86_64/multiboot2.rs` |
| ELF loading | `jos-core/src/elf.rs` (the load plan); `kernel/src/rootserver.rs` maps it |
| the root task: building and starting it | `kernel/src/rootserver.rs`, called from `kernel/src/main.rs` |
| SMEP, SMAP, NX | `kernel/src/arch/x86_64/mod.rs` |
| GDT, TSS, IST stacks | `kernel/src/gdt.rs` |
| IDT, PIC, timer, keyboard, and COM1 IRQs; the NMI and machine check | `kernel/src/interrupts.rs` |
| exception stubs, fault delivery | `kernel/src/exceptions.rs`, `kernel/src/syscall/ipc.rs` (`deliver_fault`) |
| syscall numbers, error codes, boot information, user layout (the ABI) | `jos-core/src/abi.rs` |
| `syscall` entry stub, dispatcher | `kernel/src/syscall/mod.rs` |
| console and machine syscalls | `kernel/src/syscall/platform.rs` |
| console input: the receive interrupt and its buffer | `kernel/src/console.rs`, `kernel/src/interrupts.rs` (`com1_interrupt_handler`); readers wait in `syscall/ipc.rs` (`CONSOLE_READERS`) |
| line editing | `jos-core/src/line.rs`; libjos `console::read_line` drives it |
| first entry to ring 3 | `kernel/src/usermode.rs` (`enter_context` for the root task) |
| serial and VGA output | `kernel/src/serial.rs`, `kernel/src/vga_buffer.rs` |

## Userspace

| piece | where |
|---|---|
| syscall stubs and typed wrappers | `user/libjos/src/syscall.rs`, `user/libjos/src/sys.rs` |
| slots, retype and map helpers, threads | `user/libjos/src/mem.rs`, `user/libjos/src/thread.rs` |
| console output, entry point, panic handler, KTAP | `user/libjos/src/console.rs`, `rt.rs`, `ktap.rs` |
| the root task: checks, the isolating runner, the shell | `user/root/src/main.rs` |
| starting a process: the spawner, the process runtime, a test program | `user/libjos/src/process.rs`, `rt.rs` (`process_entry!`), `user/hello/src/main.rs` |
| boot modules for the root task to read | `kernel/src/rootserver.rs` (`map_modules`) |
| target and build-std config | `user/.cargo/config.toml` |

## Verification and testing

| piece | where |
|---|---|
| Kani proofs | `#[cfg(kani)] mod kani_proofs` at the bottom of each `jos-core` module |
| Verus proofs | `jos-core/src/proof.rs` |
| deterministic simulation | `jos-core/tests/dst_*.rs`, with `rng.rs`, `fault.rs`, `trace.rs` |
| QEMU integration tests | `kernel/tests/*.rs`; multi-thread ones share `kernel/tests/common/threads.rs` |
| KTAP output of kernel tests (runner, panic handler, single-check tests) | `kernel/src/ktap.rs`, `kernel/src/lib.rs` |
| the host harness: parallel boots, KTAP parsing, reports, the machine matrix | `tools/jig/src/` (`run.rs` boots, `ktap.rs` parses, `main.rs` reports) |
| scripted shell sessions | `tools/jig/src/expect.rs`, scripts in `tools/jig/expect/` |
| the syscall fuzzer | `user/fuzz/src/main.rs`; the root task's `fuzz` mode and `run_fuzz` in `user/root/src/main.rs` |
| the executable spec the differential storm checks against | `jos-core/src/spec.rs` |
| the root task booting end to end | `scripts/check.sh boot`, `scripts/check.sh matrix` |
| in-kernel trace ring | `kernel/src/trace.rs` |
| gates and runner | `scripts/check.sh`, `scripts/run-qemu.sh`, `.githooks/` |

See `syscalls.md` for the user-facing ABI, `architecture.md` for how the pieces
fit, and `verification.md` for what each proof covers.
