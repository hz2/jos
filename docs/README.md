# jos Documentation

Start with `architecture.md` for the principle and how the pieces fit, then
`roadmap.md` for where things stand. `../TODO.md` is the short list of next
steps.

## Design

| doc | covers |
|---|---|
| [`architecture.md`](architecture.md) | the principle, what jos is not, memory, IPC, address spaces, kernel entry, the root task |
| [`capabilities.md`](capabilities.md) | the capability core: rights, badges, derivation, revocation |
| [`kernel/ipc.md`](kernel/ipc.md) | how the blocking and non-blocking IPC paths meet: handoff, order, waking |
| [`kernel/faults.md`](kernel/faults.md) | exceptions: entry stubs, fault endpoints, resuming, demand paging from userspace |
| [`userspace/README.md`](userspace/README.md) | the `user/` workspace: libjos, thread blocks, the root task, adding a check |

## Reference

| doc | covers |
|---|---|
| [`syscalls.md`](syscalls.md) | every syscall: arguments, results, rights, error codes, the IPC buffer, the root task's starting state |
| [`source-map.md`](source-map.md) | which file holds each concept, model and kernel glue side by side |

## Working on jos

| doc | covers |
|---|---|
| [`building-and-running.md`](building-and-running.md) | the toolchain, both workspaces, the boot, the QEMU runner and its variables |
| [`testing.md`](testing.md) | the test layers and which gate runs each |
| [`dst.md`](dst.md) | deterministic simulation testing and tracing |
| [`verification.md`](verification.md) | what is proved, how, and what is next |
| [`roadmap.md`](roadmap.md) | phases, milestones, adopted ideas, open decisions |
