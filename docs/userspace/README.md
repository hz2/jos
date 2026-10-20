# Userspace

Everything that runs in ring 3: the `user/` workspace, built for the built-in
`x86_64-unknown-none` target (soft-float, static PIE) with `build-std`. Its
crates depend on `jos-core` for the ABI, so a syscall number or error code is
defined once for the kernel and for userspace.

| crate | what |
|---|---|
| `user/libjos` | the runtime every program links |
| `user/root` | the root task: the first program, loaded by the kernel |
| `user/hello` | a small program the root task starts as a process, to check what a process can and cannot do |

## libjos

| module | what it gives a program |
|---|---|
| `syscall` | the raw `syscall` instruction, declaring every register the kernel clobbers (`rcx`, `r11`, and `rdi`, `rsi`, `r8` to `r10`, which it does not restore) |
| `sys` | one typed function per syscall over `jos_core::abi`, returning that call's error enum; a code the ABI does not define panics, since it means the two sides disagree |
| `console` | `print!` / `println!` through a Console capability: the bytes go into the calling thread's IPC-buffer data area and only their length crosses the boundary; `read` (with a deadline) and `read_line`, which echoes as it edits with `jos_core::line::LineEditor` (backspace, Ctrl-U, Ctrl-C, escape sequences swallowed) |
| `mem` | a slot allocator over the empty slots the kernel reported, retyping from the first untyped region with room, mapping that installs missing page tables, and `mint` that claims the slot the kernel chose |
| `thread` | `Thread::spawn` / `spawn_with` (optionally with a fault handler): a TCB, stack, and IPC buffer retyped and mapped into a fresh thread block; the thread exits when its function returns, and `reap` revokes all of it |
| `process` | `Process::spawn`: starts an ELF image as a process of its own (a fresh VSpace, CNode, and thread built from this program's untyped memory, the image loaded with `jos_core::elf`), and `reap` revokes it all |
| `rt` | `root_entry!` and `process_entry!` (the naked `_start` and runtime setup; a process's `main` returns its exit code, sent to its parent), `halt`, and the panic handler (prints one KTAP diagnostic, then a spawned thread faults with `ud2` for its fault handler to hear of, and the root task's first thread halts the machine) |
| `ktap` | the KTAP lines the host harness parses: header, `# run name`, `ok N name` / `not ok N name` |

## Thread blocks

Each thread lives in a 128 KiB-aligned thread block (`abi::layout`):

```
block + 0x00000  guard page (unmapped)
block + 0x01000  stack, up to 16 pages; a thread maps as many as it asks for,
                 counting down from the top
block + 0x11000  guard page
block + 0x12000  IPC buffer
```

A thread finds its own IPC buffer by rounding its stack pointer down to the
block and adding `THREAD_IPC_BUFFER`, so threads sharing an address space never
write each other's buffers and no thread-local storage is needed. The root
task's window is a thread block too (its `BootInfo` page sits just above the
IPC buffer), and threads it starts get blocks from `THREAD_BLOCKS_START`, the
second GiB of user space.

## The root task

The kernel loads `user/root` from the boot module named `root` and starts it
with the capabilities listed in `docs/syscalls.md` ("The root task's starting
state"). Its command line picks a mode:

- `hello` (the default) and `test [filter]` run the first-light checks in
  `user/root/src/main.rs`, or those whose name contains `filter`, report them
  in KTAP, and halt the machine with the result; `scripts/check.sh boot` and
  `matrix` run `test`, and `jig boot --args "test timed"` runs a subset;
- `list` reports every check as a skipped KTAP test, so a harness can read the
  names;
- `shell` reads commands from the console: `help`, `info`, `mem`, `list`,
  `test [filter]` (the checks, run as below), `bench [rounds]` (timed call and
  reply round trips to an echo thread), `modules`, `run name [arg]` (start a
  boot module as a process and report how it ended), `echo`, and
  `halt [code]`. `cargo run`
  at a terminal starts here, and `jig expect` scripts drive it in `check.sh
  shell`.

The checks cover the boot information, IPC, badges, revocation, mapping and
W^X, attenuated console and machine capabilities, threads and thread-id reuse,
stale replies, both directions of the parked-thread handoff, endpoint order,
fault delivery including userspace demand paging, timed receives, revoking an
endpoint with threads blocked on it, notifications (signals reaching a waiting
thread, coalescing, timing out, and ending on revoke), and processes (`user/hello` started from
its boot module, exiting, isolated from its parent's memory, and holding only
what it was given).

### How a check runs

The runner starts each check in a fresh thread whose fault handler is the
runner's own endpoint, then waits on that endpoint with `recv_timeout`. Three
things can come back:

- the check's report, badged as a report: `ok`, or `not ok` after the check
  printed why;
- a fault, badged as a fault: `not ok` with the fault's kind, instruction,
  address, and error code. A panic in a spawned thread is a fault too: the
  libjos panic handler prints the message and executes `ud2`, so only the
  root task's first thread halts the machine on a panic;
- nothing within 30 s: `not ok`, the check is stopped.

Either way the runner reaps the thread and drops any late report before the
next check starts, so one broken check costs only its own line.

## Adding a check

A check is a `fn(&BootInfo) -> Result<(), &'static str>` added to `CHECKS`:

```rust
/// What the check proves, in one sentence.
fn endpoint_carries_a_word(_: &BootInfo) -> Result<(), &'static str> {
    let ep = object(ObjectType::Endpoint)?;      // retyped into a fresh slot
    sys::send(ep, 0x1234).map_err(|_| "send")?;
    let received = sys::recv(ep).map_err(|_| "recv")?;
    release(&[ep])?;                             // revoke, and free the slot
    ensure(received == (0x1234, 0), "wrong word or badge")
}
```

Clean up before asserting, so a failing check does not leak slots into the
next one. A check that needs a second thread starts it with `Thread::spawn`
and passes slots in its argument (`pack`/`field`); to make it wait for a thread
to block, start it with `spawn_parked`, whose call returns only once the thread
is parked (see `docs/testing.md`). Then
prove the check is not vacuous: break the kernel property it covers, run
`scripts/check.sh boot`, see exactly that check report `not ok`, revert.
