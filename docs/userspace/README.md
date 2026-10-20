# Userspace

Everything that runs in ring 3: the `user/` workspace, built for the built-in
`x86_64-unknown-none` target (soft-float, static PIE) with `build-std`. Its
crates depend on `jos-core` for the ABI, so a syscall number or error code is
defined once for the kernel and for userspace.

| crate | what |
|---|---|
| `user/libjos` | the runtime every program links |
| `user/root` | the root task: the first program, loaded by the kernel |

## libjos

| module | what it gives a program |
|---|---|
| `syscall` | the raw `syscall` instruction, declaring every register the kernel clobbers (`rcx`, `r11`, and `rdi`, `rsi`, `r8` to `r10`, which it does not restore) |
| `sys` | one typed function per syscall over `jos_core::abi`, returning that call's error enum; a code the ABI does not define panics, since it means the two sides disagree |
| `console` | `print!` / `println!` through a Console capability: the bytes go into the calling thread's IPC-buffer data area and only their length crosses the boundary |
| `mem` | a slot allocator over the empty slots the kernel reported, retyping from the first untyped region with room, mapping that installs missing page tables, and `mint` that claims the slot the kernel chose |
| `thread` | `Thread::spawn` / `spawn_with` (optionally with a fault handler): a TCB, stack, and IPC buffer retyped and mapped into a fresh thread block; the thread exits when its function returns, and `reap` revokes all of it |
| `rt` | `root_entry!` (the naked `_start` and runtime setup), `halt`, and the panic handler (prints, then halts the machine through the Machine capability) |
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
state"). Its command line picks a mode; `hello` and `test` run the first-light
checks in `user/root/src/main.rs`, report them in KTAP, and halt the machine
with the result, which is what `scripts/check.sh boot` runs. The checks cover
the boot information, IPC, badges, revocation, mapping and W^X, attenuated
console and machine capabilities, threads and thread-id reuse, stale replies,
both directions of the parked-thread handoff, endpoint order, and fault
delivery including userspace demand paging.

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
to block, have the thread report `READY` first, or `spin_past_a_tick()`. Then
prove the check is not vacuous: break the kernel property it covers, run
`scripts/check.sh boot`, see exactly that check report `not ok`, revert.
