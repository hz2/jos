# Testing

## Layers and gates (current)

| layer | where | runs via | gate |
|-------|-------|----------|------|
| unit | `jos-core/src/*` `#[cfg(test)]` | `check.sh test` | pre-commit, CI |
| deterministic simulation | `jos-core/tests/dst_*.rs` | `check.sh test` | pre-commit, CI |
| undefined behavior | jos-core | `check.sh miri` | pre-push to main, CI |
| bounded proofs | `#[cfg(kani)] mod kani_proofs` | `check.sh kani` | pre-push to main, CI |
| functional proofs | `jos-core/src/proof.rs` | `check.sh verus` | manual |
| host harness | `tools/jig` unit tests (KTAP parser, reports) | `check.sh test` | pre-commit, CI |
| boot / integration | `kernel/tests/*.rs`, one QEMU image each, booted in parallel by jig | `check.sh qemu` | pre-push to main, CI |
| boot under KVM | the same tests under hardware virtualization | `check.sh qemu-kvm` | pre-push to main (skipped without `/dev/kvm`) |
| first light | the real kernel boots the real root task (`user/root`) in test mode; its ring-3 checks print KTAP and halt the machine with the result | `check.sh boot` (4 machines), `check.sh matrix` (36) | matrix: pre-push to main, CI |
| interactive | the root task's shell over the serial console, typed at by `jig expect` scripts (`tools/jig/expect/*.expect`) | `check.sh shell` | pre-push to main, CI |
| robustness fuzzing | `user/fuzz`, a process holding almost nothing, throws seeded random syscalls at the kernel; every answer must be one the ABI documents | `check.sh fuzz` (64 seeds) | pre-push to main, CI |
| differential fuzzing | the same storm made on the kernel and on `jos_core::spec`, every answer compared | `check.sh fuzz` (64 seeds) | pre-push to main, CI |
| kernel invariants | `selfcheck` (30) checks the live kernel's parts against each other; the root task runs it after every check and every fuzzer run, so a step that leaves the kernel inconsistent fails itself | `check.sh boot`, `matrix`, `fuzz`, `shell` | wherever those run |

QEMU runs with `-cpu max` so SMEP/SMAP are enforced in every kernel test, under
a 120 s timeout (`JOS_QEMU_TIMEOUT`); a fatal page fault exits with failure
instead of halting, and a triple fault (a guest reset) fails rather than passing. Ring-3 test programs are written as `global_asm!` between
two labels and copied into the user code page (see `kernel/tests/badged_ipc.rs`).

Every new oracle or proof gets a negative control: break the property, confirm
the test fails, revert.

`check.sh boot` and `check.sh matrix` run the production path end to end:
they build the kernel binary and the `user/` workspace, boot them with the
root task module named `root test`, and let the root task decide the exit
code through its Machine capability. Removing the kernel's `WRITE` check on
`console_write` makes them fail.

## jig, the host harness

`tools/jig` boots QEMU images in parallel and reads what each guest prints.
Every kernel test and the root task's self-test report in KTAP version 1, the
format Linux's KUnit uses: a `KTAP version 1` header, a `1..N` plan, a
`# run name` line before each test, `#` diagnostics, then `ok N name` or
`not ok N name`. A `harness = false` test registers its one name with
`jos::ktap::single`, the custom test runner numbers `#[test_case]`s, and the
test panic handler turns a panic into diagnostics and a `not ok`.

```text
jig test [FILTER...] [--exact] [--jobs N] [--repeat N] [--junit FILE] [machine flags]
jig boot [--args ARGS] [--matrix | --matrix-small] [--jobs N] [--junit FILE] [machine flags]
jig expect SCRIPT... [machine flags]
jig ktap FILE
machine flags: --accel tcg|kvm --cpu MODEL --mem SIZE --smp N --machine TYPE --timeout SECS
```

- `test` builds the kernel tests (`cargo test --no-run`) and boots every image
  whose name contains a filter, half the host's cores at a time by default.
  `--repeat N` boots each one N times, to hunt flaky tests.
- `boot` builds the kernel and `user/` and boots the root task with `ARGS`
  (default `test`). `--matrix` covers cpu models with and without SMEP and
  SMAP (`max`, `qemu64`), 64 MiB to 4 GiB of memory (past the identity map),
  one and four cpus, the `q35` and `pc` machines, and the host cpu under KVM
  when it is usable; `--matrix-small` is four of the most different ones.
- A boot passes only if the runner's exit code says so and the KTAP agrees:
  the header and plan appeared and every planned test reported `ok`. A missing
  plan, a test that never reported, or a `not ok` behind a clean exit fails.
- A failure prints its `not ok` lines with their diagnostics, the test that
  was running when the guest stopped (a hang, a fault), the last 25 log lines,
  where the whole log was saved (`<target>/jig/run-*/`), and a command that
  reproduces it.
- `--junit FILE` writes JUnit XML: a suite per boot, a case per KTAP test, and
  for a boot cut short a failed case named after the test it was running.
- `ktap FILE` reads a saved log.
- `expect SCRIPT...` boots the root task's shell with its console on a pipe and
  runs each script: `> text` types a line (with `\b`, `\u`, `\c`, `\e` for
  backspace, Ctrl-U, Ctrl-C, and escape), `< text` waits up to 30 s for the
  text, counting from where the previous wait matched. A script passes when
  every wait matched and the machine then halted with success; a failure names
  the script line and what it waited for, and shows the end of the session.

Run jig inside the dev shell (`nix develop`), where qemu and grub live, or
through `check.sh`, which enters it: `qemu`, `qemu-kvm`, `boot` (the small
matrix), and `matrix` all call it. On a 12-core host the 43 kernel test images
take about 15 s under TCG and 6 s under KVM, and the 36-machine matrix about
16 s.

Running under both TCG and KVM matters because their timing differs by orders
of magnitude: a loop that spans several timer ticks under TCG finishes inside
one under KVM. `tcb_revoke` first measured its waits in loop iterations and
checked nothing under KVM (its mutation still passed); it now waits on the TSC.
A test that waits for something to happen or not happen should measure time,
not iterations, and its negative control should fail under both accelerators.

A ring-3 check that needs another thread parked before it acts must not guess
with a delay either: a timer tick can land between the thread's last report and
its blocking call, so the check would act first. The root task's `spawn_parked`
starts the thread with a `call` that the thread answers and parks on in the same
`reply_recv`, so the call returns only once the thread is parked.
`nonblocking_send_reaches_a_parked_receiver` failed one machine of the matrix
before it waited this way.

## Kernel invariants after every step

The pure core proves its parts one at a time; `selfcheck` (syscall 30, in
`kernel/src/selfcheck.rs`) checks that the live kernel's parts agree: the
registry of capability spaces with the spaces in it, every derivation link with
the capability it names, the threads with the scheduler and the blocking
tables, and the mapping registry with the page tables (`docs/syscalls.md` lists
the seven invariants). The root task's runner asks after every check, and the
fuzz sweep after every run, and reports a check `not ok` with the name of each
invariant it left broken, even when its own assertions passed. The shell has a
`selfcheck` command, which `shell.expect` types after its processes have run.

`kernel/tests/selfcheck.rs` breaks each invariant on purpose, the way a bug
would, and expects exactly its bit. End to end, an `unmap` that cleared the
page-table entry but kept the mapping record failed every check of the suite
with `the kernel broke an invariant: mappings`, while every check's own
assertions still passed.
The fuzzer's storms ask every 250 steps too, through a read-only copy of the
machine at slot 5: a release that left a freed registry entry still marked as a
CNode was reported as `spec: step 249 broke a kernel invariant: registry`. That
mutation first hung the kernel, the sweep releasing the same empty entry
forever, so the sweep now releases only entries that hold a space.

## Background notes (blog_os era)


- `test` crate depends on stdlib, so we need `custom_test_frameworks`
  - as a result, many advanced features are not available


- there are two different approaches for communicating between CPU and
  peripheral hardware on x86:
  - memory-mapped I/O
    - this is what we used for the VGA buffer
  - port-mapped I/O
    - this uses a separate I/O bus for communication
    - each connected peripheral has 1+ port numbers
    - uses a special CPU instruction `in` and `out` which take a port number and
      a data byte
    - `isa-debug-exit` device uses port-mapped I/O
      - when a value is written to the I/O port specified by `iobase`, it causes
        QEMU to exit with exit-status `(value << 1) | 1`
        - so when we write `0` to port, QEMU will exit with exit status: 
          `(0 << 1) | 1 = 3`
          - see the `Cargo.toml` for  `test-success-exit-code = 33 # (0x10 << 1) | 1`

## printing to the console

- to see output from the console, we need to send the data from our kernel to
  the host system somehow, some use a TCP network interface but because setting up
  a networking stack can be complex, we will use a serial port instead
- simple way to send data is through a _serial port_ which most modern computers
  no longer support
  - we will use the `uart_16550` crate


## VGA text mode

- `volatile` gives a `Volatile` wrapper type with `read` and `write` methods so
  the compiler does not optimize away writes to the VGA buffer.
- [`format_args`](https://doc.rust-lang.org/nightly/std/macro.format_args.html)
  builds the `fmt::Arguments` that `print!` hands to the writer.

## The syscall fuzzer

`user/fuzz` runs as a process the root task starts with nothing but its
console, its parent and fault endpoints, a copy of an untyped region, and a
machine capability that can only run `selfcheck`, so whatever it does reaches
only objects it made itself. Its argument is a seed.
For each of 2000 steps it picks a syscall by a swarm mix (per-seed weights,
`jos_core::rng::OpMix::swarm`, so some seeds hammer a few calls and leave
others out) and arguments by a schema: mostly a slot it believes holds a
capability, a free slot, a valid object type, a user address, or a short wait,
and one time in eight a hostile word (zero, an edge of the range, anything).
It tracks the slots its retypes and mints fill, so later calls reach mapping,
thread configuration, revocation, and IPC on real objects; it retypes at most
24 objects a run, since untyped memory is not reclaimed yet. It skips only the
calls that would legitimately end or wedge it (`exit`, `thread_exit`, the
blocking IPC calls, moving its own IPC buffer) and keeps every wait under
20 ms.

Three oracles: the kernel must survive, every answer must be one the ABI
documents for that call (0 or an error code, a value or a flagged error code,
`ENOSYS` for no such call), and every 250 steps the kernel must still hold its
own invariants (`selfcheck`, so a broken one names the step that broke it).
The fuzzer prints each undocumented answer and broken invariant as a KTAP
diagnostic and exits with their count. `root fuzz FIRST COUNT` runs a
sweep as one KTAP test per seed (`jig boot --args "fuzz 1 64"`,
`scripts/check.sh fuzz`), the first-light checks run seed 1, and the shell
has `fuzz [seed] [count]`.

It found a real ambiguity on its first sweep: a message word with bit 63 set
reaches its receiver in `rax`, where that bit flags an error, so the kernel
now refuses to send one (`BadWord`) or to mint such a badge (`BadBadge`).

### The differential storm

The robustness storm only asks whether an answer is one the ABI allows. The
differential storm asks whether it is the right one. `jos_core::spec` is an
executable specification of one thread's non-blocking calls in its own
capability space: slots, rights, badges, the mint tree and the count a revoke
returns, retype out of an untyped region, and the non-blocking halves of
endpoints (one message deep) and notifications (coalescing bits). It is
written as plainly as possible (a flat array of slots, a parent index each, a
linear scan for every question) and shares none of the kernel's structure.

With bit 62 of its argument set, the fuzzer makes only the calls the spec
answers (`add`, `retype`, `mint`, `revoke`, `ipc_send`, `ipc_recv`, `invoke`,
`signal`, and `wait` with no wait), each on the kernel and on the spec, with
arguments drawn from what the spec knows of the space, and stops at the first
answer that differs, printing both. A `fuzz` sweep runs every seed through
both storms (`fuzz_seed_N` and `spec_seed_N`), the first-light checks run
differential seed 1, and `check.sh fuzz` runs 64 seeds of each.

A spec is only useful if it fails when the kernel is wrong. Dropping the badge
a plain mint inherits, or ignoring the rights mask a mint attenuates by, each
fails the differential storm within a few hundred calls while every
robustness seed still passes. Its first sweep found a real precedence bug: a
retype of a CNode at an unsupported size answered `BadAlign` instead of
`BadType`, because the kernel checked the region's alignment before whether
the type could be made at all.
