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
