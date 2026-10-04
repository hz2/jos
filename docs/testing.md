# Testing

## Layers and gates (current)

| layer | where | runs via | gate |
|-------|-------|----------|------|
| unit | `jos-core/src/*` `#[cfg(test)]` | `check.sh test` | pre-commit, CI |
| deterministic simulation | `jos-core/tests/dst_*.rs` | `check.sh test` | pre-commit, CI |
| undefined behavior | jos-core | `check.sh miri` | pre-push, CI |
| bounded proofs | `#[cfg(kani)] mod kani_proofs` | `check.sh kani` | pre-push, CI |
| functional proofs | `jos-core/src/proof.rs` | `check.sh verus` | manual |
| boot / integration | `kernel/tests/*.rs`, one QEMU image each | `check.sh qemu` | pre-push, CI |

QEMU runs with `-cpu max` so SMEP/SMAP are enforced in every kernel test, under
a 120 s timeout (`JOS_QEMU_TIMEOUT`); a fatal page fault exits with failure
instead of halting. Ring-3 test programs are written as `global_asm!` between
two labels and copied into the user code page (see `kernel/tests/badged_ipc.rs`).

Every new oracle or proof gets a negative control: break the property, confirm
the test fails, revert.

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
