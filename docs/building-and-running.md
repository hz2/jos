# Building and Running

How jos is built, booted, and tested today. jos began as a walk through Philipp
Oppermann's blog_os tutorial[^1], but it has since diverged: it is an x86_64
capability microkernel booted via multiboot2 and GRUB, built against a custom
bare-metal target inside a reproducible Nix toolchain. The tutorial's
`bootimage` / `bootloader`-crate flow is no longer used.

## Toolchain (Nix)

All builds and tests run inside the Nix dev shell, which pins the Rust nightly
toolchain and the QEMU / GRUB tooling so the build is reproducible:

```bash
nix develop                 # default shell: rust nightly, qemu, grub2, xorriso
nix develop .#verify        # adds Kani and Verus for proofs
```

Enter the shell once and run cargo normally, or prefix a single command with
`nix develop --command`. Entering the shell also points git at `.githooks/`.
The checks live in `scripts/check.sh`, which enters the dev shell itself (and
the verify shell for `kani` and `verus`). The toolchain version is pinned in `flake.nix`
(via fenix); `rust-toolchain` records the channel.

## Workspace layout

The repository is a two-crate Cargo workspace, and the split is load-bearing:

- `jos-core/` is pure, `no_std`, hardware-free logic (capability tables, ring
  buffers, page-table math, the endpoint state machine, the DST harnesses). It
  builds for the host, so it can be exercised under `cargo test`, Miri, and
  Kani. See `capabilities.md` and `dst.md`.
- `kernel/` is the bootable kernel: assembly, MMIO, and the hardware glue around
  `jos-core`.

The bare-metal target is configured in `kernel/.cargo/config.toml`, not at the
workspace root. That file is discovered only when cargo is invoked from inside
`kernel/`, so the kernel builds bare-metal while `jos-core` builds for the host
by default. This is why kernel commands below are run from `kernel/`.

## The custom target

The kernel targets `kernel/x86_64-jos.json`, a custom bare-metal target spec
(no host OS, soft-float, kernel code model). `kernel/.cargo/config.toml` sets it
as the default target there and enables `build-std` for `core`, `alloc`, and
`compiler_builtins`, so the standard library is compiled for the custom target:

```toml
[unstable]
build-std = ["core", "compiler_builtins", "alloc"]
build-std-features = ["compiler-builtins-mem"]
json-target-spec = true

[build]
target = "x86_64-jos.json"
```

(`aarch64-jos.json` and `riscv_32-jos.json` exist as future-arch stubs; x86_64
is the live target.)

## How it boots

jos boots via multiboot2 and GRUB, not the `bootloader` crate and not QEMU's
built-in `-kernel` loader (which is multiboot1-only and rejects an elf64 image):

- The boot trampoline lives in the library (`kernel/src/lib.rs` includes
  `src/arch/x86_64/boot.s` via `global_asm!`), so every binary that links `jos`
  (the kernel and each test) shares one boot entry. `boot.s` carries the
  multiboot2 header and a 32-to-64-bit long-mode trampoline: it identity-maps
  the first 1 GiB with 2 MiB huge pages, enables PAE / long mode / paging, loads
  a 64-bit GDT, far-jumps to 64-bit code, and calls `kernel_main(magic, info_ptr)`.
- Each binary provides its own `kernel_main`: the real kernel in `main.rs`, the
  test harness in `lib.rs` under `#[cfg(test)]`, and the standalone tests in
  `tests/`.
- `link.ld` sets `ENTRY(_start32)`, loads at 1 MiB, and keeps the multiboot
  header first.
- Legacy VGA text mode at `0xb8000` stays live because the boot image is built
  for BIOS (i386-pc), not EFI.

## Building and running

```bash
cd kernel && cargo build   # build the kernel elf
cd kernel && cargo run     # build and boot under qemu
```

`cargo run` and `cargo test` go through the runner wired in
`kernel/.cargo/config.toml`:

```toml
[target.'cfg(target_os = "none")']
runner = "../scripts/run-qemu.sh"
```

`scripts/run-qemu.sh` takes the kernel elf cargo hands it, assembles a GRUB
rescue ISO around it (`grub-mkrescue`, with `xorriso` as the backend), and boots
it headless:

```bash
timeout 120 qemu-system-x86_64 -machine q35 -cpu max -m 128M -cdrom jos.iso \
    -serial mon:stdio -display none \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 -no-reboot
```

`-cpu max` exposes SMEP and SMAP, which `jos::init` turns on, so every test runs
with ring 0 barred from executing or touching user pages. The timeout
(`JOS_QEMU_TIMEOUT`, default 120 s) turns a wedged guest into a failure, and a
fatal page fault exits QEMU with the failure code instead of halting.

## Testing

Tests are headless QEMU integration tests; output comes back over the serial
port and the guest exits via the `isa-debug-exit` device:

```bash
scripts/check.sh qemu              # every kernel test
scripts/check.sh qemu badged_ipc   # one test
```

The `isa-debug-exit` device maps a guest write of `N` at port `0xf4` to a host
exit code of `(N << 1) | 1`. The kernel writes `0x10` on success, giving exit
`33`; `run-qemu.sh` maps `33` back to shell `0` so `cargo test` reports pass and
fail correctly. Anything else (for example the `35` the kernel writes on a test
failure) propagates as a failure. See `testing.md` for the harness details.

The pure-logic crate is tested on the host, with no QEMU:

```bash
scripts/check.sh test     # unit + deterministic simulation tests
scripts/check.sh miri     # undefined-behavior checking
scripts/check.sh clippy   # both crates, -D warnings
scripts/check.sh kani     # bounded proofs
scripts/check.sh fast     # style + clippy + test: the pre-commit gate
scripts/check.sh ci       # everything ci runs
```

[^1]: [Philipp Oppermann's blog_os](https://os.phil-opp.com/)
