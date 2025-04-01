# Setup

going through os-phil's os tutorial[^1]

```bash
cargo new jos --bin # specify we want a binary

rustc --version --verbose
```

if we try running `cargo build`, there is supposed to be some sort of linker error:

```bash
/jos/src/main.rs:14: multiple definition of `_start'; /usr/lib/gcc/x86_64-linux-gnu/13/../../../x86_64-linux-gnu/Scrt1.o:(.text+0x0): first defined here
/usr/bin/ld: /usr/lib/gcc/x86_64-linux-gnu/13/../../../x86_64-linux-gnu/Scrt1.o: in function `_start':
(.text+0x1b): undefined reference to `main'
/usr/bin/ld: (.text+0x21): undefined reference to `__libc_start_main'
collect2: error: ld returned 1 exit status

  = note: some `extern` functions couldn't be found; some native libraries may need to be installed or have their path specified
  = note: use the `-l` flag to specify native libraries to link
  = note: use the `cargo:rustc-link-lib` directive to specify the native libraries to link with Cargo (see https://doc.rust-lang.org/cargo/reference/build-scripts.html#rustc-link-lib)
```

```bash
rustup target add thumbv7em-none-eabihf # specify target with no underlying OS
```

to rebuild the project for the target, we can use the following command:

```bash
cargo build --target thumbv7em-none-eabihf # build for the target
cargo build --target thumbv7em-none-eabihf --release # build for the target with optimizations
cargo build --target thumbv7em-none-eabihf --release --profile=release # build for the target with optimizations and release profile
```

```bash
cargo rustc -- -C link-arg=-nostartfiles # build for the target with no start files
```

[^1]: [freestanding rust binary](https://os.phil-opp.com/freestanding-rust-binary/)
