// build script: hand our linker script to rust-lld. the gnu-lld flavor invokes
// lld directly (not via a gcc driver), so it adds no crt startfiles and needs
// no -nostartfiles flag for this freestanding kernel.
//
// the path must be absolute: in a workspace the linker runs with cwd at the
// workspace root, but link.ld lives in this crate, so resolve it against
// CARGO_MANIFEST_DIR (the kernel/ dir).
use std::path::Path;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let script = Path::new(&manifest_dir).join("link.ld");
    let boot_asm = Path::new(&manifest_dir).join("src/arch/x86_64/boot.s");
    println!("cargo:rustc-link-arg=-T{}", script.display());
    println!("cargo:rerun-if-changed={}", script.display());
    println!("cargo:rerun-if-changed={}", boot_asm.display());
}
