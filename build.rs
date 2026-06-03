// build script: hand our linker script to rust-lld. the gnu-lld flavor invokes
// lld directly (not via a gcc driver), so it adds no crt startfiles and needs
// no -nostartfiles flag for this freestanding multiboot1 kernel.
fn main() {
    println!("cargo:rustc-link-arg=-Tlink.ld");
    println!("cargo:rerun-if-changed=link.ld");
    println!("cargo:rerun-if-changed=src/arch/x86_64/boot.s");
}
