//! x86_64 architecture support.

pub mod multiboot2;

// the multiboot2 header + 32->64 bit long-mode trampoline. it lives in the
// library so every binary that links jos (the kernel and each test binary)
// gets a valid boot entry. the linker script's ENTRY(_start32) pulls this
// object in and keeps the .multiboot_header section. the trampoline ends by
// calling kernel_main(magic, info_ptr), which each binary defines for itself.
core::arch::global_asm!(include_str!("boot.s"), options(att_syntax));
