//! x86_64 architecture support.

pub mod multiboot2;

use x86_64::registers::control::{Cr4, Cr4Flags};
use x86_64::registers::model_specific::{Efer, EferFlags};

// the multiboot2 header + 32->64 bit long-mode trampoline. it lives in the
// library so every binary that links jos (the kernel and each test binary)
// gets a valid boot entry. the linker script's ENTRY(_start32) pulls this
// object in and keeps the .multiboot_header section. the trampoline ends by
// calling kernel_main(magic, info_ptr), which each binary defines for itself.
core::arch::global_asm!(include_str!("boot.s"), options(att_syntax));

/// Enables SMEP and SMAP when the CPU supports them, returning which were
/// turned on as `(smep, smap)`.
///
/// SMEP stops ring 0 from executing user pages; SMAP stops ring 0 from reading
/// or writing user pages outside an explicit `stac`/`clac` window (RISC-V gets
/// the same guard from `sstatus.SUM`). Both turn a kernel bug that follows a
/// user pointer into a page fault instead of an exploit. The kernel never
/// dereferences user virtual addresses today (it copies through the identity
/// map), so no access window is needed yet; the IPC buffer will add one.
pub fn enable_smep_smap() -> (bool, bool) {
    // leaf 7 is only valid if the max basic leaf reaches it.
    if core::arch::x86_64::__cpuid(0).eax < 7 {
        return (false, false);
    }
    let ebx = core::arch::x86_64::__cpuid_count(7, 0).ebx;
    let smep = ebx & (1 << 7) != 0;
    let smap = ebx & (1 << 20) != 0;
    let mut flags = Cr4Flags::empty();
    if smep {
        flags |= Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION;
    }
    if smap {
        flags |= Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION;
    }
    // SAFETY: ring 0; both bits are only set when CPUID reports support, so the
    // write cannot #GP. they only restrict ring-0 access to USER pages, which
    // the kernel never touches through user virtual addresses.
    unsafe {
        Cr4::update(|f| f.insert(flags));
    }
    (smep, smap)
}

/// Enables no-execute pages (`EFER.NXE`) when the CPU supports them, returning
/// whether it was turned on.
///
/// Without NXE, bit 63 of a page-table entry is reserved: any access through
/// an entry that sets it faults with a reserved-bit (malformed table) error.
/// W^X user mappings set `NO_EXECUTE` on stacks and data, so this must run
/// before any of them is touched.
pub fn enable_nx() -> bool {
    // leaf 0x8000_0001 is only valid if the max extended leaf reaches it.
    if core::arch::x86_64::__cpuid(0x8000_0000).eax < 0x8000_0001 {
        return false;
    }
    if core::arch::x86_64::__cpuid(0x8000_0001).edx & (1 << 20) == 0 {
        return false;
    }
    // SAFETY: ring 0; NXE is only set when CPUID reports NX support, so the
    // write cannot #GP. it only changes how bit 63 of a PTE is interpreted,
    // from reserved to no-execute, and every other EFER bit is preserved.
    unsafe {
        Efer::update(|f| f.insert(EferFlags::NO_EXECUTE_ENABLE));
    }
    true
}

/// Runs `f` with the SMAP user-access window open, the one sanctioned way for
/// ring 0 to read or write a user page.
///
/// `stac` sets `RFLAGS.AC` to open the window and `clac` closes it again; it is
/// the x86 analogue of toggling `sstatus.SUM` on RISC-V. When SMAP is off the
/// window is always open and this just calls `f`. Keep `f` small: anything it
/// touches through a user address is trusted to be a user page.
pub fn with_user_access<R>(f: impl FnOnce() -> R) -> R {
    let smap = Cr4::read().contains(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION);
    if smap {
        // SAFETY: SMAP is enabled, so stac is a valid instruction. it only sets
        // RFLAGS.AC. no `nomem`: the asm must order against the user accesses
        // in `f`, so the compiler may not hoist them above the window.
        unsafe { core::arch::asm!("stac", options(nostack)) };
    }
    let result = f();
    if smap {
        // SAFETY: as above; clac clears RFLAGS.AC, closing the window before
        // any later code runs, and orders after the accesses in `f`.
        unsafe { core::arch::asm!("clac", options(nostack)) };
    }
    result
}
