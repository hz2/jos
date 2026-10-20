//! Reaching the multiboot2 boot information grub leaves in low memory.
//!
//! The parsing itself is `jos_core::multiboot2`, a bounds-checked walker over a
//! byte slice that Kani proves never leaves the structure. All this module
//! does is turn grub's physical pointer into that slice, which is valid
//! because the trampoline identity-maps low memory, and turn module ranges
//! into byte slices the same way.

use jos_core::boot_regions::PhysRange;
use jos_core::multiboot2::{BootInformation, Module, total_size};

pub use jos_core::multiboot2::BOOTLOADER_MAGIC;

/// Returns the info structure at `info_ptr` and the physical range it
/// occupies, or `None` if its header is malformed.
///
/// # Safety
///
/// `info_ptr` must be the multiboot2 info pointer grub passed to
/// `kernel_main`. Grub places the structure in identity-mapped low memory and
/// nothing writes it afterwards, so it stays valid for the kernel's lifetime.
#[must_use]
pub unsafe fn boot_information(info_ptr: u32) -> Option<(BootInformation<'static>, PhysRange)> {
    let base = info_ptr as usize;
    let start = core::ptr::with_exposed_provenance::<u8>(base);
    // SAFETY: per the contract, the 8-byte header at info_ptr is readable.
    let header = unsafe { core::slice::from_raw_parts(start, 8) };
    let size = total_size(header)?;
    // SAFETY: the header declares the structure's total size; grub keeps all of
    // it readable, and the parser checks it is at least the header.
    let bytes = unsafe { core::slice::from_raw_parts(start, size as usize) };
    let info = BootInformation::parse(bytes).ok()?;
    let range = PhysRange { start: u64::from(info_ptr), end: u64::from(info_ptr) + u64::from(size) };
    Some((info, range))
}

/// Returns the bytes of a boot module, or `None` if its range is inverted or
/// not inside the identity map.
///
/// # Safety
///
/// `module` must come from the info structure grub passed, whose module
/// ranges hold the files grub loaded; the frame allocator must have kept
/// those ranges out of use.
#[must_use]
pub unsafe fn module_bytes(module: &Module<'_>) -> Option<&'static [u8]> {
    if module.end < module.start || u64::from(module.end) > crate::cap::IDENTITY_MAPPED_LIMIT {
        return None;
    }
    let start = core::ptr::with_exposed_provenance::<u8>(module.start as usize);
    // SAFETY: the range lies inside the identity map (checked above) and holds
    // the module grub loaded there, per the contract; nothing writes it.
    Some(unsafe { core::slice::from_raw_parts(start, (module.end - module.start) as usize) })
}
