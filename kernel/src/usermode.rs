//! Dropping to ring 3: the userspace entry path (capability slice 3a).
//!
//! This is the first step of slice 3 (userspace). It does the minimum to leave
//! ring 0 and execute code at CPL 3:
//!
//! - [`load_user_image`] maps a user-accessible code page and a user-accessible
//!   stack page into the active address space and copies a payload into the
//!   code page.
//! - [`enter_user_mode`] builds an `iretq` return frame targeting the ring-3
//!   code and data segments (installed by [`crate::gdt`]) and executes `iretq`,
//!   which performs the privilege-level switch.
//!
//! There is no syscall path yet (slice 3b) and no per-task address space or
//! saved register context yet (the retypeable `VSpace`/`Tcb` objects, slice
//! 3c). A ring-3 thread here runs in the kernel's own (identity-mapped) address
//! space, in a user-accessible window the identity map does not cover, and the
//! only way back into the kernel is a fault or a software interrupt whose IDT
//! gate is reachable from ring 3.
//!
//! # Why these addresses
//!
//! The user window is placed at [`USER_BASE`] (`PML4` index 64), a lower-half
//! canonical address. The boot trampoline identity-maps only the first 1 GiB
//! using 2 MiB huge pages under `PML4[0]`; `PML4[64]` is empty, so a 4 KiB
//! `map_to` there builds a fresh page-table hierarchy instead of failing with
//! `ParentEntryHugePage` (the same reason the heap lives in the upper half).
//! The leaf flags carry `USER_ACCESSIBLE`, which `map_to` propagates to every
//! intermediate table it creates, so the whole walk is user-reachable.

use x86_64::VirtAddr;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB,
};

use crate::gdt;

/// Base virtual address of the userspace window (`PML4` index 64).
///
/// Lower-half canonical and clear of the identity map (which only populates
/// `PML4[0]`). The code page is mapped here; the stack page directly follows.
pub const USER_BASE: u64 = 0x2000_0000_0000;

/// Virtual address of the user code page (the ring-3 entry point).
pub const USER_CODE_ADDR: u64 = USER_BASE;

/// Virtual address of the user stack page (one page above the code page).
pub const USER_STACK_ADDR: u64 = USER_BASE + 0x1000;

/// Top of the user stack: the exclusive upper bound of the stack page, where
/// the ring-3 stack pointer starts (the stack grows downward into the page).
pub const USER_STACK_TOP: u64 = USER_STACK_ADDR + 0x1000;

/// A loaded user image: the entry point and initial stack pointer to hand to
/// [`enter_user_mode`].
#[derive(Debug, Clone, Copy)]
pub struct UserImage {
    /// Ring-3 entry point (the user `RIP`). Equals [`USER_CODE_ADDR`].
    pub entry: VirtAddr,
    /// Initial ring-3 stack pointer (the user `RSP`). Equals [`USER_STACK_TOP`].
    pub stack_top: VirtAddr,
}

/// Maps the user code and stack pages and copies `code` into the code page.
///
/// The code page is initially mapped writable so the kernel can copy the
/// payload in; `WRITABLE` is cleared immediately after the copy (W^X).
/// The stack page is mapped present + writable + user + `NO_EXECUTE`.
///
/// # Panics
///
/// Panics if `code` does not fit in a single 4 KiB page, or if a mapping fails
/// (out of frames, or the window is already mapped).
///
/// # Safety
///
/// The caller must ensure the user window (`[USER_BASE, USER_BASE + 0x2000)`)
/// is not already mapped, that `mapper` controls the active address space, and
/// that `frame_allocator` only hands out genuinely free frames. Creating these
/// mappings is sound only because the window is otherwise unused.
pub unsafe fn load_user_image<M, A>(
    mapper: &mut M,
    frame_allocator: &mut A,
    code: &[u8],
) -> UserImage
where
    M: Mapper<Size4KiB>,
    A: FrameAllocator<Size4KiB> + ?Sized,
{
    assert!(
        code.len() <= 4096,
        "user payload must fit in a single 4 KiB page"
    );

    // code page: mapped temporarily writable so we can copy the payload from
    // ring 0; WRITABLE is stripped after the copy to enforce W^X.
    let code_rw = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE;
    let code_rx = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;

    // stack page: writable but never executable.
    let stack_rw_nx = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;

    // map the code page.
    let code_page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(USER_CODE_ADDR));
    let code_frame = frame_allocator
        .allocate_frame()
        .expect("no frame for user code page");
    // SAFETY: USER_CODE_ADDR is a fresh, unmapped, lower-half page (per this
    // function's contract); the frame is freshly allocated and mapped nowhere
    // else, so the mapping introduces no aliasing. writable so ring 0 can copy
    // the payload; stripped to rx immediately after.
    unsafe {
        mapper
            .map_to(code_page, code_frame, code_rw, frame_allocator)
            .expect("map user code page")
            .flush();
    }

    // copy the payload into the freshly mapped code page.
    // SAFETY: the page is mapped present + writable above and is exactly one
    // 4 KiB page; the destination does not overlap the source (kernel slice vs.
    // user frame).
    unsafe {
        core::ptr::copy_nonoverlapping(code.as_ptr(), USER_CODE_ADDR as *mut u8, code.len());
    }

    // W^X: strip WRITABLE now that the copy is done. the CPU re-reads PTE flags
    // on each TLB miss, so the flush here takes effect before ring 3 runs.
    // SAFETY: code_page is mapped (we just mapped it above); single-CPU, no
    // concurrent TLB shootdown needed.
    unsafe {
        mapper
            .update_flags(code_page, code_rx)
            .expect("clear writable on code page")
            .flush();
    }

    // map the stack page.
    let stack_page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(USER_STACK_ADDR));
    let stack_frame = frame_allocator
        .allocate_frame()
        .expect("no frame for user stack page");
    // SAFETY: USER_STACK_ADDR is a fresh, unmapped, lower-half page distinct
    // from the code page; the frame is freshly allocated and unique.
    unsafe {
        mapper
            .map_to(stack_page, stack_frame, stack_rw_nx, frame_allocator)
            .expect("map user stack page")
            .flush();
    }

    UserImage {
        entry: VirtAddr::new(USER_CODE_ADDR),
        stack_top: VirtAddr::new(USER_STACK_TOP),
    }
}

/// Drops to ring 3 and begins executing user code at `entry` with stack
/// `stack_top`. Never returns to the caller: control only re-enters the kernel
/// through a fault or a ring-3-reachable interrupt.
///
/// Builds the `iretq` return frame the cpu uses to switch privilege levels. In
/// long mode `iretq` pops, from the top of the stack: `RIP`, `CS`, `RFLAGS`,
/// `RSP`, `SS`. Pushing them in reverse and executing `iretq` therefore loads
/// the ring-3 code segment into `CS` (lowering `CPL` to 3), the user stack into
/// `RSP`, and jumps to `entry`.
///
/// Interrupts are left masked in the entered context (`RFLAGS` has only the
/// reserved bit set, `IF` clear): this first bring-up is deterministic, with a
/// software trap as the sole way back into the kernel. Enabling interrupts in
/// ring 3 (so the timer can preempt user code) comes with the scheduler's
/// userspace thread support.
///
/// # Safety
///
/// The caller must ensure `entry` points at a mapped, user-accessible,
/// executable page holding valid code, and `stack_top` is the top of a mapped,
/// user-accessible, writable stack region. [`crate::gdt::init_gdt`] must have
/// run (so the user segments and the TSS `rsp0` exist). After this call the cpu
/// is in ring 3; there is no return.
pub unsafe fn enter_user_mode(entry: VirtAddr, stack_top: VirtAddr) -> ! {
    use x86_64::instructions::segmentation::{DS, ES, Segment};

    let sel = gdt::selectors();
    // the selectors returned by add_entry already carry RPL 3 for user
    // descriptors, so .0 is the full selector value iretq expects.
    let user_cs = u64::from(sel.user_code.0);
    let user_ss = u64::from(sel.user_data.0);

    // give ds/es the user data selector. iretq restores cs and ss from the
    // frame but leaves ds/es untouched; in long mode their bases are forced to
    // 0, but loading a valid user selector keeps them consistent with ring 3.
    // allowed from ring 0 because max(CPL=0, RPL=3) <= DPL=3.
    // SAFETY: sel.user_data is a valid writable data-segment selector from the
    // loaded gdt (init_gdt ran per this fn's contract); loading it into ds/es
    // is defined and cannot violate memory safety (segment bases are 0 in long
    // mode). reloading these registers has no aliasing concerns.
    unsafe {
        DS::set_reg(sel.user_data);
        ES::set_reg(sel.user_data);
    }

    // RFLAGS with only bit 1 (reserved, always 1) set: IF clear, so no maskable
    // interrupt fires in ring 3 for this bring-up.
    let rflags: u64 = 0x0000_0002;

    // SAFETY: the pushed frame is a well-formed long-mode iretq frame (SS, RSP,
    // RFLAGS, CS, RIP from top of stack downward as pushed). cs/ss are the
    // ring-3 selectors from the loaded gdt; entry/stack_top are user-accessible
    // per this function's contract. iretq performs the privilege switch and
    // does not return, matching options(noreturn).
    unsafe {
        core::arch::asm!(
            "push {ss}",
            "push {rsp}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            ss = in(reg) user_ss,
            rsp = in(reg) stack_top.as_u64(),
            rflags = in(reg) rflags,
            cs = in(reg) user_cs,
            rip = in(reg) entry.as_u64(),
            options(noreturn),
        );
    }
}
