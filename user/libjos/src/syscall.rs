//! The raw `syscall` instruction.
//!
//! The kernel takes the call number in `rax` and up to three arguments in
//! `rdi`, `rsi`, and `rdx`, and returns two results in `rax` and `rdx`. The
//! `syscall` instruction itself overwrites `rcx` and `r11`, and the kernel does
//! not restore `rdi`, `rsi`, `r8`, `r9`, or `r10`, so all of them are declared
//! clobbered. The kernel may write this thread's IPC buffer during the call
//! (a receive delivers message words there), so the stub is not `nomem`.

/// Issues syscall `nr` with three arguments and returns `(rax, rdx)`.
#[inline]
#[must_use]
pub fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> (u64, u64) {
    let rax: u64;
    let rdx: u64;
    // SAFETY: `syscall` enters the kernel, which reads only the argument
    // registers and writes only rax and rdx, the clobbered registers declared
    // below, and this thread's IPC buffer, which no Rust reference borrows
    // across the call (the wrappers in `sys` copy into and out of it around
    // the call). It never touches the user stack, hence `nostack`.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => rax,
            inlateout("rdi") a0 => _,
            inlateout("rsi") a1 => _,
            inlateout("rdx") a2 => rdx,
            lateout("rcx") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (rax, rdx)
}

/// Issues syscall `nr` with two arguments and returns `(rax, rdx)`.
#[inline]
#[must_use]
pub fn syscall2(nr: u64, a0: u64, a1: u64) -> (u64, u64) {
    syscall3(nr, a0, a1, 0)
}

/// Issues syscall `nr` with one argument and returns `(rax, rdx)`.
#[inline]
#[must_use]
pub fn syscall1(nr: u64, a0: u64) -> (u64, u64) {
    syscall3(nr, a0, 0, 0)
}
