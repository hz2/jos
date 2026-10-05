//! Threads in separate address spaces do not see each other's memory.
//!
//! Two threads, each with its own `VSpace`, map different frames at the same
//! address (`PRIVATE_ADDR`). Thread A writes `0xA` there and blocks receiving;
//! thread B writes `0xB` at the same address and sends to A. When A resumes, its
//! page must still hold `0xA`: the scheduler switched `CR3` with the thread. If
//! it did not, B would run in A's address space, where its code is not mapped.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use jos::serial_print;
use jos_core::cap_rights::Rights;

#[path = "common/threads.rs"]
mod threads;
use threads::{Program, Spaces};

// numeric labels avoid symbol clashes; backward refs avoid 0/1 (intel syntax
// would read `1b` as a binary literal). 0x200000008000 is threads::PRIVATE_ADDR.
core::arch::global_asm!(
    ".pushsection .rodata.vspace_isolation_progs, \"a\"",
    "vspace_isolation_a_start:",
    "mov rbx, 0x200000008000",
    "mov qword ptr [rbx], 0xA",
    // blocking receive on the endpoint in slot 0
    "mov eax, 7",
    "xor edi, edi",
    "syscall",
    "cmp rax, 0x42",
    "jne 9f",
    "mov rbx, 0x200000008000",
    "cmp qword ptr [rbx], 0xA",
    "jne 9f",
    "mov eax, 1",
    "mov edi, 0x10",
    "syscall",
    "9:",
    "mov eax, 1",
    "mov edi, 0x11",
    "syscall",
    "3:",
    "jmp 3b",
    "vspace_isolation_a_end:",
    "vspace_isolation_b_start:",
    "mov rbx, 0x200000008000",
    "mov qword ptr [rbx], 0xB",
    "cmp qword ptr [rbx], 0xB",
    "jne 9f",
    // blocking send of 0x42 to thread A
    "mov eax, 6",
    "xor edi, edi",
    "mov esi, 0x42",
    "syscall",
    "3:",
    "jmp 3b",
    "9:",
    "mov eax, 1",
    "mov edi, 0x11",
    "syscall",
    "vspace_isolation_b_end:",
    ".popsection",
);

unsafe extern "C" {
    static vspace_isolation_a_start: u8;
    static vspace_isolation_a_end: u8;
    static vspace_isolation_b_start: u8;
    static vspace_isolation_b_end: u8;
}

// the asm hard-codes the private page address; keep it in step with the harness.
const _: () = assert!(threads::PRIVATE_ADDR == 0x2000_0000_8000);

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    serial_print!("vspace_isolation::same_address_different_frames...\t");

    let programs = [
        Program {
            start: core::ptr::addr_of!(vspace_isolation_a_start),
            end: core::ptr::addr_of!(vspace_isolation_a_end),
        },
        Program {
            start: core::ptr::addr_of!(vspace_isolation_b_start),
            end: core::ptr::addr_of!(vspace_isolation_b_end),
        },
    ];

    // SAFETY: called once from kernel_main with the boot info pointer; each
    // program is bounded by labels in the global_asm above.
    unsafe {
        threads::boot_with(info_ptr, &programs, Spaces::Separate, |untyped, cspace| {
            let endpoint = untyped.retype_endpoint().expect("endpoint");
            cspace.insert_at(0, endpoint, Rights::all()).expect("endpoint cap");
        })
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}
