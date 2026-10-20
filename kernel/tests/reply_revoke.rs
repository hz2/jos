//! Revoking a bound reply object fails the call waiting on it.
//!
//! The server receives a call with `RecvReply`, then revokes its own reply
//! capability with `Revoke` instead of answering. The revoke must remove exactly
//! that capability, a later `Reply` through the slot must find it gone, and the
//! client's `Call` must return `NoReply` rather than blocking forever. Each thread
//! bumps the shared counter after its checks; whichever brings it to 2 exits
//! with success.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use jos_core::cap_rights::Rights;

#[path = "common/threads.rs"]
mod threads;
use threads::Program;

// numeric labels avoid symbol clashes; backward refs avoid 0/1 (intel syntax
// would read `1b` as a binary literal). the tail after label 5 is the shared
// done counter at threads::SHARED_ADDR.
core::arch::global_asm!(
    ".pushsection .rodata.reply_revoke_progs, \"a\"",
    "reply_revoke_server_start:",
    // recv_reply(ep 0, reply 1): the client's call arrives and binds the reply
    "mov eax, 10", "xor edi, edi", "mov esi, 1", "syscall",
    "cmp rax, 0x41", "jne 9f",
    // revoke the reply capability: exactly one capability removed
    "mov eax, 21", "mov edi, 1", "syscall", "cmp rax, 1", "jne 9f",
    // the slot is empty now: reply finds no capability (BadCap = 1)
    "mov eax, 11", "mov edi, 1", "mov esi, 0x42", "syscall", "cmp rax, 1", "jne 9f",
    "jmp 5f",
    "9:",
    "mov eax, 1", "mov edi, 0x11", "syscall",
    "5:",
    "mov rbx, 0x200000004000",
    "lock inc qword ptr [rbx]",
    "cmp qword ptr [rbx], 2",
    "jne 6f",
    "mov eax, 1", "mov edi, 0x10", "syscall",
    "6:",
    "jmp 6b",
    "reply_revoke_server_end:",
    "reply_revoke_client_start:",
    // call(ep 0, 0x41) must fail with NoReply | ERR_FLAG when the reply is revoked
    "mov eax, 9", "xor edi, edi", "mov esi, 0x41", "syscall",
    "mov rcx, 0x8000000000000007", "cmp rax, rcx", "jne 9f",
    "jmp 5f",
    "9:",
    "mov eax, 1", "mov edi, 0x11", "syscall",
    "5:",
    "mov rbx, 0x200000004000",
    "lock inc qword ptr [rbx]",
    "cmp qword ptr [rbx], 2",
    "jne 6f",
    "mov eax, 1", "mov edi, 0x10", "syscall",
    "6:",
    "jmp 6b",
    "reply_revoke_client_end:",
    ".popsection",
);

unsafe extern "C" {
    static reply_revoke_server_start: u8;
    static reply_revoke_server_end: u8;
    static reply_revoke_client_start: u8;
    static reply_revoke_client_end: u8;
}

// the asm hard-codes the shared page address; keep it in step with the harness.
const _: () = assert!(threads::SHARED_ADDR == 0x2000_0000_4000);

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    jos::ktap::single("reply_revoke::revoked_reply_fails_the_call");

    let programs = [
        Program {
            start: core::ptr::addr_of!(reply_revoke_server_start),
            end: core::ptr::addr_of!(reply_revoke_server_end),
        },
        Program {
            start: core::ptr::addr_of!(reply_revoke_client_start),
            end: core::ptr::addr_of!(reply_revoke_client_end),
        },
    ];

    // SAFETY: called once from kernel_main with the boot info pointer; each
    // program is bounded by labels in the global_asm above.
    unsafe {
        threads::boot(info_ptr, &programs, |untyped, cspace| {
            let endpoint = untyped.retype_endpoint().expect("endpoint");
            let reply = untyped.retype_reply().expect("reply");
            cspace.insert_at(0, endpoint, Rights::all()).expect("endpoint cap");
            cspace.insert_at(1, reply, Rights::all()).expect("reply cap");
        })
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}
