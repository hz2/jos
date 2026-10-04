// shared body of the call_reply_* tests; each test file sets SERVER_FIRST and
// TEST_NAME and then `include!`s this file.
//
// one CSpace shared by both threads:
//   slot 0  endpoint, full rights (the server's receive cap)
//   slot 1  reply object, full rights (the server answers through it)
//   slot 2  endpoint minted WRITE-only with badge 7 (the client's call cap)
//
// each program starts with its IPC buffer address in rdi and keeps it in r15
// (callee-saved, so it survives syscalls).
//
// server: recv_reply(0, 1) expecting word 0x41 with badge 7 and buffer words
//         [0x41, 1, 2, 3]; writes [4, 5, 6] and replies 0x42; a second
//         reply(1, ..) must fail with NoCaller. then the non-blocking path:
//         send(0, 0x77) with buffer words [7, 8, 9], zero them, recv(0) must
//         restore them. then spin.
// client: puts [1, 2, 3] in its buffer and calls(2, 0x41); the call must
//         return 0x42 with buffer words [0x42, 4, 5, 6]; exit success.
//
// SERVER_FIRST picks which thread runs first, so the two tests cover both
// handoffs: a call meeting a parked server, and a server meeting a parked call.

use core::panic::PanicInfo;

use jos::serial_print;
use jos_core::cap_rights::Rights;
use jos_core::notification::Badge;

#[path = "threads.rs"]
mod threads;
use threads::Program;

// numeric labels avoid symbol clashes; backward refs avoid 0/1 (intel syntax
// would read `1b` as a binary literal).
core::arch::global_asm!(
    ".pushsection .rodata.call_reply_progs, \"a\"",
    "call_reply_server_start:",
    "mov r15, rdi",
    // recv_reply(ep 0, reply 1): word in rax, badge in rdx
    "mov eax, 10",
    "xor edi, edi",
    "mov esi, 1",
    "syscall",
    "cmp rax, 0x41",
    "jne 9f",
    "cmp rdx, 7",
    "jne 9f",
    // the call's buffer words arrived in ours
    "cmp qword ptr [r15], 0x41",
    "jne 9f",
    "cmp qword ptr [r15 + 8], 1",
    "jne 9f",
    "cmp qword ptr [r15 + 16], 2",
    "jne 9f",
    "cmp qword ptr [r15 + 24], 3",
    "jne 9f",
    // answer with buffer words [4, 5, 6]
    "mov qword ptr [r15 + 8], 4",
    "mov qword ptr [r15 + 16], 5",
    "mov qword ptr [r15 + 24], 6",
    // reply(1, 0x42) answers the bound caller
    "mov eax, 11",
    "mov edi, 1",
    "mov esi, 0x42",
    "syscall",
    "test rax, rax",
    "jne 9f",
    // one shot: a second reply has no caller (NoCaller = 8)
    "mov eax, 11",
    "mov edi, 1",
    "mov esi, 0x43",
    "syscall",
    "cmp rax, 8",
    "jne 9f",
    // non-blocking send to ourselves with buffer words [7, 8, 9]
    "mov qword ptr [r15 + 8], 7",
    "mov qword ptr [r15 + 16], 8",
    "mov qword ptr [r15 + 24], 9",
    "mov eax, 2",
    "xor edi, edi",
    "mov esi, 0x77",
    "syscall",
    "test rax, rax",
    "jne 9f",
    "mov qword ptr [r15 + 8], 0",
    "mov qword ptr [r15 + 16], 0",
    "mov qword ptr [r15 + 24], 0",
    "mov eax, 3",
    "xor edi, edi",
    "syscall",
    "cmp rax, 0x77",
    "jne 9f",
    "cmp qword ptr [r15 + 8], 7",
    "jne 9f",
    "cmp qword ptr [r15 + 16], 8",
    "jne 9f",
    "cmp qword ptr [r15 + 24], 9",
    "jne 9f",
    "2:",
    "jmp 2b",
    "9:",
    "mov eax, 1",
    "mov edi, 0x11",
    "syscall",
    "3:",
    "jmp 3b",
    "call_reply_server_end:",
    "call_reply_client_start:",
    "mov r15, rdi",
    "mov qword ptr [r15 + 8], 1",
    "mov qword ptr [r15 + 16], 2",
    "mov qword ptr [r15 + 24], 3",
    // call(badged ep 2, 0x41) blocks until the server answers
    "mov eax, 9",
    "mov edi, 2",
    "mov esi, 0x41",
    "syscall",
    "cmp rax, 0x42",
    "jne 9f",
    // the reply's buffer words arrived in ours
    "cmp qword ptr [r15], 0x42",
    "jne 9f",
    "cmp qword ptr [r15 + 8], 4",
    "jne 9f",
    "cmp qword ptr [r15 + 16], 5",
    "jne 9f",
    "cmp qword ptr [r15 + 24], 6",
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
    "call_reply_client_end:",
    ".popsection",
);

unsafe extern "C" {
    static call_reply_server_start: u8;
    static call_reply_server_end: u8;
    static call_reply_client_start: u8;
    static call_reply_client_end: u8;
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    serial_print!("{}...\t", TEST_NAME);

    let server = Program {
        start: core::ptr::addr_of!(call_reply_server_start),
        end: core::ptr::addr_of!(call_reply_server_end),
    };
    let client = Program {
        start: core::ptr::addr_of!(call_reply_client_start),
        end: core::ptr::addr_of!(call_reply_client_end),
    };
    let (a, b) = if SERVER_FIRST { (server, client) } else { (client, server) };

    // SAFETY: called once from kernel_main with the boot info pointer; both
    // programs are bounded by labels in the global_asm above.
    unsafe {
        threads::boot(info_ptr, &[a, b], |untyped, cspace| {
            let endpoint = untyped.retype_endpoint().expect("endpoint");
            let reply = untyped.retype_reply().expect("reply");
            let ep = cspace.insert_at(0, endpoint, Rights::all()).expect("server cap");
            cspace.insert_at(1, reply, Rights::all()).expect("reply cap");
            let client_cap = cspace.mint_badged(ep, Rights::WRITE, Badge(7)).expect("client cap");
            assert_eq!(client_cap.slot(), 2, "client cap must land in slot 2");
        })
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}
