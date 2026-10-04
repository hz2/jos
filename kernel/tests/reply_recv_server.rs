//! A server answers two badged clients in a `ReplyRecv` loop.
//!
//! Slot 0 is the server's endpoint cap, slot 1 its reply object, and slots 2
//! and 3 are the endpoint minted `WRITE` with badges 1 and 2 for the clients.
//! The server receives once with `RecvReply`, then loops on `ReplyRecv`,
//! answering each call with `word + badge * 0x100`, so a client only gets the
//! right answer if the server told the callers apart by badge. Each client
//! checks its answer and bumps the shared counter; whichever brings it to 2
//! exits with success.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use jos::serial_print;
use jos_core::cap_rights::Rights;
use jos_core::notification::Badge;

#[path = "common/threads.rs"]
mod threads;
use threads::Program;

// numeric labels avoid symbol clashes; backward refs avoid 0/1 (intel syntax
// would read `1b` as a binary literal). the client tail after label 5 is the
// shared done counter at threads::SHARED_ADDR.
core::arch::global_asm!(
    ".pushsection .rodata.reply_recv_progs, \"a\"",
    "reply_recv_server_start:",
    // first request: recv_reply(ep 0, reply 1)
    "mov eax, 10",
    "xor edi, edi",
    "mov esi, 1",
    "syscall",
    "2:",
    // answer = word + badge * 0x100, then reply_recv(ep 0, reply 1, answer)
    "shl rdx, 8",
    "add rdx, rax",
    "mov eax, 13",
    "xor edi, edi",
    "mov esi, 1",
    "syscall",
    "jmp 2b",
    "reply_recv_server_end:",
    "reply_recv_client1_start:",
    "mov eax, 9",
    "mov edi, 2",
    "mov esi, 0x10",
    "syscall",
    "cmp rax, 0x110",
    "jne 9f",
    "jmp 5f",
    "9:",
    "mov eax, 1",
    "mov edi, 0x11",
    "syscall",
    "5:",
    "mov rbx, 0x200000004000",
    "lock inc qword ptr [rbx]",
    "cmp qword ptr [rbx], 2",
    "jne 6f",
    "mov eax, 1",
    "mov edi, 0x10",
    "syscall",
    "6:",
    "jmp 6b",
    "reply_recv_client1_end:",
    "reply_recv_client2_start:",
    "mov eax, 9",
    "mov edi, 3",
    "mov esi, 0x20",
    "syscall",
    "cmp rax, 0x220",
    "jne 9f",
    "jmp 5f",
    "9:",
    "mov eax, 1",
    "mov edi, 0x11",
    "syscall",
    "5:",
    "mov rbx, 0x200000004000",
    "lock inc qword ptr [rbx]",
    "cmp qword ptr [rbx], 2",
    "jne 6f",
    "mov eax, 1",
    "mov edi, 0x10",
    "syscall",
    "6:",
    "jmp 6b",
    "reply_recv_client2_end:",
    ".popsection",
);

unsafe extern "C" {
    static reply_recv_server_start: u8;
    static reply_recv_server_end: u8;
    static reply_recv_client1_start: u8;
    static reply_recv_client1_end: u8;
    static reply_recv_client2_start: u8;
    static reply_recv_client2_end: u8;
}

// the asm hard-codes the shared page address; keep it in step with the harness.
const _: () = assert!(threads::SHARED_ADDR == 0x2000_0000_4000);

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    serial_print!("reply_recv_server::answers_two_clients_by_badge...\t");

    let programs = [
        Program {
            start: core::ptr::addr_of!(reply_recv_server_start),
            end: core::ptr::addr_of!(reply_recv_server_end),
        },
        Program {
            start: core::ptr::addr_of!(reply_recv_client1_start),
            end: core::ptr::addr_of!(reply_recv_client1_end),
        },
        Program {
            start: core::ptr::addr_of!(reply_recv_client2_start),
            end: core::ptr::addr_of!(reply_recv_client2_end),
        },
    ];

    // SAFETY: called once from kernel_main with the boot info pointer; each
    // program is bounded by labels in the global_asm above.
    unsafe {
        threads::boot(info_ptr, &programs, |untyped, cspace| {
            let endpoint = untyped.retype_endpoint().expect("endpoint");
            let reply = untyped.retype_reply().expect("reply");
            let ep = cspace.insert_at(0, endpoint, Rights::all()).expect("server cap");
            cspace.insert_at(1, reply, Rights::all()).expect("reply cap");
            let one = cspace.mint_badged(ep, Rights::WRITE, Badge(1)).expect("client 1 cap");
            let two = cspace.mint_badged(ep, Rights::WRITE, Badge(2)).expect("client 2 cap");
            assert_eq!((one.slot(), two.slot()), (2, 3), "client caps must land in 2 and 3");
        })
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}
