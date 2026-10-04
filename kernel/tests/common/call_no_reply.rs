// shared body of the call_no_reply_* tests; each test file sets SERVER_FIRST
// and TEST_NAME and then `include!`s this file.
//
// a Call that meets a plain blocking receive can never be answered, so the
// kernel must fail it with NoReply rather than leave the caller parked:
//
// server: ipc_recv_blocking(0) must still receive the word 0x41.
// client: call(0, 0x41) must return NoReply | ERR_FLAG (0x8000000000000007).
//
// either thread may finish its check last, so each ends by bumping the shared
// counter; whichever brings it to 2 exits with success. SERVER_FIRST covers
// both kernel paths: the call meets a parked receiver (failed in sys_call), or
// the receive meets a parked call (failed through abort_call).

use core::panic::PanicInfo;

use jos::serial_print;
use jos_core::cap_rights::Rights;

#[path = "two_threads.rs"]
mod two_threads;
use two_threads::Program;

// numeric labels avoid symbol clashes; backward refs avoid 0/1 (intel syntax
// would read `1b` as a binary literal). the tail after label 5 is the shared
// done counter at two_threads::SHARED_ADDR.
core::arch::global_asm!(
    ".pushsection .rodata.call_no_reply_progs, \"a\"",
    "call_no_reply_server_start:",
    // a plain blocking receive takes the call's word but cannot answer it
    "mov eax, 7",
    "xor edi, edi",
    "syscall",
    "cmp rax, 0x41",
    "jne 9f",
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
    "9:",
    "mov eax, 1",
    "mov edi, 0x11",
    "syscall",
    "3:",
    "jmp 3b",
    "call_no_reply_server_end:",
    "call_no_reply_client_start:",
    // the call must fail with NoReply instead of blocking forever
    "mov eax, 9",
    "xor edi, edi",
    "mov esi, 0x41",
    "syscall",
    "mov rcx, 0x8000000000000007",
    "cmp rax, rcx",
    "jne 9f",
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
    "9:",
    "mov eax, 1",
    "mov edi, 0x11",
    "syscall",
    "3:",
    "jmp 3b",
    "call_no_reply_client_end:",
    ".popsection",
);

unsafe extern "C" {
    static call_no_reply_server_start: u8;
    static call_no_reply_server_end: u8;
    static call_no_reply_client_start: u8;
    static call_no_reply_client_end: u8;
}

// the asm hard-codes the shared page address; keep it in step with the harness.
const _: () = assert!(two_threads::SHARED_ADDR == 0x2000_0000_4000);

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    serial_print!("{}...\t", TEST_NAME);

    let server = Program {
        start: core::ptr::addr_of!(call_no_reply_server_start),
        end: core::ptr::addr_of!(call_no_reply_server_end),
    };
    let client = Program {
        start: core::ptr::addr_of!(call_no_reply_client_start),
        end: core::ptr::addr_of!(call_no_reply_client_end),
    };
    let (a, b) = if SERVER_FIRST { (server, client) } else { (client, server) };

    // SAFETY: called once from kernel_main with the boot info pointer; both
    // programs are bounded by labels in the global_asm above.
    unsafe {
        two_threads::boot(info_ptr, a, b, |untyped, cspace| {
            let endpoint = untyped.retype_endpoint().expect("endpoint");
            cspace.insert_at(0, endpoint, Rights::all()).expect("endpoint cap");
        })
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}
