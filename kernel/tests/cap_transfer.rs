//! A capability travels with an IPC message into another thread's space.
//!
//! The server and the client each have their own registered capability space.
//! The client holds the endpoint twice, with and without `GRANT`, plus a second
//! endpoint it hands over. A send naming a capability through the copy without
//! `GRANT` must fail with `Denied`. Through the other, the server receives the
//! word and a copy of the second endpoint in the slot it named, sees
//! `caps_received` set, and uses the copy. Revoking the original must then
//! remove exactly two capabilities, the original and the server's copy, so the
//! copy is linked into the derivation tree. A last message carries a capability
//! the server does not accept: the message still arrives, with `caps_received`
//! clear. Each thread bumps the shared counter after its checks; whichever
//! brings it to 2 exits with success.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use jos_core::cap_rights::Rights;

#[path = "common/threads.rs"]
mod threads;
use threads::{Program, Spaces};

// numeric labels avoid symbol clashes; backward refs avoid 0/1 (intel syntax
// would read `1b` as a binary literal). r12 keeps the IPC buffer address; its
// capability fields sit at 0x20 (send_cap), 0x28 (recv_slot), and 0x30
// (caps_received), both slot fields as slot plus one. SHARED_ADDR + 8 is the
// server's "copy used" flag; the tail after label 5 is the shared counter.
core::arch::global_asm!(
    ".pushsection .rodata.cap_transfer_progs, \"a\"",
    "cap_transfer_server_start:",
    "mov r12, rdi",
    // accept a capability into slot 5, then receive on the endpoint (slot 0)
    "mov qword ptr [r12 + 0x28], 6",
    "mov eax, 7", "xor edi, edi", "syscall",
    "cmp rax, 0x51", "jne 9f",
    "cmp qword ptr [r12 + 0x30], 1", "jne 9f",
    // the copy is a live endpoint with WRITE: a send deposits a message
    "mov eax, 2", "mov edi, 5", "mov esi, 0x99", "syscall", "test rax, rax", "jne 9f",
    // let the client revoke its original
    "mov rbx, 0x200000004008", "mov qword ptr [rbx], 1",
    // accept nothing this time; the message must still arrive
    "mov qword ptr [r12 + 0x28], 0",
    "mov eax, 7", "xor edi, edi", "syscall",
    "cmp rax, 0x52", "jne 9f",
    "cmp qword ptr [r12 + 0x30], 0", "jne 9f",
    // the revoke reached the copy: the slot is empty (BadCap = 1)
    "mov eax, 2", "mov edi, 5", "mov esi, 1", "syscall", "cmp rax, 1", "jne 9f",
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
    "cap_transfer_server_end:",
    "cap_transfer_client_start:",
    "mov r12, rdi",
    // send the second endpoint (slot 2) with the next message
    "mov qword ptr [r12 + 0x20], 3",
    // slot 1 lacks GRANT: Denied (2)
    "mov eax, 6", "mov edi, 1", "mov esi, 0x50", "syscall", "cmp rax, 2", "jne 9f",
    "mov eax, 6", "xor edi, edi", "mov esi, 0x51", "syscall", "test rax, rax", "jne 9f",
    // wait until the server has used its copy
    "mov rbx, 0x200000004008",
    "7:",
    "pause",
    "cmp qword ptr [rbx], 1", "jne 7b",
    // revoking the original removes it and the server's copy
    "mov eax, 21", "mov edi, 2", "syscall", "cmp rax, 2", "jne 9f",
    // send the endpoint itself (slot 0) to a server that accepts nothing
    "mov qword ptr [r12 + 0x20], 1",
    "mov eax, 6", "xor edi, edi", "mov esi, 0x52", "syscall", "test rax, rax", "jne 9f",
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
    "cap_transfer_client_end:",
    ".popsection",
);

unsafe extern "C" {
    static cap_transfer_server_start: u8;
    static cap_transfer_server_end: u8;
    static cap_transfer_client_start: u8;
    static cap_transfer_client_end: u8;
}

// the asm hard-codes the shared page address; keep it in step with the harness.
const _: () = assert!(threads::SHARED_ADDR == 0x2000_0000_4000);

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    jos::ktap::single("cap_transfer::capability_moves_with_message");

    let programs = [
        Program {
            start: core::ptr::addr_of!(cap_transfer_server_start),
            end: core::ptr::addr_of!(cap_transfer_server_end),
        },
        Program {
            start: core::ptr::addr_of!(cap_transfer_client_start),
            end: core::ptr::addr_of!(cap_transfer_client_end),
        },
    ];

    // SAFETY: called once from kernel_main with the boot info pointer; each
    // program is bounded by labels in the global_asm above.
    unsafe {
        threads::boot_isolated(info_ptr, &programs, Spaces::Shared, |untyped, cspaces| {
            let endpoint = untyped.retype_endpoint().expect("endpoint");
            let handed = untyped.retype_endpoint().expect("second endpoint");
            let (server, client) = cspaces.split_at_mut(1);
            let (server, client) = (&mut server[0], &mut client[0]);
            server.insert_at(0, endpoint, Rights::READ).expect("server endpoint");
            client
                .insert_at(0, endpoint, Rights::WRITE.union(Rights::GRANT))
                .expect("granting endpoint");
            client.insert_at(1, endpoint, Rights::WRITE).expect("plain endpoint");
            client.insert_at(2, handed, Rights::all()).expect("handed endpoint");
        })
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}
