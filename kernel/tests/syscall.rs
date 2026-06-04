// tests/syscall.rs
//
// the capability-slice-3b payoff, headless: a full ring-3 -> ring-0 -> ring-3
// system-call round-trip via syscall/sysret.
//
// the user payload is real machine code (assembled and disassembled offline,
// then pasted as bytes) implementing:
//
//   mov eax, 0          ; SYS_ADD
//   mov edi, 0x100      ; arg0
//   mov esi, 0x23       ; arg1
//   syscall             ; rax = arg0 + arg1
//   cmp rax, 0x123      ; check the result IN RING 3 (proves sysret resumed us)
//   jne fail
//   mov edi, 0x10       ; QemuExitCode::Success
//   jmp do_exit
// fail:
//   mov edi, 0x11       ; QemuExitCode::Failed
// do_exit:
//   mov eax, 1          ; SYS_EXIT
//   syscall             ; kernel writes edi to the debug-exit port; no return
//   jmp .               ; backstop
//
// the verdict is computed by the user code itself: SYS_ADD must return 0x123,
// the comparison runs at CPL 3 after sysret, and only then does SYS_EXIT(0x10)
// fire. if the add returned the wrong value, or sysret failed to resume the
// user instruction stream, the test exits Failed or times out. so a Success
// exit proves: arguments crossed into the kernel, the dispatcher ran, the
// result crossed back, AND user execution continued correctly after sysret.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use jos::memory::BootstrapFrameAllocator;
use jos::{serial_print, syscall, usermode};
use x86_64::VirtAddr;

// the assembled SYS_ADD/SYS_EXIT round-trip program (see the disassembly above).
#[rustfmt::skip]
static USER_PROGRAM: [u8; 46] = [
    0xb8, 0x00, 0x00, 0x00, 0x00,       // mov eax, 0      (SYS_ADD)
    0xbf, 0x00, 0x01, 0x00, 0x00,       // mov edi, 0x100
    0xbe, 0x23, 0x00, 0x00, 0x00,       // mov esi, 0x23
    0x0f, 0x05,                         // syscall
    0x48, 0x3d, 0x23, 0x01, 0x00, 0x00, // cmp rax, 0x123
    0x75, 0x07,                         // jne +7 (-> fail)
    0xbf, 0x10, 0x00, 0x00, 0x00,       // mov edi, 0x10   (Success)
    0xeb, 0x05,                         // jmp +5 (-> do_exit)
    0xbf, 0x11, 0x00, 0x00, 0x00,       // fail: mov edi, 0x11 (Failed)
    0xb8, 0x01, 0x00, 0x00, 0x00,       // do_exit: mov eax, 1 (SYS_EXIT)
    0x0f, 0x05,                         // syscall
    0xeb, 0xfe,                         // jmp . (backstop)
];

// a dedicated kernel stack for the syscall entry path to switch to. the user
// stack must NOT be used for kernel work, so the entry stub loads this. 16 KiB,
// 16-aligned (the syscall ABI requires a 16-aligned rsp at the dispatcher call).
const KSTACK_SIZE: usize = 4096 * 4;
#[repr(align(16))]
struct KernelStack(#[allow(dead_code)] [u8; KSTACK_SIZE]);
static mut SYSCALL_STACK: KernelStack = KernelStack([0; KSTACK_SIZE]);

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    serial_print!("syscall::add_roundtrip_and_exit...\t");

    // gdt/tss (user segments + rsp0) and the production idt.
    jos::init();

    // paging + frame allocator so we can map the user pages.
    // SAFETY: boot.s identity-maps the first 1 GiB; called once here.
    let (mut mapper, mut frame_allocator) = unsafe {
        (jos::memory::init_mapper(), BootstrapFrameAllocator::new(info_ptr))
    };

    // map the user code + stack pages and copy in the payload.
    // SAFETY: the user window is otherwise unmapped; mapper controls the active
    // address space; the bootstrap allocator hands out only free frames.
    let image = unsafe {
        usermode::load_user_image(&mut mapper, &mut frame_allocator, &USER_PROGRAM)
    };

    // tell the syscall entry stub which kernel stack to switch to, then program
    // the syscall MSRs (STAR/LSTAR/SFMASK/EFER).
    let kstack_top = {
        let base = core::ptr::addr_of!(SYSCALL_STACK) as u64;
        VirtAddr::new(base + KSTACK_SIZE as u64)
    };
    syscall::set_kernel_stack(kstack_top);
    syscall::init_syscall();

    // we are about to run ring-3 code that uses `syscall`; mask interrupts so
    // the deterministic single-thread bring-up is not perturbed by the timer.
    x86_64::instructions::interrupts::disable();

    // drop to ring 3. the user program performs the add syscall, checks the
    // result, and exits qemu via SYS_EXIT with a pass/fail code.
    // SAFETY: image entry/stack are mapped user-accessible; init ran so the gdt
    // user segments and rsp0 exist; init_syscall ran so syscall has a target.
    unsafe {
        usermode::enter_user_mode(image.entry, image.stack_top);
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}
