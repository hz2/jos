// tests/badged_ipc.rs
//
// badged endpoint capabilities, end to end through the syscall boundary. the
// kernel installs one unbadged, full-rights endpoint cap in slot 0 and drops to
// ring 3. the user program:
//
//   mint(slot 0, READ|WRITE, badge 0x42) -> expect new slot 1
//   ipc_send(slot 1, 0x1234)             -> expect 0
//   ipc_recv(slot 0)                     -> expect rax = 0x1234, rdx = 0x42
//   mint(slot 1, READ|WRITE, badge 7)    -> expect AlreadyBadged (no relabel)
//   ipc_send(slot 0, 5); ipc_recv(slot 0) -> expect rax = 5, rdx = 0 (unbadged)
//   exit(Success) iff all held
//
// a Success exit proves a server can tell clients apart by badge, the badge
// arrives in rdx alongside the message word, and a badged cap cannot be
// re-badged to impersonate another client.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use jos::cap::{KernelCapSpace, UntypedRegion};
use jos::memory::BootstrapFrameAllocator;
use jos::vspace::VSpace;
use jos::{serial_print, syscall, usermode};
use jos_core::cap_rights::Rights;
use jos_core::pte::PteFlags;
use x86_64::VirtAddr;
use x86_64::structures::paging::FrameAllocator;

// the ring-3 program, assembled by the compiler instead of hand-encoded bytes.
// position independent (relative jumps only), copied to USER_CODE_ADDR at run
// time. numeric labels avoid clashes; backward refs avoid 0/1 (intel syntax
// would parse `1b` as a binary literal).
core::arch::global_asm!(
    ".pushsection .rodata.badged_ipc_prog, \"a\"",
    ".global badged_ipc_prog_start",
    ".global badged_ipc_prog_end",
    "badged_ipc_prog_start:",
    // mint(src 0, READ|WRITE, badge 0x42) -> slot 1
    "mov eax, 8",
    "xor edi, edi",
    "mov esi, 3",
    "mov edx, 0x42",
    "syscall",
    "cmp rax, 1",
    "jne 9f",
    // send 0x1234 through the badged cap
    "mov eax, 2",
    "mov edi, 1",
    "mov esi, 0x1234",
    "syscall",
    "test rax, rax",
    "jne 9f",
    // recv through the unbadged server cap: word in rax, badge in rdx
    "mov eax, 3",
    "xor edi, edi",
    "syscall",
    "cmp rax, 0x1234",
    "jne 9f",
    "cmp rdx, 0x42",
    "jne 9f",
    // re-badging the badged cap must fail with AlreadyBadged | ERR_FLAG
    "mov eax, 8",
    "mov edi, 1",
    "mov esi, 3",
    "mov edx, 7",
    "syscall",
    "mov rcx, 0x8000000000000002",
    "cmp rax, rcx",
    "jne 9f",
    // an unbadged send delivers badge 0
    "mov eax, 2",
    "xor edi, edi",
    "mov esi, 5",
    "syscall",
    "test rax, rax",
    "jne 9f",
    "mov eax, 3",
    "xor edi, edi",
    "syscall",
    "cmp rax, 5",
    "jne 9f",
    "test rdx, rdx",
    "jne 9f",
    "mov edi, 0x10",
    "jmp 8f",
    "9:",
    "mov edi, 0x11",
    "8:",
    "mov eax, 1",
    "syscall",
    "7:",
    "jmp 7b",
    "badged_ipc_prog_end:",
    ".popsection",
);

unsafe extern "C" {
    static badged_ipc_prog_start: u8;
    static badged_ipc_prog_end: u8;
}

const UNTYPED_SIZE: usize = 64 * 1024;
#[repr(align(4096))]
struct UntypedBacking([u8; UNTYPED_SIZE]);
static mut VSPACE_UNTYPED: UntypedBacking = UntypedBacking([0; UNTYPED_SIZE]);

static mut CSPACE: Option<KernelCapSpace> = None;

const KSTACK_SIZE: usize = 4096 * 4;
#[repr(align(16))]
struct KernelStack(#[allow(dead_code)] [u8; KSTACK_SIZE]);
static mut SYSCALL_STACK: KernelStack = KernelStack([0; KSTACK_SIZE]);

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    serial_print!("badged_ipc::server_sees_client_badge...\t");

    jos::init();

    // SAFETY: boot.s identity-maps the first 1 GiB; called once here.
    let mut frame_allocator = unsafe { BootstrapFrameAllocator::new(info_ptr) };
    // SAFETY: handed out exactly once; page-aligned.
    let mut untyped = unsafe {
        UntypedRegion::new(&mut (*core::ptr::addr_of_mut!(VSPACE_UNTYPED)).0)
    };

    let endpoint = untyped.retype_endpoint().expect("carve endpoint");
    // SAFETY: single-threaded; CSPACE is written once before any syscall reads
    // it, and the &mut borrow ends before the raw pointer is handed out.
    let cspace_ptr = unsafe {
        CSPACE = Some(KernelCapSpace::new());
        let cspace = (*core::ptr::addr_of_mut!(CSPACE)).as_mut().unwrap();
        let full = cspace.insert(endpoint, Rights::all()).expect("insert full cap");
        assert_eq!(full.slot(), 0, "server cap must land in slot 0");
        core::ptr::from_mut::<KernelCapSpace>(cspace)
    };
    // SAFETY: CSPACE is 'static and only touched on the single-threaded syscall
    // path, satisfying set_current_cspace's contract.
    unsafe {
        syscall::set_current_cspace(cspace_ptr);
    }

    // SAFETY: CR3 holds the boot identity map; carved tables are not aliased.
    let mut vspace = unsafe { VSpace::new(&mut untyped).expect("carve VSpace") };
    let code_frame = frame_allocator.allocate_frame().expect("code frame");
    let stack_frame = frame_allocator.allocate_frame().expect("stack frame");
    let code = PteFlags::PRESENT | PteFlags::USER;
    let data = PteFlags::PRESENT | PteFlags::WRITABLE | PteFlags::USER | PteFlags::NO_EXECUTE;
    // SAFETY: fresh unique frames; the user window is empty in the new VSpace.
    unsafe {
        vspace
            .map_page(&mut untyped, usermode::USER_CODE_ADDR, code_frame.start_address().as_u64(), code)
            .expect("map user code");
        vspace
            .map_page(&mut untyped, usermode::USER_STACK_ADDR, stack_frame.start_address().as_u64(), data)
            .expect("map user stack");
    }
    // SAFETY: both symbols bound the program emitted by the global_asm above,
    // in one section, start before end; the frame is freshly allocated,
    // identity-mapped, and the program is far smaller than a page.
    unsafe {
        let start = core::ptr::addr_of!(badged_ipc_prog_start);
        let end = core::ptr::addr_of!(badged_ipc_prog_end);
        let len = end as usize - start as usize;
        assert!(len <= 4096, "user program must fit one page");
        let dst = code_frame.start_address().as_u64() as *mut u8;
        core::ptr::copy_nonoverlapping(start, dst, len);
    }

    let kstack_top = {
        let base = core::ptr::addr_of!(SYSCALL_STACK) as u64;
        VirtAddr::new(base + KSTACK_SIZE as u64)
    };
    syscall::set_kernel_stack(kstack_top);
    syscall::init_syscall();

    x86_64::instructions::interrupts::disable();

    // SAFETY: VSpace::new cloned the kernel PML4 entries, so the kernel stays
    // mapped across the CR3 load.
    unsafe {
        vspace.activate();
    }
    // SAFETY: user code/stack mapped USER-accessible; init + init_syscall ran.
    unsafe {
        usermode::enter_user_mode(
            VirtAddr::new(usermode::USER_CODE_ADDR),
            VirtAddr::new(usermode::USER_STACK_TOP),
        );
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}
