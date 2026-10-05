//! A thread builds part of its own address space from capabilities.
//!
//! Slot 0 is a `VSpace` capability to the thread's own address space and slot 1
//! an untyped region. The program retypes three page tables, a spare table, and
//! a frame, then maps them with `MapPageTable` and `MapFrame`, checking each
//! refusal on the way (missing table, kernel address, table mapped twice, every
//! level present, writable and executable, read-only capability mapped
//! writable, frame mapped twice) before writing and reading the new page. It then
//! unmaps the frame and maps it one page up, where the same data must appear.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use jos::cap::{KernelCapSpace, Tcb, UntypedRegion};
use jos::memory::BootstrapFrameAllocator;
use jos::vspace::VSpace;
use jos::{cpu_local, serial_print, syscall, usermode};
use jos_core::cap_rights::Rights;
use jos_core::pte::PteFlags;
use x86_64::VirtAddr;
use x86_64::structures::paging::FrameAllocator;

// numeric labels avoid symbol clashes; backward refs avoid 0/1 (intel syntax
// would read `1b` as a binary literal). r15 holds the target address, root
// entry 65 of the user half; syscall errors are the IpcSyscallError codes.
core::arch::global_asm!(
    ".pushsection .rodata.map_frame_prog, \"a\"",
    "map_frame_start:",
    "mov r15, 0x208000000000",
    // retype three tables (slots 2, 3, 4), a frame (5), and a spare table (6)
    "mov eax, 4", "mov edi, 1", "mov esi, 3", "mov edx, 2", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 4", "mov edi, 1", "mov esi, 3", "mov edx, 3", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 4", "mov edi, 1", "mov esi, 3", "mov edx, 4", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 4", "mov edi, 1", "mov esi, 5", "mov edx, 5", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 4", "mov edi, 1", "mov esi, 3", "mov edx, 6", "syscall", "test rax, rax", "jne 9f",
    // a frame before its tables: MissingTable (14)
    "mov eax, 15", "xor edi, edi", "mov esi, 5", "lea rdx, [r15 + 1]", "syscall",
    "cmp rax, 14", "jne 9f",
    // a table in the kernel's identity range: BadAddress (13)
    "mov eax, 14", "xor edi, edi", "mov esi, 2", "mov edx, 0x1000", "syscall",
    "cmp rax, 13", "jne 9f",
    // the first table, then the same table again: AlreadyMapped (15)
    "mov eax, 14", "xor edi, edi", "mov esi, 2", "mov rdx, r15", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 14", "xor edi, edi", "mov esi, 2", "mov rdx, r15", "syscall", "cmp rax, 15", "jne 9f",
    // the second and third levels
    "mov eax, 14", "xor edi, edi", "mov esi, 3", "mov rdx, r15", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 14", "xor edi, edi", "mov esi, 4", "mov rdx, r15", "syscall", "test rax, rax", "jne 9f",
    // every level present now: AlreadyPresent (16)
    "mov eax, 14", "xor edi, edi", "mov esi, 6", "mov rdx, r15", "syscall", "cmp rax, 16", "jne 9f",
    // writable and executable: WritableExecutable (17)
    "mov eax, 15", "xor edi, edi", "mov esi, 5", "lea rdx, [r15 + 3]", "syscall",
    "cmp rax, 17", "jne 9f",
    // a read-only copy of the frame mapped writable: Denied (2)
    "mov eax, 8", "mov edi, 5", "mov esi, 1", "xor edx, edx", "syscall", "mov rbx, rax",
    "mov eax, 15", "xor edi, edi", "mov rsi, rbx", "lea rdx, [r15 + 1]", "syscall",
    "cmp rax, 2", "jne 9f",
    // map it writable, then use the page
    "mov eax, 15", "xor edi, edi", "mov esi, 5", "lea rdx, [r15 + 1]", "syscall",
    "test rax, rax", "jne 9f",
    "mov qword ptr [r15], 0x1234",
    "cmp qword ptr [r15], 0x1234", "jne 9f",
    // the same frame at a second address: AlreadyMapped (15)
    "mov eax, 15", "xor edi, edi", "mov esi, 5", "lea rdx, [r15 + 0x1001]", "syscall",
    "cmp rax, 15", "jne 9f",
    // unmap it; a second unmap finds nothing mapped: NotMapped (19)
    "mov eax, 16", "mov edi, 5", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 16", "mov edi, 5", "syscall", "cmp rax, 19", "jne 9f",
    // map it again one page up: the same frame, so the same data
    "mov eax, 15", "xor edi, edi", "mov esi, 5", "lea rdx, [r15 + 0x1001]", "syscall",
    "test rax, rax", "jne 9f",
    "cmp qword ptr [r15 + 0x1000], 0x1234", "jne 9f",
    // retype a CNode (type 1, size_bits 12) into slot 8 (the mint took 7); a send
    // to it must fail with NotEndpoint (3), so it really is a CNode
    "mov eax, 4", "mov edi, 1", "mov esi, 0xc01", "mov edx, 8", "syscall",
    "test rax, rax", "jne 9f",
    "mov eax, 2", "mov edi, 8", "mov esi, 1", "syscall", "cmp rax, 3", "jne 9f",
    "mov eax, 1", "mov edi, 0x10", "syscall",
    "9:",
    "mov eax, 1", "mov edi, 0x11", "syscall",
    "3:",
    "jmp 3b",
    "map_frame_end:",
    ".popsection",
);

unsafe extern "C" {
    static map_frame_start: u8;
    static map_frame_end: u8;
}

/// Page-aligned backing for kernel and user carving.
#[repr(align(4096))]
struct Backing<const N: usize>([u8; N]);
static mut KERNEL_UNTYPED: Backing<{ 64 * 1024 }> = Backing([0; 64 * 1024]);
static mut USER_UNTYPED_BACKING: Backing<{ 64 * 1024 }> = Backing([0; 64 * 1024]);
/// The untyped region the thread retypes from; static so its capability
/// outlives the syscalls that name it.
static mut USER_UNTYPED: Option<UntypedRegion> = None;

const KSTACK_SIZE: usize = 4096 * 4;
#[repr(align(16))]
struct KernelStack(#[allow(dead_code)] [u8; KSTACK_SIZE]);
static mut KSTACK: KernelStack = KernelStack([0; KSTACK_SIZE]);

static mut TCB: Tcb = Tcb::new();
static mut CSPACE: Option<KernelCapSpace> = None;

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    serial_print!("map_frame::thread_maps_its_own_page...\t");

    jos::init();
    syscall::init_syscall();

    // SAFETY: boot.s identity-maps the first 1 GiB; called once here.
    let mut frames = unsafe { BootstrapFrameAllocator::new(info_ptr) };
    // SAFETY: page-aligned static backing, handed out once.
    let mut untyped =
        unsafe { UntypedRegion::new(&mut (*core::ptr::addr_of_mut!(KERNEL_UNTYPED)).0) };
    // SAFETY: untyped region is freshly initialized; called once before mappings.
    let mut vspace = unsafe { VSpace::new(&mut untyped).expect("vspace") };

    let code_frame = frames.allocate_frame().expect("code frame");
    let stack_frame = frames.allocate_frame().expect("stack frame");
    let start = core::ptr::addr_of!(map_frame_start);
    let len = core::ptr::addr_of!(map_frame_end) as usize - start as usize;
    assert!(len <= 4096, "user program must fit one page");
    // SAFETY: the symbols bound the program emitted above; the code frame is
    // fresh and identity-mapped.
    unsafe {
        core::ptr::copy_nonoverlapping(start, code_frame.start_address().as_u64() as *mut u8, len);
    }
    let code = PteFlags::PRESENT | PteFlags::USER;
    let data = PteFlags::PRESENT | PteFlags::WRITABLE | PteFlags::USER | PteFlags::NO_EXECUTE;
    // SAFETY: fresh frames at distinct user pages.
    unsafe {
        vspace
            .map_page(&mut untyped, usermode::USER_CODE_ADDR, code_frame.start_address().as_u64(), code)
            .expect("map code");
        vspace
            .map_page(&mut untyped, usermode::USER_STACK_ADDR, stack_frame.start_address().as_u64(), data)
            .expect("map stack");
    }

    // SAFETY: the statics are written once here, before any syscall reads them.
    let tcb_ptr = unsafe {
        USER_UNTYPED = Some(UntypedRegion::new(&mut (*core::ptr::addr_of_mut!(USER_UNTYPED_BACKING)).0));
        let user_untyped = (*core::ptr::addr_of_mut!(USER_UNTYPED)).as_mut().unwrap().as_object_id();
        let mut cspace = KernelCapSpace::new();
        cspace.insert_at(0, vspace.root(), Rights::all()).expect("vspace cap");
        cspace.insert_at(1, user_untyped, Rights::all()).expect("untyped cap");
        CSPACE = Some(cspace);

        let tcb = core::ptr::addr_of_mut!(TCB);
        (*tcb).kernel_stack_top = core::ptr::addr_of!(KSTACK) as u64 + KSTACK_SIZE as u64;
        (*tcb).cspace_ptr = (*core::ptr::addr_of_mut!(CSPACE)).as_mut().unwrap() as *mut KernelCapSpace;
        tcb
    };

    x86_64::instructions::interrupts::disable();
    // SAFETY: tcb_ptr is a live static; ring 0; interrupts disabled.
    unsafe { cpu_local::switch_to(tcb_ptr) };
    // SAFETY: VSpace::new cloned the kernel's root entries.
    unsafe { vspace.activate() };
    // SAFETY: pages mapped; init and init_syscall ran; switch_to installed the
    // thread's kernel stack, CSpace, and TCB.
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
