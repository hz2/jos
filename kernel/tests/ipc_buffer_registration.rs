//! A thread registers its IPC buffer from a Frame capability (`SetIpcBuffer`).
//!
//! The kernel carves a Frame from untyped memory, maps it into the thread's
//! address space (standing in for a root task), and hands the thread:
//! slot 0 an endpoint, slot 1 the frame (`READ | WRITE`), slot 2 the same frame
//! minted read-only, and slot 3 an untyped region to retype from. The program
//! checks that registration rejects a non-frame and a read-only frame, that an
//! unregistered thread's buffer page is never written by the kernel, that a
//! registered frame carries buffer words through a send and receive, and that a
//! frame the thread retypes itself can be registered.
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

/// User address where the kernel maps the registered frame.
const BUFFER_ADDR: u64 = usermode::USER_BASE + 0x5000;

// numeric labels avoid symbol clashes; backward refs avoid 0/1 (intel syntax
// would read `1b` as a binary literal).
core::arch::global_asm!(
    ".pushsection .rodata.ipc_buffer_registration_prog, \"a\"",
    "ipc_buffer_registration_start:",
    "mov r15, 0x200000005000",
    // an endpoint is not a frame (NotFrame = 9)
    "mov eax, 12",
    "xor edi, edi",
    "syscall",
    "cmp rax, 9",
    "jne 9f",
    // a read-only frame cannot be a buffer (Denied = 2)
    "mov eax, 12",
    "mov edi, 2",
    "syscall",
    "cmp rax, 2",
    "jne 9f",
    // unregistered: words in the page are not sent, and nothing is written back
    "mov qword ptr [r15 + 8], 1",
    "mov qword ptr [r15 + 16], 2",
    "mov qword ptr [r15 + 24], 3",
    "mov eax, 2",
    "xor edi, edi",
    "mov esi, 0x55",
    "syscall",
    "test rax, rax",
    "jne 9f",
    "mov eax, 3",
    "xor edi, edi",
    "syscall",
    "cmp rax, 0x55",
    "jne 9f",
    "cmp qword ptr [r15], 0",
    "jne 9f",
    "cmp qword ptr [r15 + 8], 1",
    "jne 9f",
    // register the mapped frame
    "mov eax, 12",
    "mov edi, 1",
    "syscall",
    "test rax, rax",
    "jne 9f",
    // now words 1 to 3 travel through it
    "mov qword ptr [r15 + 8], 4",
    "mov qword ptr [r15 + 16], 5",
    "mov qword ptr [r15 + 24], 6",
    "mov eax, 2",
    "xor edi, edi",
    "mov esi, 0x66",
    "syscall",
    "test rax, rax",
    "jne 9f",
    "mov qword ptr [r15 + 8], 0",
    "mov qword ptr [r15 + 16], 0",
    "mov qword ptr [r15 + 24], 0",
    "mov eax, 3",
    "xor edi, edi",
    "syscall",
    "cmp rax, 0x66",
    "jne 9f",
    "cmp qword ptr [r15], 0x66",
    "jne 9f",
    "cmp qword ptr [r15 + 8], 4",
    "jne 9f",
    "cmp qword ptr [r15 + 16], 5",
    "jne 9f",
    "cmp qword ptr [r15 + 24], 6",
    "jne 9f",
    // retype(untyped 3, FRAME = 5, dest 4), then register that frame
    "mov eax, 4",
    "mov edi, 3",
    "mov esi, 5",
    "mov edx, 4",
    "syscall",
    "test rax, rax",
    "jne 9f",
    "mov eax, 12",
    "mov edi, 4",
    "syscall",
    "test rax, rax",
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
    "ipc_buffer_registration_end:",
    ".popsection",
);

unsafe extern "C" {
    static ipc_buffer_registration_start: u8;
    static ipc_buffer_registration_end: u8;
}

/// Page-aligned backing for the kernel's own carving (tables and the frame).
#[repr(align(4096))]
struct Backing<const N: usize>([u8; N]);
static mut KERNEL_UNTYPED: Backing<{ 64 * 1024 }> = Backing([0; 64 * 1024]);
static mut USER_UNTYPED_BACKING: Backing<{ 16 * 1024 }> = Backing([0; 16 * 1024]);
/// The untyped region the thread retypes from; static so its capability outlives
/// the syscalls that name it.
static mut USER_UNTYPED: Option<UntypedRegion> = None;

const KSTACK_SIZE: usize = 4096 * 4;
#[repr(align(16))]
struct KernelStack(#[allow(dead_code)] [u8; KSTACK_SIZE]);
static mut KSTACK: KernelStack = KernelStack([0; KSTACK_SIZE]);

static mut TCB: Option<Tcb> = None;
static mut CSPACE: Option<KernelCapSpace> = None;

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    serial_print!("ipc_buffer_registration::frame_cap_becomes_buffer...\t");

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
    let buffer = untyped.retype_frame().expect("frame");
    let start = core::ptr::addr_of!(ipc_buffer_registration_start);
    let len = core::ptr::addr_of!(ipc_buffer_registration_end) as usize - start as usize;
    assert!(len <= 4096, "user program must fit one page");
    // SAFETY: the symbols bound the program emitted above; the code frame is
    // fresh and identity-mapped.
    unsafe {
        core::ptr::copy_nonoverlapping(start, code_frame.start_address().as_u64() as *mut u8, len);
    }

    let code = PteFlags::PRESENT | PteFlags::USER;
    let data = PteFlags::PRESENT | PteFlags::WRITABLE | PteFlags::USER | PteFlags::NO_EXECUTE;
    // SAFETY: fresh frames and the carved Frame object, at distinct user pages.
    unsafe {
        vspace
            .map_page(&mut untyped, usermode::USER_CODE_ADDR, code_frame.start_address().as_u64(), code)
            .expect("map code");
        vspace
            .map_page(&mut untyped, usermode::USER_STACK_ADDR, stack_frame.start_address().as_u64(), data)
            .expect("map stack");
        vspace
            .map_page(&mut untyped, BUFFER_ADDR, buffer.phys_addr(), data)
            .expect("map buffer frame");
    }

    let endpoint = untyped.retype_endpoint().expect("endpoint");
    // SAFETY: the statics are written once here, before any syscall reads them.
    let tcb_ptr = unsafe {
        USER_UNTYPED = Some(UntypedRegion::new(&mut (*core::ptr::addr_of_mut!(USER_UNTYPED_BACKING)).0));
        let user_untyped = (*core::ptr::addr_of_mut!(USER_UNTYPED)).as_mut().unwrap().as_object_id();

        let mut cspace = KernelCapSpace::new();
        cspace.insert_at(0, endpoint, Rights::all()).expect("endpoint cap");
        let frame_cap = cspace.insert_at(1, buffer, Rights::READ_WRITE).expect("frame cap");
        let read_only = cspace.mint(frame_cap, Rights::READ).expect("read-only frame cap");
        assert_eq!(read_only.slot(), 2, "read-only frame cap must land in slot 2");
        cspace.insert_at(3, user_untyped, Rights::all()).expect("untyped cap");
        CSPACE = Some(cspace);

        let mut tcb = Tcb::new();
        tcb.kernel_stack_top = core::ptr::addr_of!(KSTACK) as u64 + KSTACK_SIZE as u64;
        tcb.cspace_ptr = (*core::ptr::addr_of_mut!(CSPACE)).as_mut().unwrap() as *mut KernelCapSpace;
        TCB = Some(tcb);
        (*core::ptr::addr_of_mut!(TCB)).as_mut().unwrap() as *mut Tcb
    };

    x86_64::instructions::interrupts::disable();
    // SAFETY: tcb_ptr is a live static; ring 0; interrupts disabled.
    unsafe { cpu_local::switch_to(tcb_ptr) };
    // SAFETY: VSpace::new cloned the kernel PML4 entries.
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
