//! A thread creates and starts another thread from capabilities.
//!
//! The creator holds a `VSpace` capability to its own address space (slot 0)
//! and an untyped region (slot 1). It retypes a TCB, an empty CNode, and a stack
//! frame, maps the frame, checks each refusal (start before configure, a
//! non-CNode as the CSpace, a kernel entry address, a second start, configuring
//! a started thread), then configures and starts the child at a label in its
//! own code page. The child proves its stack works and that it runs in its own,
//! empty capability space, then exits with success; the creator spins, so the
//! test only passes if the child really ran.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use jos::cap::{KernelCapSpace, Tcb, UntypedRegion};
use jos::memory::BootstrapFrameAllocator;
use jos::vspace::VSpace;
use jos::{cpu_local, sched, serial_print, syscall, usermode};
use jos_core::cap_rights::Rights;
use jos_core::pte::PteFlags;
use x86_64::VirtAddr;
use x86_64::structures::paging::FrameAllocator;

// numeric labels avoid symbol clashes; backward refs avoid 0/1 (intel syntax
// would read `1b` as a binary literal). syscall errors are IpcSyscallError
// codes. the child's stack is the frame mapped at 0x200000003000.
core::arch::global_asm!(
    ".pushsection .rodata.tcb_start_prog, \"a\"",
    "tcb_start_start:",
    // retype a TCB (type 4) into slot 2, a CNode (0xc01) into 3, a frame into 4
    "mov eax, 4", "mov edi, 1", "mov esi, 4", "mov edx, 2", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 4", "mov edi, 1", "mov esi, 0xc01", "mov edx, 3", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 4", "mov edi, 1", "mov esi, 5", "mov edx, 4", "syscall", "test rax, rax", "jne 9f",
    // map the frame writable as the child's stack
    "mov eax, 15", "xor edi, edi", "mov esi, 4", "mov rdx, 0x200000003001", "syscall",
    "test rax, rax", "jne 9f",
    // start before configure: NotConfigured (23)
    "mov eax, 19", "mov edi, 2", "lea rsi, [rip + 5f]", "mov rdx, 0x200000004000", "syscall",
    "cmp rax, 23", "jne 9f",
    // a VSpace where the CNode belongs: NotCNode (21)
    "mov eax, 17", "mov edi, 2", "xor esi, esi", "xor edx, edx", "syscall",
    "cmp rax, 21", "jne 9f",
    // configure with the empty CNode and our own address space
    "mov eax, 17", "mov edi, 2", "mov esi, 3", "xor edx, edx", "syscall",
    "test rax, rax", "jne 9f",
    // the child's IPC buffer: a non-frame is refused (NotFrame = 9), the frame
    // is accepted
    "mov eax, 18", "mov edi, 2", "xor esi, esi", "syscall", "cmp rax, 9", "jne 9f",
    "mov eax, 18", "mov edi, 2", "mov esi, 4", "syscall", "test rax, rax", "jne 9f",
    // a kernel entry address: BadAddress (13)
    "mov eax, 19", "mov edi, 2", "mov rsi, 0xffff800000000000", "mov rdx, 0x200000004000",
    "syscall", "cmp rax, 13", "jne 9f",
    // start the child
    "mov eax, 19", "mov edi, 2", "lea rsi, [rip + 5f]", "mov rdx, 0x200000004000", "syscall",
    "test rax, rax", "jne 9f",
    // a second start, and configuring a started thread: AlreadyStarted (22)
    "mov eax, 19", "mov edi, 2", "lea rsi, [rip + 5f]", "mov rdx, 0x200000004000", "syscall",
    "cmp rax, 22", "jne 9f",
    "mov eax, 17", "mov edi, 2", "mov esi, 3", "xor edx, edx", "syscall",
    "cmp rax, 22", "jne 9f",
    "mov eax, 18", "mov edi, 2", "mov esi, 4", "syscall", "cmp rax, 22", "jne 9f",
    // wait for the child to end the test
    "2:",
    "jmp 2b",
    // the child: its stack works, and its slot 0 is empty (BadCap = 1), where
    // the creator's slot 0 would answer NotFrame
    "5:",
    "push 0x55", "pop rax", "cmp rax, 0x55", "jne 9f",
    "mov eax, 12", "xor edi, edi", "syscall", "cmp rax, 1", "jne 9f",
    "mov eax, 1", "mov edi, 0x10", "syscall",
    "9:",
    "mov eax, 1", "mov edi, 0x11", "syscall",
    "3:",
    "jmp 3b",
    "tcb_start_end:",
    ".popsection",
);

unsafe extern "C" {
    static tcb_start_start: u8;
    static tcb_start_end: u8;
}

/// Page-aligned backing for kernel and user carving.
#[repr(align(4096))]
struct Backing<const N: usize>([u8; N]);
static mut KERNEL_UNTYPED: Backing<{ 64 * 1024 }> = Backing([0; 64 * 1024]);
static mut USER_UNTYPED_BACKING: Backing<{ 128 * 1024 }> = Backing([0; 128 * 1024]);
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
    serial_print!("tcb_start::thread_starts_a_thread...\t");

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
    let start = core::ptr::addr_of!(tcb_start_start);
    let len = core::ptr::addr_of!(tcb_start_end) as usize - start as usize;
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
    // the creator must be a scheduled thread, or the timer never switches to
    // the child it starts.
    // SAFETY: tcb_ptr is a live static; interrupts are disabled.
    let id = unsafe { sched::register_thread(tcb_ptr) };
    sched::set_current(id);
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
