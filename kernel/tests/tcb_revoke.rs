//! Revoking a thread's TCB, `CNode`, or `VSpace` stops the thread for good.
//!
//! The creator holds a `VSpace` capability to its own address space (slot 0)
//! and an untyped region (slot 1), and retypes four TCBs, each with a `CNode`,
//! plus an endpoint. Its children share its address space and report through
//! words in its stack page.
//!
//! 1. Child A spins bumping a counter. Revoking A's TCB must freeze it.
//! 2. Child B parks in a receive. Revoking B's `CNode` must stop B and drop its
//!    parked receive, so
//! 3. the next message goes to a fresh receiver C, not to the dead B.
//! 4. Revoking a minted copy of C's TCB capability must leave C running: it
//!    still receives a second message.
//! 5. Child D spins bumping a counter. Revoking the address space it runs in
//!    must freeze it.
//!
//! The creator then exits with success; any failed check exits with failure.
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
// would read `1b` as a binary literal). r12 is the report page (the creator's
// stack page): +0 A's counter, +8 B's "about to receive" flag, +0x10 what B
// received, +0x18 what C received, +0x20 D's counter. children start with
// zeroed registers and never touch their stacks.
core::arch::global_asm!(
    ".pushsection .rodata.tcb_revoke_prog, \"a\"",
    "tcb_revoke_start:",
    "mov r12, 0x200000001000",
    // TCBs (type 4) into 2, 4, 6, 9; CNodes (0xc01) into 3, 5, 7, 10; an
    // endpoint (type 0) into 8
    "mov eax, 4", "mov edi, 1", "mov esi, 4", "mov edx, 2", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 4", "mov edi, 1", "mov esi, 0xc01", "mov edx, 3", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 4", "mov edi, 1", "mov esi, 4", "mov edx, 4", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 4", "mov edi, 1", "mov esi, 0xc01", "mov edx, 5", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 4", "mov edi, 1", "mov esi, 4", "mov edx, 6", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 4", "mov edi, 1", "mov esi, 0xc01", "mov edx, 7", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 4", "mov edi, 1", "xor esi, esi", "mov edx, 8", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 4", "mov edi, 1", "mov esi, 4", "mov edx, 9", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 4", "mov edi, 1", "mov esi, 0xc01", "mov edx, 10", "syscall", "test rax, rax", "jne 9f",
    // 1: start A, wait until it runs, revoke its TCB; its counter must freeze
    "mov eax, 17", "mov edi, 2", "mov esi, 3", "xor edx, edx", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 19", "mov edi, 2", "lea rsi, [rip + 51f]", "mov rdx, 0x200000001800", "syscall",
    "test rax, rax", "jne 9f",
    "20:", "pause", "cmp qword ptr [r12], 0", "je 20b",
    "mov eax, 21", "mov edi, 2", "syscall", "cmp rax, 1", "jne 9f",
    "mov rbx, [r12]",
    "call 70f",
    "cmp rbx, [r12]", "jne 9f",
    // 2: copy the endpoint, READ only, into slot 0 of B's and C's CNodes
    "mov eax, 20", "mov edi, 5", "mov esi, 8", "mov edx, 0x10000", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 20", "mov edi, 7", "mov esi, 8", "mov edx, 0x10000", "syscall", "test rax, rax", "jne 9f",
    // start B, let it park in its receive, then revoke its CNode
    "mov eax, 17", "mov edi, 4", "mov esi, 5", "xor edx, edx", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 19", "mov edi, 4", "lea rsi, [rip + 52f]", "mov rdx, 0x200000001800", "syscall",
    "test rax, rax", "jne 9f",
    "22:", "pause", "cmp qword ptr [r12 + 8], 0", "je 22b",
    "call 70f",
    "mov eax, 21", "mov edi, 5", "syscall", "cmp rax, 1", "jne 9f",
    // 3: start C; a blocking send must reach C, and B must get nothing
    "mov eax, 17", "mov edi, 6", "mov esi, 7", "xor edx, edx", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 19", "mov edi, 6", "lea rsi, [rip + 53f]", "mov rdx, 0x200000001800", "syscall",
    "test rax, rax", "jne 9f",
    "mov eax, 6", "mov edi, 8", "mov esi, 0x77", "syscall", "test rax, rax", "jne 9f",
    "call 72f", "24:", "cmp qword ptr [r12 + 0x18], 0x77", "je 25f", "call 73f", "jb 24b",
    "jmp 9f",
    "25:",
    "cmp qword ptr [r12 + 0x10], 0", "jne 9f",
    // 4: mint a copy of C's TCB capability and revoke only the copy; C must
    // still receive
    "mov eax, 8", "mov edi, 6", "mov esi, 0xff", "xor edx, edx", "syscall",
    "mov rdi, rax", "mov eax, 21", "syscall", "cmp rax, 1", "jne 9f",
    "mov eax, 6", "mov edi, 8", "mov esi, 0x78", "syscall", "test rax, rax", "jne 9f",
    "call 72f", "26:", "cmp qword ptr [r12 + 0x18], 0x78", "je 27f", "call 73f", "jb 26b",
    "jmp 9f",
    "27:",
    // 5: start D, wait until it runs, revoke the address space; it must freeze
    "mov eax, 17", "mov edi, 9", "mov esi, 10", "xor edx, edx", "syscall", "test rax, rax", "jne 9f",
    "mov eax, 19", "mov edi, 9", "lea rsi, [rip + 54f]", "mov rdx, 0x200000001800", "syscall",
    "test rax, rax", "jne 9f",
    "28:", "pause", "cmp qword ptr [r12 + 0x20], 0", "je 28b",
    "mov eax, 21", "xor edi, edi", "syscall", "cmp rax, 1", "jne 9f",
    "mov rbx, [r12 + 0x20]",
    "call 70f",
    "cmp rbx, [r12 + 0x20]", "jne 9f",
    "mov eax, 1", "mov edi, 0x10", "syscall",
    "9:",
    "mov eax, 1", "mov edi, 0x11", "syscall",
    "3:",
    "jmp 3b",
    // time is read from the tsc, not counted in loop iterations, so a wait spans
    // several timer ticks on any accelerator (a tcg loop runs far slower than a
    // kvm one). 70: spin for 2^31 cycles. 72: start a 2^31-cycle deadline in
    // r14; 73: set CF while it has not passed. both clobber rax and rdx.
    "70:", "call 72f",
    "71:", "pause", "call 73f", "jb 71b",
    "ret",
    "72:", "rdtsc", "shl rdx, 32", "or rax, rdx", "mov r14, rax", "ret",
    "73:", "rdtsc", "shl rdx, 32", "or rax, rdx", "sub rax, r14",
    "mov rdx, 0x80000000", "cmp rax, rdx", "ret",
    // A and D: bump a counter forever
    "51:", "mov r12, 0x200000001000",
    "31:", "lock inc qword ptr [r12]", "jmp 31b",
    "54:", "mov r12, 0x200000001000",
    "34:", "lock inc qword ptr [r12 + 0x20]", "jmp 34b",
    // B: flag, then one receive on slot 0; record what arrives
    "52:", "mov r12, 0x200000001000",
    "mov qword ptr [r12 + 8], 1",
    "mov eax, 7", "xor edi, edi", "syscall", "mov [r12 + 0x10], rax",
    "32:", "jmp 32b",
    // C: receive on slot 0 forever, recording each word
    "53:", "mov r12, 0x200000001000",
    "33:", "mov eax, 7", "xor edi, edi", "syscall", "mov [r12 + 0x18], rax", "jmp 33b",
    "tcb_revoke_end:",
    ".popsection",
);

unsafe extern "C" {
    static tcb_revoke_start: u8;
    static tcb_revoke_end: u8;
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
    serial_print!("tcb_revoke::revoked_threads_stop...\t");

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
    // SAFETY: the frame is fresh and identity-mapped; the children report
    // through words in it, which must start at zero.
    unsafe { core::ptr::write_bytes(stack_frame.start_address().as_u64() as *mut u8, 0, 4096) };
    let start = core::ptr::addr_of!(tcb_revoke_start);
    let len = core::ptr::addr_of!(tcb_revoke_end) as usize - start as usize;
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
        CSPACE = Some(KernelCapSpace::new());
        let cspace = (*core::ptr::addr_of_mut!(CSPACE)).as_mut().unwrap();
        // register while empty, so copies out of it stay revocable across spaces.
        jos::cap::register_cspace(core::ptr::from_mut(cspace)).expect("register cspace");
        cspace.insert_at(0, vspace.root(), Rights::all()).expect("vspace cap");
        cspace.insert_at(1, user_untyped, Rights::all()).expect("untyped cap");

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
