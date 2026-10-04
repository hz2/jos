// tests/blocking_ipc.rs
//
// exercises the blocking IPC rendezvous (syscalls 6 and 7).
//
// setup: two TCBs share one VSpace and one CSpace. each has the endpoint at
// slot 0. thread A calls SYS_IPC_RECV_BLOCKING and parks (no sender is ready).
// the timer fires and switches to thread B. thread B calls SYS_IPC_SEND_BLOCKING
// with word=0x42; the send path finds thread A in BLOCKED_RECVS, delivers the
// word to A's saved context (rax=0x42), marks A ready, and returns. the timer
// later switches to thread A, which resumes after the syscall instruction with
// rax=0x42, verifies the value, and exits with SYS_EXIT(0x10) = success.
//
// this proves: park-on-recv-first, wake-on-send, timer-resume-from-blocked-idle.
#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

use jos::cap::{KernelCapSpace, Tcb, UntypedRegion};
use jos::cpu_local;
use jos::memory::BootstrapFrameAllocator;
use jos::vspace::VSpace;
use jos::{gdt, sched, serial_print, syscall, usermode};
use jos_core::cap_rights::Rights;
use jos_core::pte::PteFlags;
use x86_64::VirtAddr;
use x86_64::structures::paging::FrameAllocator;

/// Thread A: blocking recv on cap slot 0, verify the word is 0x42, exit success.
///   b8 07 00 00 00   mov eax, 7          SYS_IPC_RECV_BLOCKING
///   bf 00 00 00 00   mov edi, 0          cap_slot = 0
///   0f 05            syscall             -> rax = received word
///   48 83 f8 42      cmp rax, 0x42
///   75 0c            jne +12             if wrong, jump to failure exit
///   b8 01 00 00 00   mov eax, 1          SYS_EXIT
///   bf 10 00 00 00   mov edi, 0x10       success
///   0f 05            syscall
///   b8 01 00 00 00   mov eax, 1          SYS_EXIT (failure path, offset 30)
///   bf 11 00 00 00   mov edi, 0x11       non-success exit code
///   0f 05            syscall
///   eb fe            jmp -2              backstop.
static THREAD_A_PROGRAM: [u8; 44] = [
    0xb8, 0x07, 0x00, 0x00, 0x00, // mov eax, 7
    0xbf, 0x00, 0x00, 0x00, 0x00, // mov edi, 0
    0x0f, 0x05,                   // syscall
    0x48, 0x83, 0xf8, 0x42,       // cmp rax, 0x42
    0x75, 0x0c,                   // jne +12  (-> offset 30 = failure)
    0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0xbf, 0x10, 0x00, 0x00, 0x00, // mov edi, 0x10
    0x0f, 0x05,                   // syscall  (success exit)
    0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1       <- offset 30
    0xbf, 0x11, 0x00, 0x00, 0x00, // mov edi, 0x11
    0x0f, 0x05,                   // syscall  (failure exit)
    0xeb, 0xfe,                   // jmp -2
];

/// Thread B: blocking send 0x42 to cap slot 0, then spin.
///   b8 06 00 00 00   mov eax, 6          SYS_IPC_SEND_BLOCKING
///   bf 00 00 00 00   mov edi, 0          cap_slot = 0
///   be 42 00 00 00   mov esi, 0x42       word = 0x42
///   0f 05            syscall
///   eb fe            jmp -2              spin (thread A exits the test).
static THREAD_B_PROGRAM: [u8; 19] = [
    0xb8, 0x06, 0x00, 0x00, 0x00, // mov eax, 6
    0xbf, 0x00, 0x00, 0x00, 0x00, // mov edi, 0
    0xbe, 0x42, 0x00, 0x00, 0x00, // mov esi, 0x42
    0x0f, 0x05,                   // syscall
    0xeb, 0xfe,                   // jmp -2
];

const B_CODE_ADDR: u64 = usermode::USER_BASE + 0x2000;
const B_STACK_ADDR: u64 = usermode::USER_BASE + 0x3000;
const B_STACK_TOP: u64 = B_STACK_ADDR + 0x1000;

static INFO_PTR: AtomicU32 = AtomicU32::new(0);

const UNTYPED_SIZE: usize = 256 * 1024;
#[repr(align(4096))]
struct UntypedBacking([u8; UNTYPED_SIZE]);
static mut UNTYPED: UntypedBacking = UntypedBacking([0; UNTYPED_SIZE]);

const KSTACK_SIZE: usize = 4096 * 4;
#[repr(align(16))]
struct KernelStack(#[allow(dead_code)] [u8; KSTACK_SIZE]);
static mut KSTACK_A: KernelStack = KernelStack([0; KSTACK_SIZE]);
static mut KSTACK_B: KernelStack = KernelStack([0; KSTACK_SIZE]);

static mut TCB_A: Option<Tcb> = None;
static mut TCB_B: Option<Tcb> = None;
/// One CSpace shared by both threads; endpoint at slot 0.
static mut CSPACE: Option<KernelCapSpace> = None;

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    serial_print!("blocking_ipc::recv_first_then_send_wakes_parked_thread...\t");
    INFO_PTR.store(info_ptr, Ordering::SeqCst);

    jos::init();
    syscall::init_syscall();

    // SAFETY: boot.s identity-maps the first 1 GiB; called once here.
    let mut frame_allocator = unsafe { BootstrapFrameAllocator::new(info_ptr) };
    // SAFETY: page-aligned static backing, handed out once.
    let mut untyped =
        unsafe { UntypedRegion::new(&mut (*core::ptr::addr_of_mut!(UNTYPED)).0) };

    // SAFETY: untyped region is freshly initialized; called once before mappings.
    let mut vspace = unsafe { VSpace::new(&mut untyped).expect("vspace") };

    let code_a = frame_allocator.allocate_frame().expect("code frame a");
    let stack_a = frame_allocator.allocate_frame().expect("stack frame a");
    let code_b = frame_allocator.allocate_frame().expect("code frame b");
    let stack_b = frame_allocator.allocate_frame().expect("stack frame b");

    // SAFETY: identity-mapped frames; src is a static byte slice; len fits the frame.
    unsafe {
        core::ptr::copy_nonoverlapping(
            THREAD_A_PROGRAM.as_ptr(),
            code_a.start_address().as_u64() as *mut u8,
            THREAD_A_PROGRAM.len(),
        );
        core::ptr::copy_nonoverlapping(
            THREAD_B_PROGRAM.as_ptr(),
            code_b.start_address().as_u64() as *mut u8,
            THREAD_B_PROGRAM.len(),
        );
    }

    let rw_user = PteFlags::PRESENT | PteFlags::WRITABLE | PteFlags::USER;
    // SAFETY: frames allocated above; virtual addresses are distinct user-space slots.
    unsafe {
        vspace
            .map_page(&mut untyped, usermode::USER_CODE_ADDR, code_a.start_address().as_u64(), rw_user)
            .expect("map a code");
        vspace
            .map_page(&mut untyped, usermode::USER_STACK_ADDR, stack_a.start_address().as_u64(), rw_user)
            .expect("map a stack");
        vspace
            .map_page(&mut untyped, B_CODE_ADDR, code_b.start_address().as_u64(), rw_user)
            .expect("map b code");
        vspace
            .map_page(&mut untyped, B_STACK_ADDR, stack_b.start_address().as_u64(), rw_user)
            .expect("map b stack");
    }

    let kstack_a_top =
        VirtAddr::new(core::ptr::addr_of!(KSTACK_A) as u64 + KSTACK_SIZE as u64);
    let kstack_b_top =
        VirtAddr::new(core::ptr::addr_of!(KSTACK_B) as u64 + KSTACK_SIZE as u64);

    let sel = gdt::selectors();
    let user_cs = u64::from(sel.user_code.0);
    let user_ss = u64::from(sel.user_data.0);

    // SAFETY: statics written once before context switches run.
    let (tcb_a_ptr, tcb_b_ptr) = unsafe {
        // retype an endpoint and install it at slot 0 in the shared CSpace.
        let endpoint_id = untyped.retype_endpoint().expect("endpoint");
        let mut cspace = KernelCapSpace::new();
        cspace.insert_at(0, endpoint_id, Rights::all()).expect("cap insert");
        CSPACE = Some(cspace);
        let cspace_ptr = (*core::ptr::addr_of_mut!(CSPACE)).as_mut().unwrap() as *mut KernelCapSpace;

        let mut ta = Tcb::new();
        ta.kernel_stack_top = kstack_a_top.as_u64();
        ta.cspace_ptr = cspace_ptr;
        // thread A starts at USER_CODE_ADDR with a fresh user stack.
        // SavedContext for Thread A is not pre-populated since it enters via
        // enter_user_mode, not the scheduler iretq path.
        TCB_A = Some(ta);

        let mut tb = Tcb::new();
        tb.kernel_stack_top = kstack_b_top.as_u64();
        tb.cspace_ptr = cspace_ptr;
        // thread B's context pre-populated so the scheduler can iretq into it.
        tb.context.rip = B_CODE_ADDR;
        tb.context.rsp = B_STACK_TOP;
        tb.context.rflags = 0x0000_0202; // IF=1, reserved bit 1
        tb.context.cs = user_cs;
        tb.context.ss = user_ss;
        TCB_B = Some(tb);

        (
            (*core::ptr::addr_of_mut!(TCB_A)).as_mut().unwrap() as *mut Tcb,
            (*core::ptr::addr_of_mut!(TCB_B)).as_mut().unwrap() as *mut Tcb,
        )
    };

    x86_64::instructions::interrupts::disable();
    // SAFETY: TCB pointers are live statics; interrupts are disabled above.
    let id_a = unsafe { sched::register_thread(tcb_a_ptr) };
    let id_b = unsafe { sched::register_thread(tcb_b_ptr) };
    sched::mark_ready(id_b); // B waits in the ready set; A runs first
    sched::set_current(id_a);

    // SAFETY: tcb_a is live; ring 0; interrupts disabled.
    unsafe { cpu_local::switch_to(tcb_a_ptr); }

    // SAFETY: VSpace cloned the kernel PML4 entries.
    unsafe { vspace.activate(); }

    // drop into ring-3 at thread A's entry. thread A will call
    // SYS_IPC_RECV_BLOCKING, park (no sender ready yet), and yield. the timer
    // fires, switches to thread B which sends 0x42, wakes thread A, and spins.
    // the timer switches back to thread A which verifies rax==0x42 and exits.
    // SAFETY: pages mapped; syscall/init ran; switch_to installed A's kernel stack.
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
