//! Shared harness for kernel tests that run two ring-3 threads.
//!
//! Both threads share one `VSpace` and one `CSpace`. Thread A is entered first
//! through `enter_user_mode`; thread B waits in the ready set and is entered by
//! the scheduler's `iretq` on the first timer tick that switches to it. A zeroed
//! page at [`SHARED_ADDR`] is mapped read-write for both.
//!
//! When a test needs both threads' checks to pass and either may finish last,
//! each program ends with `lock inc qword ptr [SHARED_ADDR]` and exits with
//! success only if the counter then reads 2; the other thread spins.

use jos::cap::{KernelCapSpace, Tcb, UntypedRegion};
use jos::cpu_local;
use jos::memory::BootstrapFrameAllocator;
use jos::vspace::VSpace;
use jos::{gdt, sched, syscall, usermode};
use jos_core::pte::PteFlags;
use x86_64::VirtAddr;
use x86_64::structures::paging::{FrameAllocator, PhysFrame};

/// User address of thread B's code page.
pub const B_CODE_ADDR: u64 = usermode::USER_BASE + 0x2000;
/// User address of thread B's stack page.
pub const B_STACK_ADDR: u64 = usermode::USER_BASE + 0x3000;
/// Initial stack pointer for thread B.
pub const B_STACK_TOP: u64 = B_STACK_ADDR + 0x1000;
/// User address of the zeroed data page both threads can read and write.
pub const SHARED_ADDR: u64 = usermode::USER_BASE + 0x4000;

/// The bounds of one ring-3 program emitted by a test's `global_asm!`.
#[derive(Clone, Copy)]
pub struct Program {
    /// Address of the program's first byte.
    pub start: *const u8,
    /// Address one past the program's last byte.
    pub end: *const u8,
}

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
static mut CSPACE: Option<KernelCapSpace> = None;

/// Copies `program` into the identity-mapped `frame`.
///
/// # Safety
///
/// `program` must bound bytes emitted by a `global_asm!`, and `frame` must be
/// freshly allocated and identity-mapped.
unsafe fn load(program: Program, frame: PhysFrame) {
    let len = program.end as usize - program.start as usize;
    assert!(len <= 4096, "user program must fit one page");
    // SAFETY: per this function's contract the source is one emitted program
    // and the destination is an unaliased identity-mapped 4 KiB frame.
    unsafe {
        core::ptr::copy_nonoverlapping(program.start, frame.start_address().as_u64() as *mut u8, len);
    }
}

/// Boots threads A and B and enters ring 3 as thread A. Never returns; the
/// programs end the test through the exit syscall.
///
/// `caps` fills the shared `CSpace`, carving objects from the test's untyped
/// region.
///
/// # Safety
///
/// Call once, from `kernel_main`, with the multiboot `info_ptr` the boot
/// trampoline passed in; `a` and `b` must each bound one emitted program.
pub unsafe fn boot(
    info_ptr: u32,
    a: Program,
    b: Program,
    caps: impl FnOnce(&mut UntypedRegion, &mut KernelCapSpace),
) -> ! {
    jos::init();
    syscall::init_syscall();

    // SAFETY: boot.s identity-maps the first 1 GiB; called once per test.
    let mut frames = unsafe { BootstrapFrameAllocator::new(info_ptr) };
    // SAFETY: page-aligned static backing, handed out once.
    let mut untyped = unsafe { UntypedRegion::new(&mut (*core::ptr::addr_of_mut!(UNTYPED)).0) };
    // SAFETY: untyped region is freshly initialized; called once before mappings.
    let mut vspace = unsafe { VSpace::new(&mut untyped).expect("vspace") };

    let mut frame = || frames.allocate_frame().expect("frame");
    let (code_a, stack_a, code_b, stack_b, shared) = (frame(), frame(), frame(), frame(), frame());
    // SAFETY: a and b bound emitted programs (this function's contract); the
    // frames were just allocated and are identity-mapped. the shared frame is
    // zeroed so the done counter starts at 0.
    unsafe {
        load(a, code_a);
        load(b, code_b);
        core::ptr::write_bytes(shared.start_address().as_u64() as *mut u8, 0, 4096);
    }

    let code = PteFlags::PRESENT | PteFlags::USER;
    let data = PteFlags::PRESENT | PteFlags::WRITABLE | PteFlags::USER | PteFlags::NO_EXECUTE;
    let pages = [
        (usermode::USER_CODE_ADDR, code_a, code),
        (usermode::USER_STACK_ADDR, stack_a, data),
        (B_CODE_ADDR, code_b, code),
        (B_STACK_ADDR, stack_b, data),
        (SHARED_ADDR, shared, data),
    ];
    for (addr, frame, flags) in pages {
        // SAFETY: each frame is fresh and each address is a distinct user page.
        unsafe {
            vspace
                .map_page(&mut untyped, addr, frame.start_address().as_u64(), flags)
                .expect("map user page");
        }
    }

    let kstack_a_top = core::ptr::addr_of!(KSTACK_A) as u64 + KSTACK_SIZE as u64;
    let kstack_b_top = core::ptr::addr_of!(KSTACK_B) as u64 + KSTACK_SIZE as u64;
    let sel = gdt::selectors();

    // SAFETY: statics written once here, before any context switch reads them.
    let (tcb_a_ptr, tcb_b_ptr) = unsafe {
        let mut cspace = KernelCapSpace::new();
        caps(&mut untyped, &mut cspace);
        CSPACE = Some(cspace);
        let cspace_ptr = (*core::ptr::addr_of_mut!(CSPACE)).as_mut().unwrap() as *mut KernelCapSpace;

        let mut ta = Tcb::new();
        ta.kernel_stack_top = kstack_a_top;
        ta.cspace_ptr = cspace_ptr;
        TCB_A = Some(ta);

        let mut tb = Tcb::new();
        tb.kernel_stack_top = kstack_b_top;
        tb.cspace_ptr = cspace_ptr;
        // B is entered by the scheduler's iretq, so its context is pre-filled.
        tb.context.rip = B_CODE_ADDR;
        tb.context.rsp = B_STACK_TOP;
        tb.context.rflags = 0x0000_0202;
        tb.context.cs = u64::from(sel.user_code.0);
        tb.context.ss = u64::from(sel.user_data.0);
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
    sched::mark_ready(id_b);
    sched::set_current(id_a);

    // SAFETY: tcb_a is live; ring 0; interrupts disabled.
    unsafe { cpu_local::switch_to(tcb_a_ptr) };
    // SAFETY: VSpace::new cloned the kernel PML4 entries.
    unsafe { vspace.activate() };
    // SAFETY: pages mapped; init and init_syscall ran; switch_to installed
    // thread A's kernel stack.
    unsafe {
        usermode::enter_user_mode(
            VirtAddr::new(usermode::USER_CODE_ADDR),
            VirtAddr::new(usermode::USER_STACK_TOP),
        );
    }
}
