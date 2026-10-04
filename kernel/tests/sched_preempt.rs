// tests/sched_preempt.rs
//
// proof that the preemptive round-robin scheduler actually fires and switches
// between two ring-3 threads.
//
// setup: two TCBs share one address space. thread A spins in a tight `jmp -2`
// loop indefinitely. thread B calls SYS_EXIT(success) and is never explicitly
// entered from the kernel -- it only runs if the scheduler picks it.
//
// thread B's SavedContext is pre-populated with the correct RIP, RSP, CS, SS,
// and RFLAGS before registration. when the timer fires and preempts thread A,
// the scheduler saves A's context, loads B's pre-populated context into the
// IRQ frame, calls cpu_local::switch_to(tcb_b) so the syscall path uses B's
// kernel stack, and iretq's into B. B runs, calls syscall(SYS_EXIT, 0x10),
// and exits QEMU with success.
//
// if the scheduler never fires (timer not delivering, preemption disabled, or
// context switch broken), thread A spins forever and the test times out.
#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

use jos::cap::{KernelCapSpace, Tcb, UntypedRegion};
use jos::cpu_local;
use jos::memory::BootstrapFrameAllocator;
use jos::vspace::VSpace;
use jos::{gdt, sched, serial_print, syscall, usermode};
use jos_core::pte::PteFlags;
use x86_64::VirtAddr;
use x86_64::structures::paging::FrameAllocator;

// thread A: spin forever. only exits if the test times out (QEMU watchdog).
static THREAD_A_PROGRAM: [u8; 2] = [
    0xeb, 0xfe, // jmp -2
];

// thread B: call SYS_EXIT(0x10) -> success.
//   b8 01 00 00 00   mov eax, 1      (SYS_EXIT)
//   bf 10 00 00 00   mov edi, 0x10   (success exit code)
//   0f 05            syscall
//   eb fe            jmp -2          (backstop; syscall does not return)
static THREAD_B_PROGRAM: [u8; 14] = [
    0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x10, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xeb, 0xfe,
];

// thread B code and stack live above thread A's window so they share one VSpace.
const B_CODE_ADDR: u64 = usermode::USER_BASE + 0x2000;
const B_STACK_ADDR: u64 = usermode::USER_BASE + 0x3000;
const B_STACK_TOP: u64 = B_STACK_ADDR + 0x1000;

static INFO_PTR: AtomicU32 = AtomicU32::new(0);

const UNTYPED_SIZE: usize = 128 * 1024;
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
// one CSpace is enough; SYS_EXIT does not touch capabilities.
static mut CSPACE: Option<KernelCapSpace> = None;

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    serial_print!("sched_preempt::timer_preempts_and_switches_thread...\t");
    INFO_PTR.store(info_ptr, Ordering::SeqCst);

    jos::init();
    syscall::init_syscall();

    // SAFETY: boot.s identity-maps the first 1 GiB; called once here.
    let mut frame_allocator = unsafe { BootstrapFrameAllocator::new(info_ptr) };
    // SAFETY: handed out once; page-aligned static backing.
    let mut untyped =
        unsafe { UntypedRegion::new(&mut (*core::ptr::addr_of_mut!(UNTYPED)).0) };

    // build one shared VSpace for both threads.
    // SAFETY: carves page table pages from untyped; CR3 not yet switched.
    let mut vspace = unsafe { VSpace::new(&mut untyped).expect("vspace") };

    // allocate physical frames for code and stacks.
    let code_a = frame_allocator.allocate_frame().expect("code frame a");
    let stack_a = frame_allocator.allocate_frame().expect("stack frame a");
    let code_b = frame_allocator.allocate_frame().expect("code frame b");
    let stack_b = frame_allocator.allocate_frame().expect("stack frame b");

    // copy programs into their physical frames (identity-mapped so phys == virt).
    // SAFETY: frames are freshly allocated and exclusively owned; payloads fit.
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
    // SAFETY: fresh frames; user window is empty in this new VSpace.
    unsafe {
        vspace
            .map_page(
                &mut untyped,
                usermode::USER_CODE_ADDR,
                code_a.start_address().as_u64(),
                rw_user,
            )
            .expect("map a code");
        vspace
            .map_page(
                &mut untyped,
                usermode::USER_STACK_ADDR,
                stack_a.start_address().as_u64(),
                rw_user,
            )
            .expect("map a stack");
        vspace
            .map_page(&mut untyped, B_CODE_ADDR, code_b.start_address().as_u64(), rw_user)
            .expect("map b code");
        vspace
            .map_page(
                &mut untyped,
                B_STACK_ADDR,
                stack_b.start_address().as_u64(),
                rw_user,
            )
            .expect("map b stack");
    }

    // kernel stack tops (stack grows down; top is the byte past the static).
    let kstack_a_top =
        VirtAddr::new(core::ptr::addr_of!(KSTACK_A) as u64 + KSTACK_SIZE as u64);
    let kstack_b_top =
        VirtAddr::new(core::ptr::addr_of!(KSTACK_B) as u64 + KSTACK_SIZE as u64);

    // user segment selectors for the pre-populated SavedContext of thread B.
    let sel = gdt::selectors();
    let user_cs = u64::from(sel.user_code.0);
    let user_ss = u64::from(sel.user_data.0);

    // SAFETY: statics written once before any context switch reads them.
    let (tcb_a_ptr, tcb_b_ptr) = unsafe {
        CSPACE = Some(KernelCapSpace::new());

        let mut ta = Tcb::new();
        ta.kernel_stack_top = kstack_a_top.as_u64();
        ta.cspace_ptr = (*core::ptr::addr_of_mut!(CSPACE)).as_mut().unwrap();
        TCB_A = Some(ta);

        let mut tb = Tcb::new();
        tb.kernel_stack_top = kstack_b_top.as_u64();
        // thread B's context is pre-populated so the scheduler can iretq into it
        // without B ever having been entered via enter_user_mode.
        tb.context.rip = B_CODE_ADDR;
        tb.context.rsp = B_STACK_TOP;
        tb.context.rflags = 0x0000_0202; // IF=1, reserved bit 1
        tb.context.cs = user_cs;
        tb.context.ss = user_ss;
        // SYS_EXIT does not touch the CSpace, so leave cspace_ptr null.
        TCB_B = Some(tb);

        (
            (*core::ptr::addr_of_mut!(TCB_A)).as_mut().unwrap() as *mut Tcb,
            (*core::ptr::addr_of_mut!(TCB_B)).as_mut().unwrap() as *mut Tcb,
        )
    };

    // register both TCBs. thread A will run first (set_current); thread B is
    // placed in the ready set so the scheduler can pick it on the first tick.
    x86_64::instructions::interrupts::disable();
    // SAFETY: TCBs are live 'static; interrupts disabled before the PIC fires.
    let id_a = unsafe { sched::register_thread(tcb_a_ptr) };
    let id_b = unsafe { sched::register_thread(tcb_b_ptr) };
    sched::mark_ready(id_b); // B is waiting; A is about to run
    sched::set_current(id_a);

    // switch per-CPU block to thread A's kernel stack + CSpace.
    // SAFETY: tcb_a is live; ring 0; interrupts disabled above.
    unsafe {
        cpu_local::switch_to(tcb_a_ptr);
    }

    // activate the shared address space. from here on, user pages are reachable.
    // SAFETY: VSpace cloned the kernel PML4 entries; kernel stays mapped.
    unsafe {
        vspace.activate();
    }

    // drop to ring 3 at thread A's entry with IF=1. the timer will fire after
    // ~18 ms, preempt A, and context-switch to B, which calls SYS_EXIT(success).
    // SAFETY: code/stack pages mapped user-accessible; init + init_syscall ran;
    // switch_to installed A's kernel stack; this call does not return.
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
