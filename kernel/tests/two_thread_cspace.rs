// tests/two_thread_cspace.rs
//
// the per-Tcb-CSpace payoff (Phase-2 follow-up), headless: which capability
// space a syscall resolves against is selected PER THREAD via the per-CPU block
// (swapgs + switch_to), not a single global. This is the prerequisite for more
// than one userspace thread: each thread has its own CSpace and kernel stack.
//
// Setup: two TCBs, each with its OWN KernelCapSpace holding an endpoint. The
// kernel pre-loads a DIFFERENT word into each thread's endpoint from ring 0
// (thread A's: 0xA0A0; thread B's: 0xB0B0). It then switch_to(tcb_b) and enters
// ring 3 running thread B's program, which recvs from its slot 0 and checks the
// word is 0xB0B0 (thread B's), NOT 0xA0A0 (thread A's). Success proves switch_to
// selected B's CSpace.
//
// Negative control (separate binary two_thread_wrong_cspace.rs): switch_to(tcb_a)
// but run thread B's program (which expects 0xB0B0). It resolves against thread
// A's CSpace, recvs 0xA0A0, the compare fails, and it exits Failed. That proves
// the selection is actually load-bearing: pointing at the other thread's CSpace
// changes what the syscall sees.
#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

use jos::cap::{cap_send, KernelCapSpace, Message, Tcb, UntypedRegion};
use jos::cpu_local;
use jos::memory::BootstrapFrameAllocator;
use jos::vspace::VSpace;
use jos::{serial_print, syscall, usermode};
use jos_core::cap_rights::Rights;
use jos_core::pte::PteFlags;
use x86_64::VirtAddr;
use x86_64::structures::paging::FrameAllocator;

// thread B: recv from slot 0, require the word == 0xB0B0, else fail.
#[rustfmt::skip]
static THREAD_B_PROGRAM: [u8; 41] = [
    0xb8, 0x03, 0x00, 0x00, 0x00, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x3d, 0xb0, 0xb0,
    0x00, 0x00, 0x75, 0x07, 0xbf, 0x10, 0x00, 0x00, 0x00, 0xeb, 0x05, 0xbf, 0x11, 0x00, 0x00, 0x00,
    0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xeb, 0xfe,
];

static INFO_PTR: AtomicU32 = AtomicU32::new(0);

const UNTYPED_SIZE: usize = 128 * 1024;
#[repr(align(4096))]
struct UntypedBacking([u8; UNTYPED_SIZE]);
static mut UNTYPED: UntypedBacking = UntypedBacking([0; UNTYPED_SIZE]);

// two CSpaces + two TCBs, kernel-owned and 'static (the per-CPU block points at
// the chosen CSpace, and the TCB carries the chosen kernel stack).
static mut CSPACE_A: Option<KernelCapSpace> = None;
static mut CSPACE_B: Option<KernelCapSpace> = None;
static mut TCB_A: Option<Tcb> = None;
static mut TCB_B: Option<Tcb> = None;

// a kernel stack per thread (the whole point: distinct stacks). 16 KiB each.
const KSTACK_SIZE: usize = 4096 * 4;
#[repr(align(16))]
struct KernelStack(#[allow(dead_code)] [u8; KSTACK_SIZE]);
static mut KSTACK_A: KernelStack = KernelStack([0; KSTACK_SIZE]);
static mut KSTACK_B: KernelStack = KernelStack([0; KSTACK_SIZE]);

// set this to TCB_A in the negative-control binary; TCB_B here. selecting A's
// CSpace while running B's program (which expects B's word) must fail.
const RUN_TCB_IS_B: bool = true;

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    serial_print!("two_thread_cspace::switch_selects_per_thread_cspace...\t");
    INFO_PTR.store(info_ptr, Ordering::SeqCst);
    jos::init();

    // SAFETY: boot.s identity-maps the first 1 GiB; called once here.
    let mut frame_allocator = unsafe { BootstrapFrameAllocator::new(info_ptr) };
    // SAFETY: handed out once; page-aligned.
    let mut untyped = unsafe { UntypedRegion::new(&mut (*core::ptr::addr_of_mut!(UNTYPED)).0) };

    // build two CSpaces, each with an endpoint, and pre-load a distinct word
    // into each thread's endpoint from ring 0. then build two TCBs naming their
    // CSpaces + kernel stacks.
    // SAFETY: single-threaded setup; each static is written once before any
    // syscall runs; &mut borrows end before raw pointers are taken.
    let (cspace_a_ptr, cspace_b_ptr) = unsafe {
        CSPACE_A = Some(KernelCapSpace::new());
        CSPACE_B = Some(KernelCapSpace::new());
        let ca = (*core::ptr::addr_of_mut!(CSPACE_A)).as_mut().unwrap();
        let cb = (*core::ptr::addr_of_mut!(CSPACE_B)).as_mut().unwrap();

        // thread A's endpoint, full cap in slot 0, pre-loaded with 0xA0A0.
        let ep_a = untyped.retype_endpoint().expect("ep a");
        let a0 = ca.insert(ep_a, Rights::all()).expect("ca slot0");
        assert_eq!(a0.slot(), 0);
        cap_send(ca, a0, Message { label: 0, words: [0xA0A0, 0, 0, 0] }).expect("preload a");

        // thread B's endpoint, full cap in slot 0, pre-loaded with 0xB0B0.
        let ep_b = untyped.retype_endpoint().expect("ep b");
        let b0 = cb.insert(ep_b, Rights::all()).expect("cb slot0");
        assert_eq!(b0.slot(), 0);
        cap_send(cb, b0, Message { label: 0, words: [0xB0B0, 0, 0, 0] }).expect("preload b");

        (
            core::ptr::from_mut::<KernelCapSpace>(ca),
            core::ptr::from_mut::<KernelCapSpace>(cb),
        )
    };

    // kernel stack tops.
    let kstack_a = VirtAddr::new(core::ptr::addr_of!(KSTACK_A) as u64 + KSTACK_SIZE as u64);
    let kstack_b = VirtAddr::new(core::ptr::addr_of!(KSTACK_B) as u64 + KSTACK_SIZE as u64);

    // build the two TCBs, each carrying its CSpace pointer + kernel stack.
    // SAFETY: written once here before any context switch reads them.
    let (tcb_a_ptr, tcb_b_ptr) = unsafe {
        let mut ta = Tcb::new();
        ta.cspace_ptr = cspace_a_ptr;
        ta.kernel_stack_top = kstack_a.as_u64();
        TCB_A = Some(ta);
        let mut tb = Tcb::new();
        tb.cspace_ptr = cspace_b_ptr;
        tb.kernel_stack_top = kstack_b.as_u64();
        TCB_B = Some(tb);
        (
            (*core::ptr::addr_of_mut!(TCB_A)).as_mut().unwrap() as *mut Tcb,
            (*core::ptr::addr_of_mut!(TCB_B)).as_mut().unwrap() as *mut Tcb,
        )
    };

    // map thread B's program into a fresh address space (we only run B).
    // SAFETY: CR3 holds the boot identity map; carved tables not aliased.
    let mut vspace = unsafe { VSpace::new(&mut untyped).expect("vspace") };
    let code_frame = frame_allocator.allocate_frame().expect("code frame");
    let stack_frame = frame_allocator.allocate_frame().expect("stack frame");
    let leaf = PteFlags::PRESENT | PteFlags::WRITABLE | PteFlags::USER;
    // SAFETY: fresh unique frames; user window empty.
    unsafe {
        vspace
            .map_page(&mut untyped, usermode::USER_CODE_ADDR, code_frame.start_address().as_u64(), leaf)
            .expect("map code");
        vspace
            .map_page(&mut untyped, usermode::USER_STACK_ADDR, stack_frame.start_address().as_u64(), leaf)
            .expect("map stack");
    }
    // SAFETY: freshly allocated identity-mapped frame; program fits one page.
    unsafe {
        core::ptr::copy_nonoverlapping(
            THREAD_B_PROGRAM.as_ptr(),
            code_frame.start_address().as_u64() as *mut u8,
            THREAD_B_PROGRAM.len(),
        );
    }

    syscall::init_syscall();

    // select the thread to run: switch_to sets the per-CPU kernel stack + CSpace
    // from the chosen TCB. running thread B's program against B's CSpace must see
    // 0xB0B0; the negative-control binary flips RUN_TCB_IS_B and must fail.
    let run_tcb = if RUN_TCB_IS_B { tcb_b_ptr } else { tcb_a_ptr };
    // suppress unused warning for the not-chosen tcb.
    let _ = (tcb_a_ptr, tcb_b_ptr);
    // SAFETY: run_tcb is a live, initialized Tcb with a valid kernel stack and
    // a live 'static CSpace; called from ring 0 with interrupts disabled below.
    unsafe {
        cpu_local::switch_to(run_tcb);
    }

    x86_64::instructions::interrupts::disable();

    // SAFETY: VSpace::new cloned the kernel PML4 entries; kernel stays mapped.
    unsafe {
        vspace.activate();
    }
    // SAFETY: B's code/stack mapped USER-accessible; init + init_syscall ran;
    // switch_to installed the per-CPU kernel stack + CSpace.
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
