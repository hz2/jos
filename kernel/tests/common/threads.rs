//! Shared harness for kernel tests that run several ring-3 threads.
//!
//! All threads share one `VSpace` and one `CSpace`. Thread 0 is entered first
//! through `enter_user_mode_with_arg`; the others wait in the ready set and are
//! entered by the scheduler's `iretq` when a timer tick switches to them.
//!
//! Thread `i` lives in its own 64 KiB window at `USER_BASE + i * 0x10000`:
//! code at offset 0, stack at `0x1000`, and its IPC buffer at `0x2000`. The
//! buffer frame is registered in the thread's TCB and its address is passed in
//! `rdi` at start. A zeroed page at [`SHARED_ADDR`] is mapped read-write for
//! every thread. With [`Spaces::Separate`] every thread runs in its own
//! address space and the scheduler switches `CR3` with the thread.
//!
//! When a test needs several threads' checks to pass and any may finish last,
//! each program ends with `lock inc qword ptr [SHARED_ADDR]` and exits with
//! success only if the counter then reads the number of checking threads; the
//! others spin.

// each test binary compiles this module on its own and uses only part of it.
#![allow(dead_code)]

use jos::cap::{KernelCapSpace, Tcb, UntypedRegion};
use jos::cpu_local;
use jos::memory::BootstrapFrameAllocator;
use jos::vspace::VSpace;
use jos::{gdt, sched, syscall, usermode};
use jos_core::pte::PteFlags;
use x86_64::VirtAddr;
use x86_64::structures::paging::{FrameAllocator, PhysFrame};

/// The most threads one test can run.
pub const MAX_TEST_THREADS: usize = 4;
/// User address of the zeroed data page every thread can read and write.
pub const SHARED_ADDR: u64 = usermode::USER_BASE + 0x4000;
/// User address of each thread's private page under [`Spaces::Separate`]: the
/// same address in every address space, a different frame behind it.
pub const PRIVATE_ADDR: u64 = usermode::USER_BASE + 0x8000;

/// Returns the base of thread `i`'s 64 KiB user window.
const fn window(i: usize) -> u64 {
    usermode::USER_BASE + 0x1_0000 * i as u64
}

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
#[derive(Clone, Copy)]
struct KernelStack(#[allow(dead_code)] [u8; KSTACK_SIZE]);
static mut KSTACKS: [KernelStack; MAX_TEST_THREADS] = [KernelStack([0; KSTACK_SIZE]); MAX_TEST_THREADS];

static mut TCBS: [Tcb; MAX_TEST_THREADS] = [const { Tcb::new() }; MAX_TEST_THREADS];
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

/// Whether the threads share one address space or each get their own.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Spaces {
    /// One `VSpace` for every thread.
    Shared,
    /// A `VSpace` per thread. Each also gets a private page at
    /// [`PRIVATE_ADDR`], backed by a different frame in every address space.
    Separate,
}

/// Boots one thread per program in one shared address space; see [`boot_with`].
///
/// # Safety
///
/// As [`boot_with`].
pub unsafe fn boot(
    info_ptr: u32,
    programs: &[Program],
    caps: impl FnOnce(&mut UntypedRegion, &mut KernelCapSpace),
) -> ! {
    // SAFETY: forwarded unchanged; same contract.
    unsafe { boot_with(info_ptr, programs, Spaces::Shared, caps) }
}

/// Boots one thread per program and enters ring 3 as thread 0. Never returns;
/// the programs end the test through the exit syscall.
///
/// `caps` fills the shared `CSpace`, carving objects from the test's untyped
/// region. Each thread's `vspace_root` is set, so the scheduler switches
/// address spaces with the thread.
///
/// # Safety
///
/// Call once, from `kernel_main`, with the multiboot `info_ptr` the boot
/// trampoline passed in; each program must bound bytes emitted by a
/// `global_asm!`, and there must be between 1 and [`MAX_TEST_THREADS`] of them.
pub unsafe fn boot_with(
    info_ptr: u32,
    programs: &[Program],
    spaces: Spaces,
    caps: impl FnOnce(&mut UntypedRegion, &mut KernelCapSpace),
) -> ! {
    assert!(!programs.is_empty() && programs.len() <= MAX_TEST_THREADS, "1 to 4 threads");
    jos::init();
    syscall::init_syscall();

    // SAFETY: boot.s identity-maps the first 1 GiB; called once per test.
    let mut frames = unsafe { BootstrapFrameAllocator::new(info_ptr) };
    // SAFETY: page-aligned static backing, handed out once.
    let mut untyped = unsafe { UntypedRegion::new(&mut (*core::ptr::addr_of_mut!(UNTYPED)).0) };
    let mut fresh_frame = || {
        let frame = frames.allocate_frame().expect("frame");
        // SAFETY: the frame is fresh and identity-mapped; zeroing it gives every
        // data page (stacks, buffers, counters) a known start.
        unsafe { core::ptr::write_bytes(frame.start_address().as_u64() as *mut u8, 0, 4096) };
        frame
    };
    let map = |vspace: &mut VSpace, untyped: &mut UntypedRegion, addr: u64, frame: PhysFrame, flags| {
        // SAFETY: the frame is identity-mapped and each address is a distinct
        // user page in this address space.
        unsafe {
            vspace
                .map_page(untyped, addr, frame.start_address().as_u64(), flags)
                .expect("map user page");
        }
    };

    let count = if spaces == Spaces::Separate { programs.len() } else { 1 };
    let mut vspaces: [Option<VSpace>; MAX_TEST_THREADS] = [None, None, None, None];
    for slot in vspaces.iter_mut().take(count) {
        // SAFETY: the untyped region is live; each root is carved fresh.
        *slot = Some(unsafe { VSpace::new(&mut untyped).expect("vspace") });
    }
    let space_of = |i: usize| if spaces == Spaces::Separate { i } else { 0 };

    let code = PteFlags::PRESENT | PteFlags::USER;
    let data = PteFlags::PRESENT | PteFlags::WRITABLE | PteFlags::USER | PteFlags::NO_EXECUTE;
    // the shared page is one frame mapped into every address space.
    let shared = fresh_frame();
    for vspace in vspaces.iter_mut().flatten() {
        map(vspace, &mut untyped, SHARED_ADDR, shared, data);
    }

    let sel = gdt::selectors();
    // SAFETY: the statics are written once here, before any context switch.
    let cspace_ptr = unsafe {
        let mut cspace = KernelCapSpace::new();
        caps(&mut untyped, &mut cspace);
        CSPACE = Some(cspace);
        (*core::ptr::addr_of_mut!(CSPACE)).as_mut().unwrap() as *mut KernelCapSpace
    };

    let mut tcb_ptrs = [core::ptr::null_mut::<Tcb>(); MAX_TEST_THREADS];
    for (i, program) in programs.iter().enumerate() {
        let base = window(i);
        let vspace = vspaces[space_of(i)].as_mut().unwrap();
        let (code_frame, stack, buffer) = (fresh_frame(), fresh_frame(), fresh_frame());
        map(vspace, &mut untyped, base, code_frame, code);
        map(vspace, &mut untyped, base + 0x1000, stack, data);
        map(vspace, &mut untyped, base + 0x2000, buffer, data);
        if spaces == Spaces::Separate {
            map(vspace, &mut untyped, PRIVATE_ADDR, fresh_frame(), data);
        }
        let root = vspace.root_phys();
        // SAFETY: program bounds emitted bytes (this function's contract); the
        // code frame was just allocated and is identity-mapped.
        unsafe { load(*program, code_frame) };

        // SAFETY: TCBS and KSTACKS are statics touched only here, before any
        // context switch reads them; i < MAX_TEST_THREADS (asserted above).
        unsafe {
            let tcb = core::ptr::addr_of_mut!(TCBS[i]);
            (*tcb).kernel_stack_top =
                core::ptr::addr_of!(KSTACKS[i]) as u64 + KSTACK_SIZE as u64;
            (*tcb).cspace_ptr = cspace_ptr;
            (*tcb).vspace_root = root;
            (*tcb).ipc_buffer = buffer.start_address().as_u64();
            // threads other than 0 are entered by the scheduler's iretq.
            (*tcb).context.rip = base;
            (*tcb).context.rsp = base + 0x2000;
            (*tcb).context.rflags = 0x0000_0202;
            (*tcb).context.cs = u64::from(sel.user_code.0);
            (*tcb).context.ss = u64::from(sel.user_data.0);
            (*tcb).context.rdi = base + 0x2000;
            tcb_ptrs[i] = tcb;
        }
    }

    x86_64::instructions::interrupts::disable();
    let mut first = 0;
    for (i, tcb) in tcb_ptrs.iter().take(programs.len()).enumerate() {
        // SAFETY: each pointer is a live TCB static; interrupts are disabled.
        let id = unsafe { sched::register_thread(*tcb) };
        if i == 0 {
            first = id;
        } else {
            sched::mark_ready(id);
        }
    }
    sched::set_current(first);

    // SAFETY: thread 0's TCB is live, with its kernel stack, CSpace, and VSpace
    // set; ring 0; interrupts disabled. switch_to loads its address space.
    unsafe { cpu_local::switch_to(tcb_ptrs[0]) };
    // SAFETY: pages mapped; init and init_syscall ran; switch_to installed
    // thread 0's kernel stack and address space.
    unsafe {
        usermode::enter_user_mode_with_arg(
            VirtAddr::new(window(0)),
            VirtAddr::new(window(0) + 0x2000),
            window(0) + 0x2000,
        );
    }
}
