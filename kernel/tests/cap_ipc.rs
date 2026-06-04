// tests/cap_ipc.rs
//
// the capability-slice-3d payoff, headless and the Phase 2 milestone: a
// userspace program performs capability-mediated IPC through the syscall
// boundary, and the kernel enforces rights per call.
//
// the kernel sets up a CSpace holding (slot 0) a full-rights cap to an endpoint
// carved from untyped, (slot 1) a WRITE-only (send) cap minted from it, and
// (slot 2) a READ-only (recv) cap. it installs that CSpace as the current task's
// and drops to ring 3. the user program (assembled offline, bytes below):
//
//   ipc_send(slot 1, 0xABCD)   -> expect 0 (ok): send through the WRITE cap
//   ipc_recv(slot 2)           -> expect 0xABCD: the message round-trips out
//   ipc_send(slot 2, 1)        -> expect nonzero: send through a READ-only cap
//                                 must be DENIED (rights enforced at the syscall)
//   exit(Success) iff all three held, else exit(Failed)
//
// a Success exit proves: a capability slot index from ring 3 is resolved per
// call against the kernel's CSpace (ref_at reconstructs the generation-checked
// CapRef), a message crosses through the endpoint, and the kernel refuses an
// operation the presented capability lacks the right for. that is the
// confused-deputy defense, enforced structurally at the kernel boundary.
#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

use jos::cap::{KernelCapSpace, UntypedRegion};
use jos::memory::BootstrapFrameAllocator;
use jos::vspace::VSpace;
use jos::{serial_print, syscall, usermode};
use jos_core::cap_rights::Rights;
use jos_core::pte::PteFlags;
use x86_64::VirtAddr;
use x86_64::structures::paging::FrameAllocator;

// the assembled capability-IPC program (see the disassembly in the commit/notes).
#[rustfmt::skip]
static USER_PROGRAM: [u8; 85] = [
    0xb8, 0x02, 0x00, 0x00, 0x00,       // mov eax, 2     (SYS_IPC_SEND)
    0xbf, 0x01, 0x00, 0x00, 0x00,       // mov edi, 1     (cap slot 1, WRITE)
    0xbe, 0xcd, 0xab, 0x00, 0x00,       // mov esi, 0xABCD
    0x0f, 0x05,                         // syscall
    0x48, 0x85, 0xc0,                   // test rax, rax
    0x75, 0x31,                         // jne fail
    0xb8, 0x03, 0x00, 0x00, 0x00,       // mov eax, 3     (SYS_IPC_RECV)
    0xbf, 0x02, 0x00, 0x00, 0x00,       // mov edi, 2     (cap slot 2, READ)
    0x0f, 0x05,                         // syscall
    0x48, 0x3d, 0xcd, 0xab, 0x00, 0x00, // cmp rax, 0xABCD
    0x75, 0x1d,                         // jne fail
    0xb8, 0x02, 0x00, 0x00, 0x00,       // mov eax, 2     (SYS_IPC_SEND)
    0xbf, 0x02, 0x00, 0x00, 0x00,       // mov edi, 2     (cap slot 2, READ-only)
    0xbe, 0x01, 0x00, 0x00, 0x00,       // mov esi, 1
    0x0f, 0x05,                         // syscall
    0x48, 0x85, 0xc0,                   // test rax, rax
    0x74, 0x07,                         // je fail  (send via READ-only must fail)
    0xbf, 0x10, 0x00, 0x00, 0x00,       // mov edi, 0x10  (Success)
    0xeb, 0x05,                         // jmp do_exit
    0xbf, 0x11, 0x00, 0x00, 0x00,       // fail: mov edi, 0x11 (Failed)
    0xb8, 0x01, 0x00, 0x00, 0x00,       // do_exit: mov eax, 1 (SYS_EXIT)
    0x0f, 0x05,                         // syscall
    0xeb, 0xfe,                         // jmp . (backstop)
];

static INFO_PTR: AtomicU32 = AtomicU32::new(0);

// page-aligned untyped region for the VSpace tables, the endpoint, and a tcb.
const UNTYPED_SIZE: usize = 64 * 1024;
#[repr(align(4096))]
struct UntypedBacking([u8; UNTYPED_SIZE]);
static mut VSPACE_UNTYPED: UntypedBacking = UntypedBacking([0; UNTYPED_SIZE]);

// the current task's CSpace, kernel-owned and 'static so it outlives the
// syscalls that resolve capabilities in it. KernelCapSpace::new is not const
// (the cap table builds its slots with array::from_fn), so the space is created
// at runtime in kernel_main and stashed here, handed out as a single *mut.
static mut CSPACE: Option<KernelCapSpace> = None;

// a dedicated kernel stack for the syscall entry path.
const KSTACK_SIZE: usize = 4096 * 4;
#[repr(align(16))]
struct KernelStack(#[allow(dead_code)] [u8; KSTACK_SIZE]);
static mut SYSCALL_STACK: KernelStack = KernelStack([0; KSTACK_SIZE]);

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    serial_print!("cap_ipc::user_ipc_through_capabilities...\t");
    INFO_PTR.store(info_ptr, Ordering::SeqCst);

    jos::init();

    // SAFETY: boot.s identity-maps the first 1 GiB; called once here.
    let mut frame_allocator = unsafe { BootstrapFrameAllocator::new(info_ptr) };
    // SAFETY: handed out exactly once; page-aligned.
    let mut untyped = unsafe {
        UntypedRegion::new(&mut (*core::ptr::addr_of_mut!(VSPACE_UNTYPED)).0)
    };

    // carve an endpoint and build the CSpace: slot 0 = full cap, slot 1 = WRITE
    // (send), slot 2 = READ (recv). insert fills the lowest free slot first, so
    // the slot numbers the user program uses are deterministic. the CSpace is
    // stored in the 'static slot and addressed by a pointer to the contained
    // value, so it stays valid across the syscalls.
    let endpoint = untyped.retype_endpoint().expect("carve endpoint");
    // SAFETY: single-threaded; CSPACE is written once here before any syscall
    // reads it, and the &mut borrow ends before the raw pointer is handed out.
    let cspace_ptr = unsafe {
        CSPACE = Some(KernelCapSpace::new());
        let cspace = (*core::ptr::addr_of_mut!(CSPACE)).as_mut().unwrap();
        let full = cspace.insert(endpoint, Rights::all()).expect("insert full cap"); // slot 0
        let send = cspace.mint(full, Rights::WRITE).expect("mint send cap"); // slot 1
        let recv = cspace.mint(full, Rights::READ).expect("mint recv cap"); // slot 2
        assert_eq!(send.slot(), 1, "send cap must land in slot 1");
        assert_eq!(recv.slot(), 2, "recv cap must land in slot 2");
        core::ptr::from_mut::<KernelCapSpace>(cspace)
    };
    // install it as the current task's CSpace for the IPC syscalls.
    // SAFETY: CSPACE is 'static and accessed only on the single-threaded syscall
    // path, satisfying set_current_cspace's contract.
    unsafe {
        syscall::set_current_cspace(cspace_ptr);
    }

    // build an address space, map the user program into it (as in slice 3c).
    // SAFETY: CR3 holds the boot identity map; carved tables are not aliased.
    let mut vspace = unsafe { VSpace::new(&mut untyped).expect("carve VSpace") };
    let code_frame = frame_allocator.allocate_frame().expect("code frame");
    let stack_frame = frame_allocator.allocate_frame().expect("stack frame");
    let leaf = PteFlags::PRESENT | PteFlags::WRITABLE | PteFlags::USER;
    // SAFETY: fresh unique frames; the user window is empty in the new VSpace.
    unsafe {
        vspace
            .map_page(&mut untyped, usermode::USER_CODE_ADDR, code_frame.start_address().as_u64(), leaf)
            .expect("map user code");
        vspace
            .map_page(&mut untyped, usermode::USER_STACK_ADDR, stack_frame.start_address().as_u64(), leaf)
            .expect("map user stack");
    }
    // copy the payload through the code frame's identity-mapped physical address.
    // SAFETY: freshly allocated identity-mapped frame; payload fits one page.
    unsafe {
        let dst = code_frame.start_address().as_u64() as *mut u8;
        core::ptr::copy_nonoverlapping(USER_PROGRAM.as_ptr(), dst, USER_PROGRAM.len());
    }

    // syscall path setup (kernel stack + MSRs).
    let kstack_top = {
        let base = core::ptr::addr_of!(SYSCALL_STACK) as u64;
        VirtAddr::new(base + KSTACK_SIZE as u64)
    };
    syscall::set_kernel_stack(kstack_top);
    syscall::init_syscall();

    x86_64::instructions::interrupts::disable();

    // activate the address space and drop to ring 3.
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
