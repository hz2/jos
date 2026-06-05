// tests/retype_invoke.rs
//
// the retype/invoke-syscall payoff (Phase-2 follow-up), headless: userspace
// CREATES a kernel object from an untyped capability via SYS_RETYPE, then uses
// it via SYS_IPC_SEND and the generic SYS_INVOKE, all from ring 3. This is the
// seL4 discipline: the kernel does not pre-create the endpoint; userspace asks
// for it from untyped memory it was handed, names the destination slot, and the
// kernel enforces every step (only an untyped cap can be retyped; the dest must
// be free and in range).
//
// The user program (assembled offline; bytes below) does:
//   retype(untyped slot 0, Endpoint, dest slot 1) -> expect 0
//   ipc_send(slot 1, 0xD00D)                       -> expect 0
//   invoke(slot 1, Recv)                           -> expect 0xD00D
//   retype(slot 1 [an Endpoint], ...)              -> expect nonzero (NotUntyped)
//   retype(untyped 0, ..., dest slot 1 [occupied]) -> expect nonzero (DestOccupied)
//   retype(untyped 0, ..., dest slot 64 [OOB])     -> expect nonzero (DestOutOfRange)
//   invoke(slot 1, method 99 [bad])                -> expect nonzero (BadMethod)
//   exit(Success) iff all held, else exit(Failed)
//
// A Success exit proves: the untyped cap was resolved and retyped into the named
// slot, the created object works for IPC and generic invoke, and the kernel
// rejects retyping a non-untyped cap, an occupied dest, and an out-of-range dest.
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

// the assembled retype/invoke program (see the source in the commit notes).
#[rustfmt::skip]
static USER_PROGRAM: [u8; 210] = [
    0xb8, 0x04, 0x00, 0x00, 0x00, 0xbf, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x00, 0x00, 0x00, 0x00, 0xba,
    0x01, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x0f, 0x85, 0xa5, 0x00, 0x00, 0x00, 0xb8,
    0x02, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00, 0xbe, 0x0d, 0xd0, 0x00, 0x00, 0x0f, 0x05,
    0x48, 0x85, 0xc0, 0x0f, 0x85, 0x8b, 0x00, 0x00, 0x00, 0xb8, 0x05, 0x00, 0x00, 0x00, 0xbf, 0x01,
    0x00, 0x00, 0x00, 0xbe, 0x01, 0x00, 0x00, 0x00, 0x31, 0xd2, 0x0f, 0x05, 0x48, 0x3d, 0x0d, 0xd0,
    0x00, 0x00, 0x75, 0x70, 0xb8, 0x04, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00, 0xbe, 0x00,
    0x00, 0x00, 0x00, 0xba, 0x02, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x74, 0x55, 0xb8,
    0x04, 0x00, 0x00, 0x00, 0xbf, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x00, 0x00, 0x00, 0x00, 0xba, 0x01,
    0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x74, 0x3a, 0xb8, 0x04, 0x00, 0x00, 0x00, 0xbf,
    0x00, 0x00, 0x00, 0x00, 0xbe, 0x00, 0x00, 0x00, 0x00, 0xba, 0x40, 0x00, 0x00, 0x00, 0x0f, 0x05,
    0x48, 0x85, 0xc0, 0x74, 0x1f, 0xb8, 0x05, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00, 0xbe,
    0x63, 0x00, 0x00, 0x00, 0x31, 0xd2, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x74, 0x07, 0xbf, 0x10, 0x00,
    0x00, 0x00, 0xeb, 0x05, 0xbf, 0x11, 0x00, 0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05,
    0xeb, 0xfe,
];

static INFO_PTR: AtomicU32 = AtomicU32::new(0);

// page-aligned untyped region. it must be 'static (the untyped capability names
// its address, and the syscall resolves it on every call), and page-aligned so
// retyping a PageTable/CNode from it would work too.
const UNTYPED_SIZE: usize = 64 * 1024;
#[repr(align(4096))]
struct UntypedBacking([u8; UNTYPED_SIZE]);
static mut VSPACE_UNTYPED: UntypedBacking = UntypedBacking([0; UNTYPED_SIZE]);

// the untyped REGION struct (distinct from its backing bytes): it must outlive
// the syscalls, since the untyped capability names this struct's address.
static mut OBJECT_UNTYPED: Option<UntypedRegion> = None;
// the current task's CSpace (runtime-built; KernelCapSpace::new is not const).
static mut CSPACE: Option<KernelCapSpace> = None;

const KSTACK_SIZE: usize = 4096 * 4;
#[repr(align(16))]
struct KernelStack(#[allow(dead_code)] [u8; KSTACK_SIZE]);
static mut SYSCALL_STACK: KernelStack = KernelStack([0; KSTACK_SIZE]);

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    serial_print!("retype_invoke::user_creates_and_uses_object...\t");
    INFO_PTR.store(info_ptr, Ordering::SeqCst);

    jos::init();

    // SAFETY: boot.s identity-maps the first 1 GiB; called once here.
    let mut frame_allocator = unsafe { BootstrapFrameAllocator::new(info_ptr) };

    // build the untyped REGION (for carving the VSpace tables + the user's
    // retype source) over the page-aligned backing.
    // SAFETY: handed out exactly once; page-aligned.
    let mut vspace_untyped = unsafe {
        UntypedRegion::new(&mut (*core::ptr::addr_of_mut!(VSPACE_UNTYPED)).0)
    };

    // build the address space + map the user program (as in cap_ipc.rs).
    // SAFETY: CR3 holds the boot identity map; carved tables are not aliased.
    let mut vspace = unsafe { VSpace::new(&mut vspace_untyped).expect("carve VSpace") };
    let code_frame = frame_allocator.allocate_frame().expect("code frame");
    let stack_frame = frame_allocator.allocate_frame().expect("stack frame");
    let leaf = PteFlags::PRESENT | PteFlags::WRITABLE | PteFlags::USER;
    // SAFETY: fresh unique frames; user window empty in the new VSpace.
    unsafe {
        vspace
            .map_page(&mut vspace_untyped, usermode::USER_CODE_ADDR, code_frame.start_address().as_u64(), leaf)
            .expect("map user code");
        vspace
            .map_page(&mut vspace_untyped, usermode::USER_STACK_ADDR, stack_frame.start_address().as_u64(), leaf)
            .expect("map user stack");
    }
    // SAFETY: freshly allocated identity-mapped frame; payload fits one page.
    unsafe {
        let dst = code_frame.start_address().as_u64() as *mut u8;
        core::ptr::copy_nonoverlapping(USER_PROGRAM.as_ptr(), dst, USER_PROGRAM.len());
    }

    // build the user's untyped region (the retype SOURCE) and a CSpace holding
    // ONLY an untyped capability in slot 0. the user program creates the
    // endpoint in slot 1 itself via SYS_RETYPE. both statics outlive the
    // syscalls; the untyped capability names OBJECT_UNTYPED's address.
    // SAFETY: single-threaded; both statics are written once here before any
    // syscall reads them, and the &mut borrows end before the raw pointer to the
    // CSpace is handed out.
    let cspace_ptr = unsafe {
        OBJECT_UNTYPED = Some(UntypedRegion::new(fresh_object_backing()));
        let region = (*core::ptr::addr_of_mut!(OBJECT_UNTYPED)).as_mut().unwrap();
        let untyped_id = region.as_object_id();

        CSPACE = Some(KernelCapSpace::new());
        let cspace = (*core::ptr::addr_of_mut!(CSPACE)).as_mut().unwrap();
        let slot0 = cspace.insert(untyped_id, Rights::all()).expect("insert untyped cap");
        assert_eq!(slot0.slot(), 0, "untyped cap must land in slot 0");
        core::ptr::from_mut::<KernelCapSpace>(cspace)
    };
    // SAFETY: CSPACE is 'static and accessed only on the single-threaded syscall
    // path, satisfying set_current_cspace's contract.
    unsafe {
        syscall::set_current_cspace(cspace_ptr);
    }

    let kstack_top = {
        let base = core::ptr::addr_of!(SYSCALL_STACK) as u64;
        VirtAddr::new(base + KSTACK_SIZE as u64)
    };
    syscall::set_kernel_stack(kstack_top);
    syscall::init_syscall();

    x86_64::instructions::interrupts::disable();

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

// a second page-aligned static backing for the user's retype-source region,
// distinct from the VSpace region. 16 KiB is ample for a few endpoints.
fn fresh_object_backing() -> &'static mut [u8] {
    #[repr(align(4096))]
    struct Backing([u8; 16 * 1024]);
    static mut BACKING: Backing = Backing([0; 16 * 1024]);
    // SAFETY: handed out exactly once (kernel_main runs once); 4096-aligned.
    unsafe { &mut (*core::ptr::addr_of_mut!(BACKING)).0 }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}
