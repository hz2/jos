// tests/vspace.rs
//
// the capability-slice-3c payoff, headless: a userspace program runs in its OWN
// address space, built by the retypeable VSpace mapper, reached by switching
// CR3 to a freshly carved PML4.
//
// what this exercises end to end:
//   1. carve a VSpace (a PML4 page-table object) from a page-aligned untyped
//      region, cloning the kernel's identity + higher-half PML4 entries so the
//      kernel survives the CR3 switch;
//   2. map the user code + stack pages into that VSpace via map_page, which
//      hand-walks PML4->PDPT->PD->PT carving intermediate tables from untyped
//      and writing entries through the Kani-verified jos_core::pte encoder
//      (USER bit on every level);
//   3. carve a Tcb, record the VSpace root + the entry context in it;
//   4. activate the VSpace (mov cr3) and iretq into ring 3.
//
// the user program is the SAME self-checking syscall payload as the 3b test:
// add(0x100, 0x23), verify == 0x123 in ring 3, then SYS_EXIT with the verdict.
// a Success exit now additionally proves the new address space's page tables
// translate the user code/stack correctly AND the kernel kept running across
// the CR3 load (otherwise: triple fault / timeout).
#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

use jos::cap::{ObjectKind, TcbState, UntypedRegion};
use jos::memory::BootstrapFrameAllocator;
use jos::vspace::VSpace;
use jos::{serial_print, syscall, usermode};
use jos_core::pte::PteFlags;
use x86_64::VirtAddr;
use x86_64::structures::paging::FrameAllocator;

// the assembled SYS_ADD/SYS_EXIT round-trip program (same bytes as the 3b test).
#[rustfmt::skip]
static USER_PROGRAM: [u8; 46] = [
    0xb8, 0x00, 0x00, 0x00, 0x00,       // mov eax, 0      (SYS_ADD)
    0xbf, 0x00, 0x01, 0x00, 0x00,       // mov edi, 0x100
    0xbe, 0x23, 0x00, 0x00, 0x00,       // mov esi, 0x23
    0x0f, 0x05,                         // syscall
    0x48, 0x3d, 0x23, 0x01, 0x00, 0x00, // cmp rax, 0x123
    0x75, 0x07,                         // jne +7 (-> fail)
    0xbf, 0x10, 0x00, 0x00, 0x00,       // mov edi, 0x10   (Success)
    0xeb, 0x05,                         // jmp +5 (-> do_exit)
    0xbf, 0x11, 0x00, 0x00, 0x00,       // fail: mov edi, 0x11 (Failed)
    0xb8, 0x01, 0x00, 0x00, 0x00,       // do_exit: mov eax, 1 (SYS_EXIT)
    0x0f, 0x05,                         // syscall
    0xeb, 0xfe,                         // jmp . (backstop)
];

static INFO_PTR: AtomicU32 = AtomicU32::new(0);

// a page-aligned untyped region to carve page tables and the tcb from. page
// tables are 4096-aligned, so the region base must be page-aligned. 64 KiB is
// room for a PML4 + a few intermediate tables + a TCB.
const UNTYPED_SIZE: usize = 64 * 1024;
#[repr(align(4096))]
struct UntypedBacking([u8; UNTYPED_SIZE]);
static mut VSPACE_UNTYPED: UntypedBacking = UntypedBacking([0; UNTYPED_SIZE]);

// a dedicated kernel stack for the syscall entry path (as in the 3b test).
const KSTACK_SIZE: usize = 4096 * 4;
#[repr(align(16))]
struct KernelStack(#[allow(dead_code)] [u8; KSTACK_SIZE]);
static mut SYSCALL_STACK: KernelStack = KernelStack([0; KSTACK_SIZE]);

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    serial_print!("vspace::user_runs_in_own_address_space...\t");
    INFO_PTR.store(info_ptr, Ordering::SeqCst);

    jos::init();

    // paging + a frame allocator. ONE allocator, shared between the leaf-page
    // frames and (implicitly) anything else, per the paging_heap gotcha.
    // SAFETY: boot.s identity-maps the first 1 GiB; called once here.
    let mut frame_allocator = unsafe { BootstrapFrameAllocator::new(info_ptr) };

    // build the untyped region the VSpace carves its tables from.
    // SAFETY: handed out exactly once; page-aligned via repr(align(4096)).
    let mut untyped = unsafe {
        UntypedRegion::new(&mut (*core::ptr::addr_of_mut!(VSPACE_UNTYPED)).0)
    };

    // 1. carve a fresh address space (clones the kernel PML4 entries).
    // SAFETY: CR3 holds the boot identity-mapped PML4; the carved table is not
    // aliased.
    let mut vspace = unsafe { VSpace::new(&mut untyped).expect("carve VSpace") };

    // 2. allocate frames for the user code + stack and map them into the VSpace
    // at the usermode window, with USER + WRITABLE leaf flags.
    let code_frame = frame_allocator.allocate_frame().expect("code frame");
    let stack_frame = frame_allocator.allocate_frame().expect("stack frame");
    let leaf = PteFlags::PRESENT | PteFlags::WRITABLE | PteFlags::USER;
    // SAFETY: the frames are freshly allocated and unique; the user window is
    // empty in the new VSpace, so mapping introduces no aliasing.
    unsafe {
        vspace
            .map_page(&mut untyped, usermode::USER_CODE_ADDR, code_frame.start_address().as_u64(), leaf)
            .expect("map user code");
        vspace
            .map_page(&mut untyped, usermode::USER_STACK_ADDR, stack_frame.start_address().as_u64(), leaf)
            .expect("map user stack");
    }

    // copy the payload into the code frame THROUGH its identity-mapped physical
    // address (phys == virt under the boot identity map; we are still on the
    // kernel PML4 here, which has the identity map).
    // SAFETY: code_frame is a freshly allocated, identity-mapped frame; the
    // payload fits in one page; source and dest do not overlap.
    unsafe {
        let dst = code_frame.start_address().as_u64() as *mut u8;
        core::ptr::copy_nonoverlapping(USER_PROGRAM.as_ptr(), dst, USER_PROGRAM.len());
    }

    // 3. carve a Tcb and record the VSpace root + entry context in it.
    let tcb_id = untyped.retype_tcb().expect("carve Tcb");
    assert_eq!(tcb_id.kind(), ObjectKind::Tcb);
    // SAFETY: tcb_id was just carved as a Tcb and is not aliased.
    let tcb = unsafe { tcb_id.as_tcb_mut() };
    tcb.vspace_root = vspace.root_phys();
    tcb.context.rip = usermode::USER_CODE_ADDR;
    tcb.context.rsp = usermode::USER_STACK_TOP;
    tcb.state = TcbState::Running;
    // sanity: the tcb recorded the address space we are about to activate.
    assert_eq!(tcb.vspace_root, vspace.root_phys());
    assert_ne!(tcb.vspace_root, 0);

    // set up the syscall path (kernel stack + MSRs) as in 3b.
    let kstack_top = {
        let base = core::ptr::addr_of!(SYSCALL_STACK) as u64;
        VirtAddr::new(base + KSTACK_SIZE as u64)
    };
    syscall::set_kernel_stack(kstack_top);
    syscall::init_syscall();

    // deterministic bring-up: mask interrupts so the timer cannot perturb the
    // single-threaded path.
    x86_64::instructions::interrupts::disable();

    // 4. switch to the new address space, then drop to ring 3 at the tcb's
    // entry. from here the user program runs out of the freshly mapped pages.
    // SAFETY: the VSpace cloned the kernel's identity + higher-half PML4 entries
    // in VSpace::new, so kernel code/stack/data stay mapped across the CR3 load.
    unsafe {
        vspace.activate();
    }
    // SAFETY: the user code/stack are mapped USER-accessible in the active
    // VSpace; init + init_syscall ran; the context fields hold the entry/stack.
    unsafe {
        usermode::enter_user_mode(
            VirtAddr::new(tcb.context.rip),
            VirtAddr::new(tcb.context.rsp),
        );
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}
