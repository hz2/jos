// tests/usermode.rs
//
// the capability-slice-3a payoff, headless: jos can drop to ring 3 and run user
// code, and a ring-3 trap re-enters the kernel on the TSS rsp0 stack.
//
// the proof is precise. reaching ring 3 is not demonstrated by "int3 ran" (ring
// 0 can execute int3 too); it is demonstrated by the cpu state the breakpoint
// handler observes. the user payload is three bytes of machine code:
//
//   cc        int3            ; trap into the kernel
//   eb fe     jmp $           ; spin if the handler ever returns here
//
// we map that payload into a user-accessible page, iretq into it at ring 3, and
// in the breakpoint handler assert the SAVED code selector has RPL == 3. that
// can only be true if the cpu was running at CPL 3 when int3 fired, which in
// turn means iretq performed the privilege switch AND the cpu switched to the
// rsp0 kernel stack to deliver the interrupt (otherwise it would have
// triple-faulted on the user stack). the handler then reports success and exits
// qemu; if we never reached the handler the test times out / resets and fails.
#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

use jos::memory::BootstrapFrameAllocator;
use jos::{QemuExitCode, exit_qemu, gdt, serial_print, serial_println};
use x86_64::PrivilegeLevel;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

// a ring-3 program: int3 (0xcc) then jmp-to-self (0xeb 0xfe) as a backstop in
// case the breakpoint handler returns instead of exiting.
static USER_PROGRAM: [u8; 3] = [0xCC, 0xEB, 0xFE];

static INFO_PTR: AtomicU32 = AtomicU32::new(0);

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    serial_print!("usermode::enter_ring3...\t");
    INFO_PTR.store(info_ptr, Ordering::SeqCst);

    // gdt/tss (user segments + rsp0) and our test idt (breakpoint gate reachable
    // from ring 3). the real jos::init wires the production idt; here we install
    // a test idt whose breakpoint handler checks CPL and exits qemu.
    gdt::init_gdt();
    init_test_idt();

    // set up paging + a frame allocator so we can map the user pages. heap is
    // not needed for this test, so we only build the mapper + allocator.
    // SAFETY: boot.s identity-maps the first 1 GiB; called once here.
    let (mut mapper, mut frame_allocator) = unsafe {
        let mapper = jos::memory::init_mapper();
        let frame_allocator = BootstrapFrameAllocator::new(info_ptr);
        (mapper, frame_allocator)
    };

    // map the user code + stack pages and copy in the payload.
    // SAFETY: the user window is otherwise unmapped, mapper controls the active
    // address space, and the bootstrap allocator hands out only free frames.
    let image = unsafe {
        jos::usermode::load_user_image(&mut mapper, &mut frame_allocator, &USER_PROGRAM)
    };

    // drop to ring 3 at the payload's entry. does not return: the int3 in the
    // payload traps into test_breakpoint_handler, which exits qemu.
    // SAFETY: the image's entry/stack are mapped user-accessible (just done),
    // and init_gdt ran above so the user segments and rsp0 exist.
    unsafe {
        jos::usermode::enter_user_mode(image.entry, image.stack_top);
    }
}

static mut TEST_IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();

fn init_test_idt() {
    // SAFETY: single-threaded test boot context; nothing else touches TEST_IDT.
    unsafe {
        let idt = &mut *core::ptr::addr_of_mut!(TEST_IDT);
        // the breakpoint gate must be reachable from ring 3: set its DPL to 3,
        // otherwise int3 from CPL 3 raises a #GP instead of invoking the handler.
        idt.breakpoint
            .set_handler_fn(test_breakpoint_handler)
            .set_privilege_level(PrivilegeLevel::Ring3);
        // a double-fault handler on the IST stack so that, if anything goes
        // wrong (e.g. we did not actually reach a usable state), we fail loudly
        // via the handler rather than silently triple-faulting and resetting.
        idt.double_fault
            .set_handler_fn(test_double_fault_handler)
            .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
        idt.load();
    }
}

// the breakpoint handler the ring-3 int3 traps into. the saved code segment in
// the interrupt stack frame is the CS the cpu was running when int3 fired; its
// RPL is the privilege level. RPL == 3 proves we were in ring 3.
extern "x86-interrupt" fn test_breakpoint_handler(stack_frame: InterruptStackFrame) {
    let saved_cs = stack_frame.code_segment;
    let rpl = saved_cs & 0b11;
    if rpl == 3 {
        serial_println!("[ok] (trapped from CPL {})", rpl);
        exit_qemu(QemuExitCode::Success);
    } else {
        serial_println!("[failed] breakpoint came from CPL {}, expected 3", rpl);
        exit_qemu(QemuExitCode::Failed);
    }
    jos::hlt_loop()
}

extern "x86-interrupt" fn test_double_fault_handler(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    serial_println!("[failed] unexpected double fault");
    exit_qemu(QemuExitCode::Failed);
    jos::hlt_loop()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}
