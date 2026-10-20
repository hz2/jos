//! A TCB's kernel stack overflows into its guard page, not its header.
//!
//! The test carves a TCB from untyped memory, switches to the TCB's own kernel
//! stack, and recurses without bound. The guard page under that stack is
//! unmapped, so the overflow page-faults there; the fault cannot be delivered
//! on the exhausted stack, which escalates to a double fault on its IST stack.
//! The handler checks that the TCB header above the stack is untouched before
//! reporting success. Without the guard the recursion would run on through the
//! header and whatever lies below the object.
#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

use core::panic::PanicInfo;

use jos::cap::{TcbState, UntypedRegion};
use jos::{QemuExitCode, exit_qemu, gdt, serial_print, serial_println};
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

/// Page-aligned backing for one TCB object (and spare room).
#[repr(align(4096))]
struct Backing([u8; 64 * 1024]);
static mut BACKING: Backing = Backing([0; 64 * 1024]);
static mut REGION: Option<UntypedRegion> = None;

/// Where the TCB's header lives and the stack top it recorded, for the
/// double-fault handler to check.
static mut TCB_ADDR: usize = 0;
static mut STACK_TOP: u64 = 0;

static mut TEST_IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, _info_ptr: u32) -> ! {
    serial_print!("tcb_guard::overflow_hits_the_guard...\t");
    gdt::init_gdt();
    // SAFETY: single-threaded boot; nothing else touches TEST_IDT, and the IST
    // stack the double-fault entry names was installed by init_gdt above.
    unsafe {
        let idt = &mut *core::ptr::addr_of_mut!(TEST_IDT);
        idt.double_fault
            .set_handler_fn(double_fault)
            .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
        idt.load();
    }

    // SAFETY: the statics are written once here, before anything reads them; the
    // backing is page-aligned and handed out once.
    let top = unsafe {
        REGION = Some(UntypedRegion::new(&mut (*core::ptr::addr_of_mut!(BACKING)).0));
        let region = (*core::ptr::addr_of_mut!(REGION)).as_mut().unwrap();
        let id = region.retype_tcb().expect("carve tcb");
        let tcb = id.as_tcb_mut();
        TCB_ADDR = core::ptr::from_mut(tcb).addr();
        STACK_TOP = tcb.kernel_stack_top;
        tcb.kernel_stack_top
    };

    // SAFETY: top is the end of the TCB's own kernel stack, 16-aligned, with
    // interrupts disabled; overflow never returns, it double-faults.
    unsafe {
        core::arch::asm!(
            "mov rsp, {top}",
            "call {overflow}",
            top = in(reg) top,
            overflow = sym overflow,
            options(noreturn),
        );
    }
}

/// Recurses until the stack runs out.
#[allow(unconditional_recursion)]
extern "C" fn overflow() -> ! {
    let frame = [0_u8; 256];
    core::hint::black_box(&frame);
    overflow()
}

extern "x86-interrupt" fn double_fault(_frame: InterruptStackFrame, _code: u64) -> ! {
    // SAFETY: the statics were written before the overflow began and the TCB
    // header page is still mapped; interrupts are off, so nothing races this.
    let intact = unsafe {
        let tcb = &*core::ptr::with_exposed_provenance::<jos::cap::Tcb>(TCB_ADDR);
        tcb.state == TcbState::Inactive && tcb.kernel_stack_top == STACK_TOP
    };
    if intact {
        serial_println!("[ok]");
        exit_qemu(QemuExitCode::Success);
    } else {
        serial_println!("[failed: the overflow reached the TCB header]");
        exit_qemu(QemuExitCode::Failed);
    }
    jos::hlt_loop()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}
