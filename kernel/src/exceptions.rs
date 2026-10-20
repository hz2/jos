//! CPU exceptions: an entry stub for every vector a thread can raise, and
//! what happens next.
//!
//! An exception in ring 0 is a kernel bug and stops the machine loudly, except
//! the two traps (`#DB`, `#BP`), which resume. An exception in ring 3 is the
//! faulting thread's business and never the kernel's: the thread is parked as
//! if it had made a `call` on its fault endpoint, with the fault as the
//! message (the seL4 model). Whoever receives it with a reply object can map a
//! page, fix a register, or give up; a reply resumes the thread at the
//! faulting instruction with its registers as they were. A thread with no
//! usable fault endpoint is stopped, and only it: everything else keeps
//! running. Kernel tests, which have no root task, still fail fast on a fault,
//! and a fault in the root task itself halts the machine, since nothing could
//! answer it.
//!
//! The stubs push a uniform frame (a zero error code for the vectors without
//! one, then the vector), swap to the kernel GS only when the exception came
//! from ring 3, save every general register as an [`ExceptionFrame`], and call
//! [`exception_handler`].

use core::mem::offset_of;

use jos_core::abi::{FaultKind, fault_message};
use x86_64::VirtAddr;
use x86_64::structures::idt::InterruptDescriptorTable;

use crate::cap::{SavedContext, Tcb, TcbState};

/// The state an exception stub saves: the general registers, the vector and
/// error code the stub pushed, and the frame the CPU pushed.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ExceptionFrame {
    /// General registers, in push order from r15 down to rax.
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// The exception vector.
    pub vector: u64,
    /// The error code the CPU pushed, or zero for vectors without one.
    pub error_code: u64,
    /// The instruction that faulted (or, for a trap, the one after it).
    pub rip: u64,
    /// The interrupted code segment; its low bits are the privilege level.
    pub cs: u64,
    /// The interrupted flags.
    pub rflags: u64,
    /// The interrupted stack pointer.
    pub rsp: u64,
    /// The interrupted stack segment.
    pub ss: u64,
}

const _: () = assert!(offset_of!(ExceptionFrame, vector) == 120);
const _: () = assert!(offset_of!(ExceptionFrame, rip) == 136);
const _: () = assert!(offset_of!(ExceptionFrame, cs) == 144);
const _: () = assert!(core::mem::size_of::<ExceptionFrame>() == 176);

impl ExceptionFrame {
    /// The interrupted thread's registers, as a TCB saves them.
    fn to_context(self) -> SavedContext {
        SavedContext {
            rax: self.rax,
            rbx: self.rbx,
            rcx: self.rcx,
            rdx: self.rdx,
            rsi: self.rsi,
            rdi: self.rdi,
            rbp: self.rbp,
            r8: self.r8,
            r9: self.r9,
            r10: self.r10,
            r11: self.r11,
            r12: self.r12,
            r13: self.r13,
            r14: self.r14,
            r15: self.r15,
            rip: self.rip,
            rsp: self.rsp,
            rflags: self.rflags,
            cs: self.cs,
            ss: self.ss,
        }
    }
}

// one stub per vector: those without an error code push a zero in its place,
// then every stub pushes its vector and joins the common path. the cpu aligned
// rsp to 16 before its five or six words, so after the stub's words and the 15
// registers rsp is aligned again at the call.
macro_rules! stubs {
    ($(($label:literal, $vector:literal, $pushes_error:literal)),* $(,)?) => {
        core::arch::global_asm!(
            $(
                concat!(".global ", $label),
                concat!($label, ":"),
                concat!(".if ", $pushes_error, " == 0"),
                "push 0",
                ".endif",
                concat!("push ", $vector),
                "jmp jos_exception_common",
            )*
            "jos_exception_common:",
            // [rsp] vector, [rsp + 8] error, [rsp + 16] rip, [rsp + 24] cs.
            "cmp qword ptr [rsp + 24], 0x08",
            "je 1f",
            "swapgs",
            "1:",
            "push r15",
            "push r14",
            "push r13",
            "push r12",
            "push r11",
            "push r10",
            "push r9",
            "push r8",
            "push rbp",
            "push rdi",
            "push rsi",
            "push rdx",
            "push rcx",
            "push rbx",
            "push rax",
            // the call needs DF clear; iretq restores the interrupted flags.
            "cld",
            "mov rdi, rsp",
            "call {handler}",
            "pop rax",
            "pop rbx",
            "pop rcx",
            "pop rdx",
            "pop rsi",
            "pop rdi",
            "pop rbp",
            "pop r8",
            "pop r9",
            "pop r10",
            "pop r11",
            "pop r12",
            "pop r13",
            "pop r14",
            "pop r15",
            "cmp qword ptr [rsp + 24], 0x08",
            "je 2f",
            "swapgs",
            "2:",
            // drop the vector and the error code.
            "add rsp, 16",
            "iretq",
            handler = sym exception_handler,
        );
    };
}

stubs!(
    ("jos_exception_0", 0, 0),
    ("jos_exception_1", 1, 0),
    ("jos_exception_3", 3, 0),
    ("jos_exception_4", 4, 0),
    ("jos_exception_5", 5, 0),
    ("jos_exception_6", 6, 0),
    ("jos_exception_7", 7, 0),
    ("jos_exception_10", 10, 1),
    ("jos_exception_11", 11, 1),
    ("jos_exception_12", 12, 1),
    ("jos_exception_13", 13, 1),
    ("jos_exception_14", 14, 1),
    ("jos_exception_16", 16, 0),
    ("jos_exception_17", 17, 1),
    ("jos_exception_19", 19, 0),
    ("jos_exception_20", 20, 0),
    ("jos_exception_21", 21, 1),
);

unsafe extern "C" {
    /// The entry stubs defined by [`stubs!`].
    fn jos_exception_0();
    fn jos_exception_1();
    fn jos_exception_3();
    fn jos_exception_4();
    fn jos_exception_5();
    fn jos_exception_6();
    fn jos_exception_7();
    fn jos_exception_10();
    fn jos_exception_11();
    fn jos_exception_12();
    fn jos_exception_13();
    fn jos_exception_14();
    fn jos_exception_16();
    fn jos_exception_17();
    fn jos_exception_19();
    fn jos_exception_20();
    fn jos_exception_21();
}

/// Points every exception vector a thread can raise at its stub. The double
/// fault keeps its own handler on its IST stack, and NMI and machine checks
/// are not a thread's doing.
///
/// # Safety
///
/// Call once while building the IDT, before it is loaded.
pub unsafe fn install(idt: &mut InterruptDescriptorTable) {
    let addr = |stub: unsafe extern "C" fn()| VirtAddr::new(stub as usize as u64);
    // SAFETY: each address is a stub above, which saves the full state,
    // handles the GS swap for both privilege levels, and returns with iretq.
    unsafe {
        idt.divide_error.set_handler_addr(addr(jos_exception_0));
        idt.debug.set_handler_addr(addr(jos_exception_1));
        // int3 from ring 3 must reach the gate, so its privilege is 3.
        idt.breakpoint
            .set_handler_addr(addr(jos_exception_3))
            .set_privilege_level(x86_64::PrivilegeLevel::Ring3);
        idt.overflow.set_handler_addr(addr(jos_exception_4));
        idt.bound_range_exceeded.set_handler_addr(addr(jos_exception_5));
        idt.invalid_opcode.set_handler_addr(addr(jos_exception_6));
        idt.device_not_available.set_handler_addr(addr(jos_exception_7));
        idt.invalid_tss.set_handler_addr(addr(jos_exception_10));
        idt.segment_not_present.set_handler_addr(addr(jos_exception_11));
        idt.stack_segment_fault.set_handler_addr(addr(jos_exception_12));
        idt.general_protection_fault.set_handler_addr(addr(jos_exception_13));
        idt.page_fault.set_handler_addr(addr(jos_exception_14));
        idt.x87_floating_point.set_handler_addr(addr(jos_exception_16));
        idt.alignment_check.set_handler_addr(addr(jos_exception_17));
        idt.simd_floating_point.set_handler_addr(addr(jos_exception_19));
        idt.virtualization.set_handler_addr(addr(jos_exception_20));
        idt.cp_protection_exception.set_handler_addr(addr(jos_exception_21));
    }
}

/// The Rust half of every exception stub.
///
/// # Safety
///
/// Only the stubs call this, with `frame` pointing at the state they saved,
/// interrupts disabled, and GS holding the per-CPU block.
#[unsafe(no_mangle)]
unsafe extern "C" fn exception_handler(frame: *mut ExceptionFrame) {
    // SAFETY: the stub passes the frame it just pushed on this stack.
    let frame = unsafe { &mut *frame };
    if frame.cs & 3 != 3 {
        kernel_exception(frame);
        return;
    }
    // SAFETY: forwarded; a ring-3 exception runs on the thread's kernel stack.
    unsafe { user_fault(frame) }
}

/// A vector, as a log line names it: its kind, or the bare number.
struct Vector(u64);

impl core::fmt::Display for Vector {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match FaultKind::from_vector(self.0) {
            Some(kind) => write!(f, "{kind:?}"),
            None => write!(f, "vector {}", self.0),
        }
    }
}

/// An exception in ring 0. Traps resume; anything else is a kernel bug.
fn kernel_exception(frame: &ExceptionFrame) {
    if frame.vector == 1 || frame.vector == 3 {
        crate::serial_println!("EXCEPTION: {} in the kernel at {:#x}; resuming", Vector(frame.vector), frame.rip);
        return;
    }
    crate::serial_println!("EXCEPTION: {} in the kernel", Vector(frame.vector));
    crate::serial_println!(
        "  rip {:#x}, error code {:#x}, address {:#x}, rsp {:#x}",
        frame.rip,
        frame.error_code,
        fault_address(frame),
        frame.rsp
    );
    // the kernel cannot carry on; fail a test run rather than hang it.
    crate::exit_qemu(crate::QemuExitCode::Failed);
    crate::hlt_loop();
}

/// The address a page fault was about (`CR2`), or zero for other faults.
fn fault_address(frame: &ExceptionFrame) -> u64 {
    if frame.vector == 14 {
        x86_64::registers::control::Cr2::read_raw()
    } else {
        0
    }
}

/// An exception in ring 3: deliver it to the thread's fault endpoint, or stop
/// the thread, then run whatever else is ready. Never returns to the thread.
///
/// # Safety
///
/// As [`exception_handler`], for an exception from ring 3.
unsafe fn user_fault(frame: &ExceptionFrame) -> ! {
    // SAFETY: the per-CPU block is read with interrupts off.
    let tcb: *mut Tcb = unsafe { (*crate::cpu_local::cpu_local_ptr()).current_tcb };
    let id = crate::sched::current_thread_id();
    let message = fault_message(frame.vector, fault_address(frame), frame.rip, frame.error_code);
    if tcb.is_null() || id == usize::MAX {
        // a ring-3 program the scheduler does not know (an early test): nothing
        // can answer it.
        stop_machine(frame);
    }
    // SAFETY: switch_to installed a live TCB as current; interrupts are off.
    unsafe {
        // an answer resumes the thread at the faulting instruction, as it was.
        (*tcb).context = frame.to_context();
        let delivered = match crate::syscall::fault_endpoint(&*tcb) {
            Some((endpoint, badge)) => {
                (*tcb).state = TcbState::Faulted;
                crate::syscall::deliver_fault(id, endpoint, badge, &message)
            }
            None => false,
        };
        if !delivered {
            stop_thread(tcb, frame);
        }
    }
    crate::sched::enter_idle_from_syscall()
}

/// Stops a faulting thread that nothing can answer, and only it; in a kernel
/// test (no root task) or for the root task itself, the machine stops instead.
///
/// # Safety
///
/// `tcb` is the current thread's live TCB; interrupts are off.
unsafe fn stop_thread(tcb: *mut Tcb, frame: &ExceptionFrame) {
    let root = crate::rootserver::root_tcb();
    if root.is_null() || core::ptr::eq(root, tcb) {
        stop_machine(frame);
    }
    crate::serial_println!(
        "jos: thread {} stopped by an unhandled {} at {:#x} (address {:#x}, error {:#x})",
        crate::sched::current_thread_id(),
        Vector(frame.vector),
        frame.rip,
        fault_address(frame),
        frame.error_code
    );
    crate::syscall::retire_threads(|t| core::ptr::eq(t, tcb));
}

/// Reports a fault nothing can answer and stops the machine with failure.
fn stop_machine(frame: &ExceptionFrame) -> ! {
    crate::serial_println!("EXCEPTION: unhandled {} in ring 3", Vector(frame.vector));
    crate::serial_println!(
        "  rip {:#x}, error code {:#x}, address {:#x}, rsp {:#x}",
        frame.rip,
        frame.error_code,
        fault_address(frame),
        frame.rsp
    );
    crate::exit_qemu(crate::QemuExitCode::Failed);
    crate::hlt_loop()
}
