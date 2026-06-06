//! Preemptive round-robin scheduler (phase 4 first step).
//!
//! This module owns the timer IDT entry. Instead of the simple
//! `extern "x86-interrupt"` handler, a `#[naked]` stub saves **all** GPRs into an
//! [`IrqFrame`] on the kernel stack and calls [`timer_irq_handler`]. The Rust
//! handler can then save the interrupted thread's context into its [`Tcb`], pick
//! the next runnable thread from the [`RunQueue`], and overwrite the frame with
//! the new thread's registers so the epilogue's `pop`s + `iretq` resume it.
//!
//! # Calling convention of the naked stub
//!
//! At IDT entry from ring 3 the CPU pushes (SS, RSP, RFLAGS, CS, RIP) onto the
//! kernel stack (RSP0 from TSS). The stub then pushes the 15 GPRs in reverse
//! order so `rax` lands at the lowest address. The resulting stack layout matches
//! [`IrqFrame`] exactly; passing `rsp` as `rdi` gives `timer_irq_handler` a
//! typed `&mut IrqFrame` pointer.
//!
//! For same-privilege (ring-0 → ring-0) timer ticks the CPU only pushes 3 words
//! (RFLAGS, CS, RIP); the stub still pushes the same 15 GPRs, but
//! `IrqFrame::user_rsp` / `IrqFrame::ss` will be garbage. The Rust handler checks
//! `frame.cs & 3 != 3` and returns early before touching those fields.
//!
//! # Stack alignment
//!
//! With a 16-byte-aligned RSP0, the CPU's 5-word push leaves RSP % 16 == 8.
//! 15 more pushes add 120 bytes (120 % 16 == 8), yielding RSP % 16 == 0.
//! The `call` instruction then makes RSP % 16 == 8 at `timer_irq_handler` entry —
//! exactly the System V AMD64 ABI requirement.

use core::sync::atomic::{AtomicUsize, Ordering};

use jos_core::run_queue::RunQueue;
use spin::Mutex;
use x86_64::structures::idt::InterruptStackFrame;

use crate::{
    cap::{SavedContext, Tcb},
    interrupts::{InterruptIndex, PICS, TICK_COUNT},
};

/// Maximum number of threads the scheduler can track.
pub const MAX_THREADS: usize = 8;

const NO_THREAD: usize = usize::MAX;

/// Raw TCB pointers indexed by scheduler thread ID.
///
/// Written once during `register_thread` (before any thread runs), read from
/// the timer IRQ. Single-CPU + interrupts disabled at write time → no races.
static mut THREAD_TABLE: [*mut Tcb; MAX_THREADS] = [core::ptr::null_mut(); MAX_THREADS];
static mut THREAD_COUNT: usize = 0;

/// FIFO run queue of ready thread IDs. Backed by `RunQueue` from jos-core.
static RUN_QUEUE: Mutex<RunQueue<MAX_THREADS>> = Mutex::new(RunQueue::new());

/// Scheduler thread ID of the thread currently on the CPU, or `NO_THREAD`.
static CURRENT: AtomicUsize = AtomicUsize::new(NO_THREAD);

/// Full register state as laid out on the kernel stack by [`timer_preempt_entry`].
///
/// The naked stub pushes GPRs in reverse order (r15 first so rax is at the
/// lowest address / `rsp` after all pushes). The CPU's interrupt frame sits
/// above the GPRs.
///
/// Field order must match the push sequence exactly; verified by the
/// `offset_of!` assertions below.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct IrqFrame {
    // gpr saves (in push order r15..rax, so rax is at lowest address)
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
    // cpu-pushed interrupt frame
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    /// User-mode stack pointer (only valid when interrupted from ring 3).
    pub user_rsp: u64,
    /// Stack segment (only valid when interrupted from ring 3).
    pub ss: u64,
}

// compile-time checks: the 15 GPR saves are 15 * 8 = 120 bytes, so the iret
// frame starts at offset 120.
const _: () = assert!(core::mem::offset_of!(IrqFrame, rip) == 120);
const _: () = assert!(core::mem::offset_of!(IrqFrame, cs) == 128);
const _: () = assert!(core::mem::size_of::<IrqFrame>() == 160);

impl IrqFrame {
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
            rsp: self.user_rsp,
            rflags: self.rflags,
            cs: self.cs,
            ss: self.ss,
        }
    }

    fn load_context(&mut self, ctx: &SavedContext) {
        self.rax = ctx.rax;
        self.rbx = ctx.rbx;
        self.rcx = ctx.rcx;
        self.rdx = ctx.rdx;
        self.rsi = ctx.rsi;
        self.rdi = ctx.rdi;
        self.rbp = ctx.rbp;
        self.r8 = ctx.r8;
        self.r9 = ctx.r9;
        self.r10 = ctx.r10;
        self.r11 = ctx.r11;
        self.r12 = ctx.r12;
        self.r13 = ctx.r13;
        self.r14 = ctx.r14;
        self.r15 = ctx.r15;
        self.rip = ctx.rip;
        self.user_rsp = ctx.rsp;
        self.rflags = ctx.rflags;
        self.cs = ctx.cs;
        self.ss = ctx.ss;
    }
}

/// Register a TCB with the scheduler and enqueue it as runnable.
///
/// Returns the scheduler thread ID (index into the internal thread table).
/// Must be called before any thread runs, with interrupts disabled.
///
/// # Safety
///
/// `tcb` must point to a live, initialized [`Tcb`] that will remain valid for
/// the lifetime of the kernel. Must be called from ring 0 with interrupts
/// disabled or before the timer is running.
pub unsafe fn register_thread(tcb: *mut Tcb) -> usize {
    // SAFETY: single-CPU; caller ensures interrupts are off at registration time.
    unsafe {
        let id = THREAD_COUNT;
        assert!(id < MAX_THREADS, "scheduler thread table full");
        THREAD_TABLE[id] = tcb;
        THREAD_COUNT += 1;
        RUN_QUEUE.lock().enqueue(id);
        id
    }
}

/// Inform the scheduler which thread is currently executing.
///
/// Call after `register_thread` and before the first `iretq` to ring 3.
pub fn set_current(id: usize) {
    CURRENT.store(id, Ordering::Relaxed);
}

/// The Rust half of the timer IRQ.
///
/// Called from [`timer_preempt_entry`] with `frame` pointing to the full
/// saved state on the kernel stack. Handles EOI, fires software timers, and —
/// when interrupted from ring 3 — runs the round-robin policy: re-enqueues the
/// current thread and, if a different thread is next, saves the current context
/// and overwrites `frame` with the new thread's context so the stub's epilogue
/// resumes it.
///
/// # Safety
///
/// Must only be called from the naked timer stub:
/// - GS already points to the kernel `CpuLocal` block (stub did `swapgs`)
/// - `frame` points to a valid [`IrqFrame`] on the kernel stack
/// - interrupts are disabled (cpu cleared IF on IRQ entry)
#[unsafe(no_mangle)]
unsafe extern "C" fn timer_irq_handler(frame: *mut IrqFrame) {
    // SAFETY: the naked stub passes a valid aligned pointer to the IrqFrame on
    // the kernel stack; it is non-null and exclusively accessible for this call.
    let frame = unsafe { &mut *frame };

    TICK_COUNT.fetch_add(1, Ordering::Relaxed);
    crate::clock::on_timer_tick();

    // send EOI before potentially-long scheduler work so the PIC can deliver
    // further interrupts as soon as IF is re-enabled.
    // SAFETY: timer is IRQ0 mapped to PIC_1_OFFSET; correct vector.
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Timer.as_u8());
    }

    // only preempt when we interrupted ring-3 code. ring-0 timer ticks just
    // update counters and return.
    if frame.cs & 3 != 3 {
        return;
    }

    let cur = CURRENT.load(Ordering::Relaxed);
    if cur == NO_THREAD {
        return;
    }

    // round-robin: re-enqueue the current thread, pick the next.
    let next = {
        let mut q = RUN_QUEUE.lock();
        q.enqueue(cur);
        q.dequeue()
    };

    let Some(next_id) = next else { return };
    if next_id == cur {
        // only one runnable thread; no switch needed.
        return;
    }

    // save current thread's user context into its TCB.
    // SAFETY: THREAD_TABLE[cur] was set by register_thread and lives for the
    // duration of the kernel.
    unsafe {
        let cur_tcb = THREAD_TABLE[cur];
        if !cur_tcb.is_null() {
            (*cur_tcb).context = frame.to_context();
        }
    }

    // overwrite the frame with the next thread's context. the stub's epilogue
    // pops these values into the hardware registers and iretq resumes the
    // new thread in ring 3.
    // SAFETY: same lifetime guarantee as above.
    unsafe {
        let next_tcb = THREAD_TABLE[next_id];
        if !next_tcb.is_null() {
            frame.load_context(&(*next_tcb).context);
            // update per-cpu block so syscalls from the new thread land on its
            // kernel stack and resolve its capability space.
            // SAFETY: ring 0, interrupts disabled (cpu cleared IF on IRQ entry).
            crate::cpu_local::switch_to(next_tcb);
        }
    }

    CURRENT.store(next_id, Ordering::Relaxed);
}

/// IDT entry point for the timer IRQ (replaces the plain `extern "x86-interrupt"`
/// handler).
///
/// Declared as `extern "x86-interrupt"` so it can be passed to
/// `Entry::set_handler_fn`; `#[naked]` prevents LLVM from emitting any
/// prologue or epilogue — only the `naked_asm!` body is emitted.
///
/// Layout invariants (see module doc):
/// - conditional `swapgs` on entry and exit keyed on saved CS
/// - 15 GPR pushes yield a valid [`IrqFrame`] at `rsp` before the call
/// - the `call` leaves the stack System V ABI-aligned at callee entry
#[unsafe(naked)]
pub extern "x86-interrupt" fn timer_preempt_entry(_frame: InterruptStackFrame) {
    // SAFETY: this is a naked function; the body is pure assembly. the
    // conditional swapgs pairs are correct (see module doc). the call to
    // timer_irq_handler satisfies the extern "C" ABI (rdi = frame pointer,
    // stack 16-aligned at callee entry). the epilogue mirrors the prologue.
    core::arch::naked_asm!(
            // conditional swapgs: kernel CS (RPL=0) is 0x08; ring-3 CS has
            // RPL=3, so any value != 0x08 means we came from user space.
            "cmp qword ptr [rsp + 8], 0x08",
            "je 1f",
            "swapgs",
            "1:",
            // save all GPRs onto the kernel stack. push in reverse SavedContext
            // order so rax ends up at the lowest address.
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
            // rsp now == &IrqFrame. pass as first argument (System V rdi).
            "mov rdi, rsp",
            "call {handler}",
            // restore GPRs (symmetric with the pushes above).
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
            // conditional swapgs on exit. cs is now at [rsp+8] again (same
            // layout as on entry; the handler may have replaced it with the
            // new thread's cs, but that is also ring-3 = != 0x08).
            "cmp qword ptr [rsp + 8], 0x08",
            "je 2f",
            "swapgs",
            "2:",
            "iretq",
            handler = sym timer_irq_handler,
    )
}
