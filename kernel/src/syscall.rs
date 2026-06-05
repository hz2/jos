//! The SYSCALL/SYSRET system-call boundary (capability slice 3b).
//!
//! Slice 3a reached ring 3 and could only return to the kernel through a fault.
//! This slice adds the real ring-3 -> ring-0 -> ring-3 path via the `syscall`
//! and `sysret` instructions, the fast system-call mechanism on `x86_64`.
//!
//! # What `syscall` does in hardware (and what we must do by hand)
//!
//! `syscall` is deliberately minimal. On execution the cpu:
//!
//! - saves the return address (`RIP` of the next user instruction) into `RCX`,
//! - saves `RFLAGS` into `R11`, then clears the bits set in the `SFMASK` MSR,
//! - loads `CS`/`SS` from the `STAR` MSR's syscall selectors (entering ring 0),
//! - jumps to the entry point in the `LSTAR` MSR.
//!
//! Crucially it does **not** switch the stack pointer: on entry `RSP` is still
//! the user stack. So the entry stub ([`syscall_entry`]) must switch to a
//! kernel stack itself before doing anything that pushes. It saves the user
//! `RSP`, loads the kernel stack, preserves the caller-saved registers the ABI
//! and the cpu rely on (`RCX` = return RIP, `R11` = saved RFLAGS), calls the
//! Rust dispatcher, then restores and executes `sysretq`, which reloads `CS`/
//! `SS` from `STAR`'s sysret selectors (returning to ring 3), restores `RFLAGS`
//! from `R11`, and jumps to `RCX`.
//!
//! # jos system-call ABI (slice 3b)
//!
//! Register-only, no IPC buffer yet (that arrives with the cap IPC syscall,
//! slice 3d). Mirrors the SysV-ish convention the user code already uses:
//!
//! | Register | Meaning |
//! |----------|---------|
//! | `rax`    | syscall number ([`Syscall`]) on entry, return value on exit |
//! | `rdi`    | argument 0 |
//! | `rsi`    | argument 1 |
//! | `rdx`    | argument 2 |
//!
//! `rcx` and `r11` are reserved by the `syscall` instruction itself and must
//! not be used to pass arguments.
//!
//! # Single-thread kernel stack (for now)
//!
//! The kernel stack the entry stub switches to is held in one static
//! ([`KERNEL_RSP`]). That is correct while jos runs a single userspace thread
//! at a time; the per-TCB version (a kernel stack per thread, swapped via
//! `KernelGsBase`/`swapgs` on entry) arrives with the retypeable `Tcb` object
//! in slice 3c.

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use x86_64::VirtAddr;
use x86_64::registers::model_specific::{Efer, EferFlags, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;

use crate::cap::{
    cap_recv, cap_send, IpcError, KernelCapSpace, Message, ObjectKind, RetypeError,
};
use crate::gdt;
use jos_core::cap_rights::Rights;
use jos_core::cap_space::InsertAtError;
use jos_core::untyped::ObjectType;

/// The system calls jos understands.
///
/// Started tiny in slice 3b (`Add`/`Exit`); slice 3d adds the capability-
/// mediated IPC calls, which is what makes this a real capability syscall
/// surface rather than a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum Syscall {
    /// `add(a, b) -> a + b` (wrapping). A pure, side-effect-free probe that
    /// proves arguments flow in and a result flows back out across the boundary.
    Add = 0,
    /// `exit(code)`: write `code` to the qemu isa-debug-exit port. Lets a
    /// ring-3 program end the test with a pass/fail verdict. Does not return.
    Exit = 1,
    /// `ipc_send(cap_slot, word) -> 0 | errno`. Sends a one-word message
    /// through the capability in slot `cap_slot` of the current task's
    /// `CSpace`. Returns 0 on success or an [`IpcSyscallError`] code. Requires
    /// the capability to carry `WRITE`; the kernel enforces this per call.
    IpcSend = 2,
    /// `ipc_recv(cap_slot) -> word | (errno | ERR_FLAG)`. Receives a one-word
    /// message through the capability in slot `cap_slot`. On success returns
    /// the message's first data word; on failure returns an error code with
    /// [`IPC_ERR_FLAG`] set (so a valid word is distinguishable from an error).
    /// Requires `READ`.
    IpcRecv = 3,
    /// `retype(untyped_slot, type_word, dest_slot) -> 0 | errno`. Carves a typed
    /// kernel object from the untyped capability in `untyped_slot` and installs
    /// a full-rights capability to it at `dest_slot` of the current `CSpace`.
    /// `type_word` packs the object type (see [`decode_object_type`]). Returns 0
    /// or a [`RetypeSyscallError`]. This is the seL4 `Retype`: userspace, not
    /// the kernel, decides when objects come into being.
    Retype = 4,
    /// `invoke(cap_slot, method, arg0) -> result | (errno | ERR_FLAG)`. Invokes
    /// a method on the object named by `cap_slot`, routed by the object's kind.
    /// The generic capability-invocation syscall; today it covers Endpoint
    /// send/recv (the same primitives [`Syscall::IpcSend`]/[`Syscall::IpcRecv`]
    /// expose directly). Errors carry [`IPC_ERR_FLAG`].
    Invoke = 5,
}

impl Syscall {
    // maps a raw syscall number to its enum form, or None if unknown.
    fn from_u64(n: u64) -> Option<Self> {
        match n {
            0 => Some(Self::Add),
            1 => Some(Self::Exit),
            2 => Some(Self::IpcSend),
            3 => Some(Self::IpcRecv),
            4 => Some(Self::Retype),
            5 => Some(Self::Invoke),
            _ => None,
        }
    }
}

/// Sentinel returned in `rax` when the syscall number is not recognized.
pub const ENOSYS: u64 = u64::MAX;

/// Error codes returned by [`Syscall::IpcSend`] (in `rax`, 0 meaning success).
///
/// Distinct small non-zero values so a userspace program can tell *why* an IPC
/// call failed: a stale capability, a missing right, the wrong object type, or
/// a full/empty endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum IpcSyscallError {
    /// The slot index is out of range or names no live capability.
    BadCap = 1,
    /// The capability lacks the right this operation needs (`WRITE`/`READ`).
    Denied = 2,
    /// The capability does not name an endpoint.
    NotEndpoint = 3,
    /// `send` to a full endpoint, or `recv` from an empty one (non-blocking).
    WouldBlock = 4,
}

/// Bit OR-ed into an [`Syscall::IpcRecv`] return value to mark it an error
/// rather than a received data word. The high bit, so any real message word
/// below `1 << 63` is unambiguous.
pub const IPC_ERR_FLAG: u64 = 1 << 63;

/// Error codes returned by [`Syscall::Retype`] (in `rax`, 0 meaning success).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum RetypeSyscallError {
    /// The untyped slot is out of range or names no live capability.
    BadCap = 1,
    /// The named capability is live but is not an untyped region.
    NotUntyped = 2,
    /// `type_word` had an unknown discriminant or malformed reserved bits.
    BadArgs = 3,
    /// The untyped region has no room for the requested object.
    NoRoom = 4,
    /// The destination slot already holds a live capability.
    DestOccupied = 5,
    /// The destination slot is out of range (`>= CSPACE_SLOTS`).
    DestOutOfRange = 6,
    /// The region is too misaligned for the requested object.
    BadAlign = 7,
    /// The requested object type cannot be carved via the syscall.
    BadType = 8,
}

/// Error codes returned by [`Syscall::Invoke`] (OR-ed with [`IPC_ERR_FLAG`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum InvokeError {
    /// The cap slot is out of range or names no live capability.
    BadCap = 1,
    /// The capability lacks the right the method needs.
    Denied = 2,
    /// The method label is not defined for this object kind.
    BadMethod = 3,
    /// A would-block condition (endpoint full on send / empty on recv).
    WouldBlock = 4,
}

/// Userspace-visible [`ObjectType`] discriminants for the `type_word` of a
/// [`Syscall::Retype`]. Stable across the boundary (the Rust `ObjectType`
/// discriminants are compiler-assigned and must not leak to userspace).
pub mod object_type_id {
    /// A synchronous IPC endpoint.
    pub const ENDPOINT: u8 = 0;
    /// A capability node (capability space).
    pub const CNODE: u8 = 1;
    /// An untyped sub-region.
    pub const UNTYPED: u8 = 2;
    /// A page table.
    pub const PAGE_TABLE: u8 = 3;
    /// A thread control block.
    pub const TCB: u8 = 4;
}

// decodes a retype `type_word` into an ObjectType. bits [7:0] are the type
// discriminant (object_type_id), bits [15:8] are size_bits (for CNode/Untyped;
// must be 0 for fixed-size types), bits [63:16] must be zero. returns None for
// an unknown discriminant or malformed reserved/size bits.
fn decode_object_type(type_word: u64) -> Option<ObjectType> {
    if type_word >> 16 != 0 {
        return None; // reserved bits must be zero
    }
    let discriminant = (type_word & 0xFF) as u8;
    let size_bits = ((type_word >> 8) & 0xFF) as u8;
    match discriminant {
        object_type_id::ENDPOINT if size_bits == 0 => Some(ObjectType::Endpoint),
        object_type_id::PAGE_TABLE if size_bits == 0 => Some(ObjectType::PageTable),
        object_type_id::TCB if size_bits == 0 => Some(ObjectType::Tcb),
        object_type_id::CNODE => Some(ObjectType::CNode { size_bits }),
        object_type_id::UNTYPED => Some(ObjectType::Untyped { size_bits }),
        // unknown discriminant, or a fixed-size type given a non-zero size_bits.
        _ => None,
    }
}

/// The kernel stack pointer the syscall entry stub switches to on entry.
///
/// Set by [`set_kernel_stack`] before dropping to user mode. A single slot
/// suffices for one userspace thread; slice 3c replaces it with a per-thread
/// stack selected via `KernelGsBase`.
static KERNEL_RSP: AtomicU64 = AtomicU64::new(0);

/// Records the kernel stack pointer the next syscall entry will switch to.
///
/// Call with the top of a valid kernel stack before [`crate::usermode::
/// enter_user_mode`]. The value is read by the assembly entry stub.
pub fn set_kernel_stack(rsp: VirtAddr) {
    KERNEL_RSP.store(rsp.as_u64(), Ordering::SeqCst);
}

/// The current task's capability space, resolved per IPC syscall.
///
/// The IPC syscalls take a capability *slot index* from userspace and resolve
/// it against this `CSpace` on every call (via `ref_at`, which reconstructs the
/// generation-checked `CapRef`), rather than borrowing a Rust reference once.
/// That per-call resolution is exactly what lets a revoked capability be
/// rejected on the next syscall, the property the slice-2b borrow-based API
/// could not provide.
///
/// A single slot holds the one userspace task's `CSpace` for now; the per-`Tcb`
/// `CSpace` root (a retypeable `CNode`) is deferred. Stored as a raw pointer to
/// a kernel-owned `CapSpace`; the kernel is single-threaded across syscalls.
static CURRENT_CSPACE: AtomicPtr<KernelCapSpace> = AtomicPtr::new(core::ptr::null_mut());

/// Installs `cspace` as the current task's capability space for IPC syscalls.
///
/// # Safety
///
/// `cspace` must point to a `KernelCapSpace` that outlives every syscall made
/// while it is installed (in practice a `'static` kernel object), and must not
/// be mutated concurrently (jos is single-threaded across the syscall path).
pub unsafe fn set_current_cspace(cspace: *mut KernelCapSpace) {
    CURRENT_CSPACE.store(cspace, Ordering::SeqCst);
}

/// Programs the syscall MSRs so `syscall`/`sysret` work. Call once during
/// kernel init, after [`gdt::init_gdt`] (it needs the segment selectors).
///
/// # Panics
///
/// Panics if the GDT selectors are laid out such that `STAR` cannot be
/// programmed (they are, by construction in [`gdt`]; this would be a bug).
pub fn init_syscall() {
    let sel = gdt::selectors();

    // STAR holds the syscall/sysret segment bases. The x86_64 crate validates
    // the seL4-style layout for us: sysret CS = base + 16, SS = base + 8;
    // syscall CS = base, SS = base + 8. Our gdt order (kernel_code, kernel_data,
    // user_data, user_code) is exactly what makes this consistent:
    //   syscall: cs = kernel_code, ss = kernel_data (= kernel_code + 8)
    //   sysret:  the base is user_data, so cs = user_data + 16 = user_code,
    //            ss = user_data + 8 = ... the crate computes ss_sysret = base,
    //            i.e. user_data, and cs_sysret = base + 16 = user_code.
    Star::write(sel.user_code, sel.user_data, sel.kernel_code, sel.kernel_data)
        .expect("STAR selectors must satisfy the syscall/sysret layout");

    // LSTAR is the entry point the cpu jumps to on syscall.
    LStar::write(VirtAddr::new(syscall_entry as *const () as usize as u64));

    // SFMASK: the RFLAGS bits cleared on syscall entry. Clearing IF means
    // interrupts are masked inside the entry stub until we choose otherwise,
    // so the half-built kernel frame (before the stack switch completes) cannot
    // be interrupted. Also clear the direction and trap flags for a sane kernel
    // entry state.
    SFMask::write(RFlags::INTERRUPT_FLAG | RFlags::DIRECTION_FLAG | RFlags::TRAP_FLAG);

    // finally enable the syscall/sysret instructions in EFER.
    // SAFETY: we set only the SYSTEM_CALL_EXTENSIONS bit; Efer::write preserves
    // the reserved bits and the existing long-mode flags, so this cannot
    // disable long mode or otherwise break memory safety. LSTAR/STAR/SFMASK are
    // already programmed above, so the first syscall has a valid target.
    unsafe {
        Efer::write(Efer::read() | EferFlags::SYSTEM_CALL_EXTENSIONS);
    }
}

/// The Rust system-call dispatcher, called by [`syscall_entry`] with the user
/// arguments already in C-ABI registers.
///
/// Returns the value to place in the user's `rax`. `Syscall::Exit` does not
/// return (it ends the qemu session); every other call returns a `u64`.
///
/// `extern "C"` so the assembly stub can call it with the standard argument
/// registers (`rdi`, `rsi`, `rdx`, `rcx`) holding (nr, arg0, arg1, arg2).
extern "C" fn dispatch_syscall(nr: u64, arg0: u64, arg1: u64, arg2: u64) -> u64 {
    match Syscall::from_u64(nr) {
        Some(Syscall::Add) => arg0.wrapping_add(arg1),
        Some(Syscall::Exit) => {
            // arg0 is the exit code; map the two known codes, default to Failed.
            let code = match arg0 {
                0x10 => crate::QemuExitCode::Success,
                _ => crate::QemuExitCode::Failed,
            };
            crate::exit_qemu(code);
            // exit_qemu returns if the debug-exit device is absent; halt so we
            // never fall back into user mode with a bogus result.
            crate::hlt_loop();
        }
        // ipc_send(cap_slot = arg0, word = arg1) -> 0 | errno.
        Some(Syscall::IpcSend) => sys_ipc_send(arg0, arg1),
        // ipc_recv(cap_slot = arg0) -> word | (errno | IPC_ERR_FLAG).
        Some(Syscall::IpcRecv) => sys_ipc_recv(arg0),
        // retype(untyped_slot = arg0, type_word = arg1, dest_slot = arg2).
        Some(Syscall::Retype) => sys_retype(arg0, arg1, arg2),
        // invoke(cap_slot = arg0, method = arg1, arg0_word = arg2).
        Some(Syscall::Invoke) => sys_invoke(arg0, arg1, arg2),
        None => ENOSYS,
    }
}

// resolves the current task's CSpace for MUTATION (retype installs a capability
// via insert_at). same pointer as current_cspace, but exclusive.
//
// SAFETY note: returns an exclusive reference to the kernel-owned CapSpace
// behind CURRENT_CSPACE; sound on the single-threaded syscall path where
// set_current_cspace's contract guarantees the pointer is live and unaliased,
// and no other reference is taken for the duration of the call.
fn current_cspace_mut() -> Option<&'static mut KernelCapSpace> {
    let ptr = CURRENT_CSPACE.load(Ordering::SeqCst);
    if ptr.is_null() {
        return None;
    }
    // SAFETY: as current_cspace, but exclusive; single-threaded syscall path, no
    // aliasing reference is live across this call.
    Some(unsafe { &mut *ptr })
}

// resolves the current task's CSpace, the one IPC syscalls address capabilities
// in. returns None if no CSpace is installed (a kernel setup bug).
//
// SAFETY note: the returned reference borrows the kernel-owned CapSpace behind
// CURRENT_CSPACE; the caller (an IPC syscall handler) uses it only within the
// single-threaded syscall path, where set_current_cspace's contract guarantees
// the pointer is live and unaliased.
fn current_cspace() -> Option<&'static KernelCapSpace> {
    let ptr = CURRENT_CSPACE.load(Ordering::SeqCst);
    if ptr.is_null() {
        return None;
    }
    // SAFETY: ptr was installed via set_current_cspace, whose contract requires
    // it to point at a live, 'static, non-concurrently-mutated KernelCapSpace.
    // jos is single-threaded across syscalls, so no aliasing &mut exists.
    Some(unsafe { &*ptr })
}

// maps an IpcError from the cap layer to the userspace-visible errno. the cap
// layer distinguishes more cases than userspace needs, so several collapse.
fn ipc_errno(e: IpcError) -> u64 {
    let code = match e {
        IpcError::InvalidCap => IpcSyscallError::BadCap,
        IpcError::InsufficientRights => IpcSyscallError::Denied,
        IpcError::NotAnEndpoint => IpcSyscallError::NotEndpoint,
        IpcError::EndpointBusy | IpcError::EndpointEmpty => IpcSyscallError::WouldBlock,
    };
    code as u64
}

// ipc_send: resolve cap_slot in the current CSpace per call, then send a
// one-word message. the per-call resolution (ref_at reconstructs the
// generation-checked CapRef) is what makes a revoked capability fail here
// rather than the borrow being held across the block.
fn sys_ipc_send(cap_slot: u64, word: u64) -> u64 {
    let Some(space) = current_cspace() else {
        return IpcSyscallError::BadCap as u64;
    };
    let Ok(slot) = usize::try_from(cap_slot) else {
        return IpcSyscallError::BadCap as u64;
    };
    // resolve the slot index to a live, generation-checked CapRef in OUR table.
    // an out-of-range or empty slot yields None -> BadCap.
    let Some(cap_ref) = space.ref_at(slot) else {
        return IpcSyscallError::BadCap as u64;
    };
    let message = Message {
        label: 0,
        words: [word, 0, 0, 0],
    };
    match cap_send(space, cap_ref, message) {
        Ok(()) => 0,
        Err(e) => ipc_errno(e),
    }
}

// ipc_recv: resolve cap_slot per call, then receive a one-word message. returns
// the message's first word on success, or (errno | IPC_ERR_FLAG) on failure so
// userspace can distinguish a real word from an error.
fn sys_ipc_recv(cap_slot: u64) -> u64 {
    let Some(space) = current_cspace() else {
        return IpcSyscallError::BadCap as u64 | IPC_ERR_FLAG;
    };
    let Ok(slot) = usize::try_from(cap_slot) else {
        return IpcSyscallError::BadCap as u64 | IPC_ERR_FLAG;
    };
    let Some(cap_ref) = space.ref_at(slot) else {
        return IpcSyscallError::BadCap as u64 | IPC_ERR_FLAG;
    };
    match cap_recv(space, cap_ref) {
        Ok(message) => message.words[0],
        Err(e) => ipc_errno(e) | IPC_ERR_FLAG,
    }
}

// retype: carve a typed object from the untyped cap in `untyped_slot` and
// install a full-rights capability to it at `dest_slot`. the seL4 Retype, with
// the source untyped and the destination both named by CSpace slots (resolved
// per call), so userspace can only create objects from untyped it was handed.
fn sys_retype(untyped_slot: u64, type_word: u64, dest_slot: u64) -> u64 {
    use crate::cap::CSPACE_SLOTS;
    let err = |e: RetypeSyscallError| e as u64;

    // decode the requested object type before touching the CSpace.
    let Some(ty) = decode_object_type(type_word) else {
        return err(RetypeSyscallError::BadArgs);
    };
    let (Ok(uslot), Ok(dslot)) = (usize::try_from(untyped_slot), usize::try_from(dest_slot)) else {
        return err(RetypeSyscallError::BadCap);
    };
    if dslot >= CSPACE_SLOTS {
        return err(RetypeSyscallError::DestOutOfRange);
    }

    let Some(space) = current_cspace_mut() else {
        return err(RetypeSyscallError::BadCap);
    };
    // resolve the untyped source: must be a live cap naming an untyped region.
    let Some(usource) = space.ref_at(uslot) else {
        return err(RetypeSyscallError::BadCap);
    };
    let untyped_obj = match space.lookup(usource) {
        Some(cap) if cap.object.kind() == ObjectKind::Untyped => cap.object,
        Some(_) => return err(RetypeSyscallError::NotUntyped),
        None => return err(RetypeSyscallError::BadCap),
    };
    // the destination must be free BEFORE we carve, so a failure leaves the
    // untyped watermark untouched (no half-done carve into an occupied slot).
    if space.ref_at(dslot).is_some() {
        return err(RetypeSyscallError::DestOccupied);
    }

    // carve the object from the untyped region.
    // SAFETY: untyped_obj is a live cap of kind Untyped (checked); the region is
    // a 'static kernel object; single-threaded syscall path, so no aliasing &mut
    // to it exists. retype_object mutates only the region's own watermark.
    let region = unsafe { untyped_obj.as_untyped_mut() };
    let new_obj = match region.retype_object(ty) {
        Ok(id) => id,
        Err(RetypeError::NoRoom) => return err(RetypeSyscallError::NoRoom),
        Err(RetypeError::BadAlign) => return err(RetypeSyscallError::BadAlign),
        Err(RetypeError::BadType) => return err(RetypeSyscallError::BadType),
    };

    // install a full-rights capability to the new object at the dest slot.
    match space.insert_at(dslot, new_obj, Rights::all()) {
        Ok(_) => 0,
        // the dest was free a moment ago and nothing else runs concurrently, so
        // these are not expected; map them faithfully rather than unwrap.
        Err(InsertAtError::Occupied) => err(RetypeSyscallError::DestOccupied),
        Err(InsertAtError::OutOfRange) => err(RetypeSyscallError::DestOutOfRange),
    }
}

// invoke: a generic capability invocation routed by the named object's kind.
// today only Endpoint methods (Send/Recv) are defined; they reuse the IPC
// primitives, so SYS_INVOKE(Endpoint, Send/Recv) is equivalent to the dedicated
// IPC syscalls, proving the generic dispatch path.
fn sys_invoke(cap_slot: u64, method: u64, arg0: u64) -> u64 {
    // endpoint method labels.
    const ENDPOINT_SEND: u64 = 0;
    const ENDPOINT_RECV: u64 = 1;
    let err = |e: InvokeError| e as u64 | IPC_ERR_FLAG;

    let Some(space) = current_cspace() else {
        return err(InvokeError::BadCap);
    };
    let Ok(slot) = usize::try_from(cap_slot) else {
        return err(InvokeError::BadCap);
    };
    let Some(cap_ref) = space.ref_at(slot) else {
        return err(InvokeError::BadCap);
    };
    let Some(cap) = space.lookup(cap_ref) else {
        return err(InvokeError::BadCap);
    };
    match cap.object.kind() {
        ObjectKind::Endpoint => match method {
            ENDPOINT_SEND => {
                let message = Message {
                    label: 0,
                    words: [arg0, 0, 0, 0],
                };
                match cap_send(space, cap_ref, message) {
                    Ok(()) => 0,
                    Err(e) => invoke_errno(e),
                }
            }
            ENDPOINT_RECV => match cap_recv(space, cap_ref) {
                Ok(message) => message.words[0],
                Err(e) => invoke_errno(e),
            },
            _ => err(InvokeError::BadMethod),
        },
        // no methods defined for the other object kinds yet.
        _ => err(InvokeError::BadMethod),
    }
}

// maps an IpcError to an Invoke return value (errno OR'd with IPC_ERR_FLAG).
fn invoke_errno(e: IpcError) -> u64 {
    let code = match e {
        IpcError::InvalidCap => InvokeError::BadCap,
        IpcError::InsufficientRights => InvokeError::Denied,
        IpcError::NotAnEndpoint => InvokeError::BadMethod,
        IpcError::EndpointBusy | IpcError::EndpointEmpty => InvokeError::WouldBlock,
    };
    code as u64 | IPC_ERR_FLAG
}

// the raw syscall entry point installed in LSTAR. it runs in ring 0 with the
// USER stack still in rsp (syscall does not switch stacks), so it must switch
// to the kernel stack before touching memory through the stack.
//
// written as a global_asm symbol (not a naked fn) so the compiler emits no
// stack frame of its own: rsp is still the user stack on entry, so any
// compiler-generated prologue would push onto user memory. the whole body is
// one assembly block.
//
// register discipline (jos syscall ABI, slice 3b):
//   on entry  rcx = user return RIP, r11 = user RFLAGS (both set by `syscall`);
//             rax = syscall nr; rdi/rsi/rdx = args 0/1/2.
//   a syscall is treated like a C call: caller-saved registers may be clobbered
//   by the dispatcher; rcx and r11 are reserved by the instruction; rax holds
//   the return value on the way out.
//
// stack alignment: the SysV C ABI requires rsp % 16 == 0 at a `call`. KERNEL_RSP
// is 16-aligned (see set_kernel_stack), so three 8-byte pushes leave rsp % 16
// == 8; an explicit 8-byte pad restores 16 before the call and is undone after.
core::arch::global_asm!(
    ".global syscall_entry",
    "syscall_entry:",
    // save the user stack pointer into a scratch register the SysV ABI lets us
    // clobber (r10 is caller-saved and untouched by `syscall`), then switch to
    // the kernel stack loaded from KERNEL_RSP.
    "mov r10, rsp",                 // r10 = user rsp
    "mov rsp, [rip + {kernel_rsp}]",// rsp = kernel stack top (16-aligned)
    // preserve the values sysretq depends on, plus the user rsp, on the kernel
    // stack across the dispatcher call.
    "push r10",                     // [kernel stack] user rsp        rsp%16=8
    "push rcx",                     // user return RIP (sysretq uses)  rsp%16=0
    "push r11",                     // user RFLAGS (sysretq uses)      rsp%16=8
    "sub rsp, 8",                   // align to 16 for the call        rsp%16=0
    // marshal the jos ABI (nr in rax, args in rdi/rsi/rdx) into the C ABI the
    // dispatcher expects: dispatch_syscall(nr, arg0, arg1, arg2) lands in
    // rdi, rsi, rdx, rcx. this is a register rotation; the move order is chosen
    // so each source is read before it is overwritten, and it runs AFTER the
    // pushes so rcx's user value is already safe on the stack.
    "mov rcx, rdx",                 // arg2 -> 4th C arg (rcx)
    "mov rdx, rsi",                 // arg1 -> 3rd C arg (rdx)
    "mov rsi, rdi",                 // arg0 -> 2nd C arg (rsi)
    "mov rdi, rax",                 // nr   -> 1st C arg (rdi)
    "call {dispatch}",              // rax = return value
    // tear down: drop the alignment pad, restore the syscall-return state and
    // the user stack, then return to ring 3.
    "add rsp, 8",                   // drop alignment pad
    "pop r11",                      // user RFLAGS
    "pop rcx",                      // user return RIP
    "pop r10",                      // user rsp
    "mov rsp, r10",                 // back onto the user stack
    "sysretq",                      // -> ring 3 at rcx, RFLAGS = r11
    kernel_rsp = sym KERNEL_RSP,
    dispatch = sym dispatch_syscall,
);

unsafe extern "C" {
    /// The assembly syscall entry point (defined in the `global_asm!` above).
    /// Its address is written to `LSTAR`.
    fn syscall_entry();
}
