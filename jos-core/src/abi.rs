//! The system-call ABI, shared by the kernel and userspace.
//!
//! Everything a ring-3 program and the kernel must agree on lives here: the
//! syscall numbers, the error codes each call returns, the object type ids a
//! `retype` names, the mapping flags, and how packed arguments are laid out.
//! The kernel dispatches on these definitions and userspace builds its calls
//! from them, so the two sides cannot drift apart. `docs/syscalls.md` is the
//! human-readable map of the same ground.
//!
//! # Calling convention
//!
//! | register | role |
//! |---|---|
//! | `rax` | syscall number on entry; result on return |
//! | `rdi`, `rsi`, `rdx` | arguments 0, 1, 2 |
//! | `rdx` | second result on return (the sender's badge after a receive) |
//! | `rcx`, `r11` | clobbered by `syscall` itself |
//!
//! The kernel does not restore `rdi`, `rsi`, `r8`, `r9`, or `r10` either, so a
//! caller must treat them as clobbered.
//!
//! Calls that return data (a received word, a slot, a count) report errors with
//! [`IPC_ERR_FLAG`] set, so any value below `1 << 63` is a real result. Calls
//! that only succeed or fail return `0` or a plain error code.

use crate::untyped::ObjectType;

/// The system calls jos understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum Syscall {
    /// `add(a, b) -> a + b` (wrapping). A pure, side-effect-free probe that
    /// proves arguments flow in and a result flows back out across the boundary.
    Add = 0,
    /// `exit(code)`: write `code` to the qemu isa-debug-exit port. Lets a
    /// ring-3 test program end the run with a pass/fail verdict. Does not
    /// return.
    Exit = 1,
    /// `ipc_send(cap_slot, word) -> 0 | errno`. Sends a one-word message
    /// through the capability in slot `cap_slot` of the current task's
    /// `CSpace`. Returns 0 on success or an [`IpcSyscallError`] code. Requires
    /// the capability to carry `WRITE`; the kernel enforces this per call.
    /// If the IPC buffer names a capability in `send_cap`, a copy travels with
    /// the message on this, [`IpcSendBlocking`](Syscall::IpcSendBlocking), and
    /// [`Call`](Syscall::Call); that requires `GRANT` on the endpoint
    /// capability. See [`crate::ipc_buffer`] for the receiving side.
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
    /// `ipc_send_blocking(cap_slot, word) -> 0 | errno`. Like
    /// [`IpcSend`](Syscall::IpcSend) but parks the calling thread until a
    /// receiver is ready rather than returning [`IpcSyscallError::WouldBlock`].
    IpcSendBlocking = 6,
    /// `ipc_recv_blocking(cap_slot) -> word | (errno | ERR_FLAG)`. Like
    /// [`IpcRecv`](Syscall::IpcRecv) but parks the calling thread until a
    /// sender is ready.
    IpcRecvBlocking = 7,
    /// `mint(src_slot, rights, badge) -> new_slot | (errno | ERR_FLAG)`. Derives a
    /// capability from `src_slot` with rights attenuated by the low 8 bits of
    /// `rights`, installing it in the lowest free slot of the current `CSpace`.
    /// A non-zero `badge` stamps it (only allowed on an unbadged source), so a
    /// server can hand each client a distinguishable endpoint capability.
    /// Errors are [`MintSyscallError`] codes with [`IPC_ERR_FLAG`] set.
    Mint = 8,
    /// `call(cap_slot, word) -> reply_word | (errno | ERR_FLAG)`. Sends `word`
    /// through the endpoint (requires `WRITE`) and blocks until the server
    /// answers with [`Reply`](Syscall::Reply). The server must receive with
    /// [`RecvReply`](Syscall::RecvReply); a plain receive cannot answer, so the
    /// call fails with [`IpcSyscallError::NoReply`].
    Call = 9,
    /// `recv_reply(ep_slot, reply_slot) -> word | (errno | ERR_FLAG)`, badge in
    /// `rdx`. A blocking receive that names an idle reply object (requires
    /// `WRITE` on it): if the message came from a [`Call`](Syscall::Call), the
    /// reply object is bound to the caller.
    RecvReply = 10,
    /// `reply(reply_slot, word) -> 0 | errno`. Answers the caller bound to the
    /// reply object with `word` and returns the object to idle. One answer per
    /// call: a second reply fails with [`IpcSyscallError::NoCaller`].
    Reply = 11,
    /// `set_ipc_buffer(frame_slot) -> 0 | errno`. Registers the frame named by
    /// `frame_slot` as the calling thread's IPC buffer, replacing any previous
    /// one. The capability must name a Frame and carry `READ` and `WRITE`, since
    /// the kernel reads and writes the buffer on the thread's behalf. Mapping the
    /// frame into the thread's address space is the caller's business.
    SetIpcBuffer = 12,
    /// `reply_recv(ep_slot, reply_slot, word) -> word | (errno | ERR_FLAG)`, badge
    /// in `rdx`. The server loop in one call: answers the caller bound to the
    /// reply object with `word` (and the server's buffer words), then receives
    /// exactly like [`RecvReply`](Syscall::RecvReply). If no caller is bound the
    /// answer is skipped, so a loop can use it from its first iteration.
    ReplyRecv = 13,
    /// `map_page_table(vspace_slot, table_slot, vaddr) -> 0 | errno`. Installs
    /// the page table at the first missing level on the path to `vaddr` in the
    /// address space. Both capabilities need `WRITE`. Call it once per missing
    /// level; the kernel never allocates a table itself.
    MapPageTable = 14,
    /// `map_frame(vspace_slot, frame_slot, vaddr | flags) -> 0 | errno`. Maps
    /// the frame at the page-aligned `vaddr`; the low bits carry
    /// [`map_flags`]. The frame capability needs `READ`, plus `WRITE` for a
    /// writable mapping, and a mapping is never both writable and executable.
    MapFrame = 15,
    /// `unmap(object_slot) -> 0 | errno`. Removes the mapping of the frame or page
    /// table named by `object_slot` (which needs `WRITE`); unmapping a table also
    /// unmaps everything beneath it. The object can then be mapped again.
    Unmap = 16,
    /// `tcb_configure(tcb_slot, cnode_slot, vspace_slot) -> 0 | errno`. Gives a
    /// thread that has not started its capability space and address space. All
    /// three capabilities need `WRITE`.
    TcbConfigure = 17,
    /// `tcb_set_ipc_buffer(tcb_slot, frame_slot) -> 0 | errno`. Registers a frame
    /// as another thread's IPC buffer, with the same checks as
    /// [`SetIpcBuffer`](Syscall::SetIpcBuffer).
    TcbSetIpcBuffer = 18,
    /// `tcb_start(tcb_slot, entry, stack_top) -> 0 | errno`. Starts a configured
    /// thread in ring 3 at `entry` with stack pointer `stack_top`, and hands it
    /// to the scheduler. A thread starts once.
    TcbStart = 19,
    /// `cnode_copy(dest_cnode_slot, src_slot, dest_slot | rights << 16) -> 0 |
    /// errno`. Copies the capability at `src_slot` of the caller's space into
    /// slot `dest_slot` of another capability space, with rights attenuated by
    /// the mask in bits 16 to 23 (see [`pack_cnode_copy`]; use
    /// [`Mint`](Syscall::Mint) first to badge it). The destination `CNode`
    /// capability needs `WRITE`. The copy stays in the derivation tree, so
    /// revoking the source reaches it.
    CNodeCopy = 20,
    /// `revoke(slot) -> count | (errno | ERR_FLAG)`. Removes the capability in
    /// `slot` and every capability derived from it, in every capability space
    /// (copies included), and returns how many were removed. Threads blocked on
    /// a revoked object are woken with an error, and revoked frames and page
    /// tables are unmapped.
    Revoke = 21,
    /// `console_write(console_slot, len) -> 0 | errno`. Writes the first `len`
    /// bytes of the caller's IPC-buffer data area (see
    /// [`crate::ipc_buffer::DATA_OFFSET`]) to the kernel console. Needs `WRITE`
    /// on a Console capability; the kernel reads the bytes through its own
    /// mapping of the buffer frame, never through a user pointer.
    ConsoleWrite = 22,
    /// `machine_halt(machine_slot, code)`: stops the machine. Code 0 reports
    /// success to a test harness and anything else failure (under qemu, the
    /// isa-debug-exit device turns it into the emulator's exit status). Needs
    /// `WRITE` on the Machine capability; does not return unless the
    /// capability is refused.
    MachineHalt = 23,
    /// `thread_exit()`: stops the calling thread for good, as revoking its TCB
    /// would. It needs no capability: a thread can always stop itself, which
    /// takes nothing from anyone else. Whoever holds its capabilities still
    /// revokes them to reclaim the slots. Does not return.
    ThreadExit = 24,
    /// `tcb_set_fault_handler(tcb_slot, fault_slot) -> 0 | errno`. Sends the
    /// thread's faults to the endpoint in slot `fault_slot` of the thread's own
    /// capability space, as calls carrying a [`fault_message`]: the slot is
    /// looked up when a fault happens, and the capability there must name an
    /// endpoint and carry `WRITE`. Needs `WRITE` on the TCB capability.
    TcbSetFaultHandler = 25,
    /// `recv_timeout(ep_slot, reply_slot, ms) -> word | errno` (badge in
    /// `rdx`): a blocking receive that gives up with
    /// [`IpcSyscallError::TimedOut`] once `ms` milliseconds have passed,
    /// counted in whole ticks of the kernel timer and rounded up. With
    /// `reply_slot` set to [`NO_REPLY`] it receives as
    /// [`IpcRecvBlocking`](Syscall::IpcRecvBlocking) does; otherwise as
    /// [`RecvReply`](Syscall::RecvReply), with that reply object.
    RecvTimeout = 26,
    /// `console_read(console_slot, max, ms) -> len | errno`: moves up to `max`
    /// bytes of console input (at most [`crate::ipc_buffer::DATA_LEN`]) into the
    /// caller's IPC-buffer data area and returns how many. With no input yet it
    /// waits for some: not at all when `ms` is 0 ([`IpcSyscallError::WouldBlock`]),
    /// for `ms` milliseconds in whole timer ticks ([`IpcSyscallError::TimedOut`]),
    /// or for as long as it takes when `ms` is [`NO_TIMEOUT`]. Needs `READ` on a
    /// Console capability.
    ConsoleRead = 27,
    /// `signal(ntfn_slot) -> 0 | errno`: signals the notification with the
    /// capability's badge (bit 0 for an unbadged one). The thread that has
    /// waited longest takes the bits at once; with none waiting they join the
    /// pending bits. Never blocks. Needs `WRITE` on a Notification capability.
    Signal = 28,
    /// `wait(ntfn_slot, ms) -> bits | errno`: collects the notification's
    /// pending bits, never zero, clearing them. With none pending it waits as
    /// [`Syscall::ConsoleRead`] does: not at all for `ms` 0, `ms` milliseconds,
    /// or for as long as it takes for [`NO_TIMEOUT`]. Needs `READ`.
    Wait = 29,
}

impl Syscall {
    /// Every syscall, in number order; the numbers are dense from 0.
    pub const ALL: [Self; 30] = [
        Self::Add,
        Self::Exit,
        Self::IpcSend,
        Self::IpcRecv,
        Self::Retype,
        Self::Invoke,
        Self::IpcSendBlocking,
        Self::IpcRecvBlocking,
        Self::Mint,
        Self::Call,
        Self::RecvReply,
        Self::Reply,
        Self::SetIpcBuffer,
        Self::ReplyRecv,
        Self::MapPageTable,
        Self::MapFrame,
        Self::Unmap,
        Self::TcbConfigure,
        Self::TcbSetIpcBuffer,
        Self::TcbStart,
        Self::CNodeCopy,
        Self::Revoke,
        Self::ConsoleWrite,
        Self::MachineHalt,
        Self::ThreadExit,
        Self::TcbSetFaultHandler,
        Self::RecvTimeout,
        Self::ConsoleRead,
        Self::Signal,
        Self::Wait,
    ];

    /// Maps a raw syscall number to its enum form, or `None` if it is unknown.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<Self> {
        let index = usize::try_from(n).ok()?;
        Self::ALL.get(index).copied()
    }
}

/// Sentinel returned in `rax` when the syscall number is not recognized.
pub const ENOSYS: u64 = u64::MAX;

/// The `reply_slot` of [`Syscall::RecvTimeout`] that names no reply object.
pub const NO_REPLY: u64 = u64::MAX;

/// The `ms` of a wait with no deadline, as for [`Syscall::ConsoleRead`].
pub const NO_TIMEOUT: u64 = u64::MAX;

/// Bit OR-ed into the result of a call that returns data, to mark it an error
/// rather than a value. The high bit, so any real result below `1 << 63` is
/// unambiguous.
pub const IPC_ERR_FLAG: u64 = 1 << 63;

/// Error codes of the IPC, mapping, and thread calls.
///
/// Distinct small non-zero values so a userspace program can tell *why* a call
/// failed: a stale capability, a missing right, the wrong object type, or a
/// full or empty endpoint.
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
    /// The reply slot does not name a reply object.
    NotReply = 5,
    /// `recv_reply` named a reply object that is already bound to a caller.
    ReplyBusy = 6,
    /// A `call` was received by a plain receive, or its reply object was
    /// revoked, so it can never be answered.
    NoReply = 7,
    /// `reply` named a reply object with no caller waiting.
    NoCaller = 8,
    /// The slot does not name a frame.
    NotFrame = 9,
    /// The call needs a current thread (a TCB) and there is none.
    NoThread = 10,
    /// The slot does not name an address space (`VSpace`).
    NotVSpace = 11,
    /// The slot does not name a page table.
    NotPageTable = 12,
    /// The address is outside the user half, or carries unknown flag bits.
    BadAddress = 13,
    /// A page table is missing on the path to the address; map one first.
    MissingTable = 14,
    /// The table or frame is already mapped somewhere.
    AlreadyMapped = 15,
    /// The address already has every table level, or a frame, mapped there.
    AlreadyPresent = 16,
    /// A frame was asked to be mapped both writable and executable.
    WritableExecutable = 17,
    /// The kernel's mapping registry is full.
    MappingsFull = 18,
    /// `unmap` named a frame or table that is not mapped.
    NotMapped = 19,
    /// The slot does not name a thread (TCB).
    NotTcb = 20,
    /// The slot does not name a capability node.
    NotCNode = 21,
    /// The thread has already started, so it can no longer be configured.
    AlreadyStarted = 22,
    /// `tcb_start` named a thread without a capability space and address space.
    NotConfigured = 23,
    /// The scheduler has no room for another thread.
    ThreadsFull = 24,
    /// A capability cannot be copied into the space it comes from.
    SameSpace = 25,
    /// The destination slot already holds a capability.
    SlotOccupied = 26,
    /// The destination slot is out of range.
    SlotOutOfRange = 27,
    /// A capability was sent from a space that is not registered, so its copy
    /// could not stay linked to it for revocation.
    NotRegistered = 28,
    /// The slot does not name the console.
    NotConsole = 29,
    /// The slot does not name the machine.
    NotMachine = 30,
    /// The call passes data through the IPC buffer and the caller has none.
    NoIpcBuffer = 31,
    /// A length exceeds the IPC buffer's data area.
    TooLong = 32,
    /// A timed wait ran out of time before a message, input, or signal came.
    TimedOut = 33,
    /// The slot does not name a notification.
    NotNotification = 34,
    /// Word 0 of a message has bit 63 set, which its receiver would read as
    /// an error.
    BadWord = 35,
}

impl IpcSyscallError {
    /// Every error, in code order; the codes are dense from 1.
    pub const ALL: [Self; 35] = [
        Self::BadCap,
        Self::Denied,
        Self::NotEndpoint,
        Self::WouldBlock,
        Self::NotReply,
        Self::ReplyBusy,
        Self::NoReply,
        Self::NoCaller,
        Self::NotFrame,
        Self::NoThread,
        Self::NotVSpace,
        Self::NotPageTable,
        Self::BadAddress,
        Self::MissingTable,
        Self::AlreadyMapped,
        Self::AlreadyPresent,
        Self::WritableExecutable,
        Self::MappingsFull,
        Self::NotMapped,
        Self::NotTcb,
        Self::NotCNode,
        Self::AlreadyStarted,
        Self::NotConfigured,
        Self::ThreadsFull,
        Self::SameSpace,
        Self::SlotOccupied,
        Self::SlotOutOfRange,
        Self::NotRegistered,
        Self::NotConsole,
        Self::NotMachine,
        Self::NoIpcBuffer,
        Self::TooLong,
        Self::TimedOut,
        Self::NotNotification,
        Self::BadWord,
    ];

    /// Decodes an error code (without [`IPC_ERR_FLAG`]), or `None` if unknown.
    #[must_use]
    pub fn from_code(code: u64) -> Option<Self> {
        let index = usize::try_from(code.checked_sub(1)?).ok()?;
        Self::ALL.get(index).copied()
    }
}

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
    /// The destination slot is out of range.
    DestOutOfRange = 6,
    /// The region is too misaligned for the requested object.
    BadAlign = 7,
    /// The requested object type cannot be carved via the syscall.
    BadType = 8,
}

impl RetypeSyscallError {
    /// Every error, in code order; the codes are dense from 1.
    pub const ALL: [Self; 8] = [
        Self::BadCap,
        Self::NotUntyped,
        Self::BadArgs,
        Self::NoRoom,
        Self::DestOccupied,
        Self::DestOutOfRange,
        Self::BadAlign,
        Self::BadType,
    ];

    /// Decodes an error code, or `None` if unknown.
    #[must_use]
    pub fn from_code(code: u64) -> Option<Self> {
        let index = usize::try_from(code.checked_sub(1)?).ok()?;
        Self::ALL.get(index).copied()
    }
}

/// Error codes returned by [`Syscall::Mint`] (OR-ed with [`IPC_ERR_FLAG`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum MintSyscallError {
    /// The source slot is out of range or names no live capability.
    BadCap = 1,
    /// A badge was requested but the source capability is already badged.
    AlreadyBadged = 2,
    /// The current `CSpace` has no free slot.
    SpaceFull = 3,
    /// The badge has bit 63 set, which the waiter on a notification it
    /// signals would read as an error.
    BadBadge = 4,
}

impl MintSyscallError {
    /// Every error, in code order; the codes are dense from 1.
    pub const ALL: [Self; 4] = [Self::BadCap, Self::AlreadyBadged, Self::SpaceFull, Self::BadBadge];

    /// Decodes an error code (without [`IPC_ERR_FLAG`]), or `None` if unknown.
    #[must_use]
    pub fn from_code(code: u64) -> Option<Self> {
        let index = usize::try_from(code.checked_sub(1)?).ok()?;
        Self::ALL.get(index).copied()
    }
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
    /// The word to send has bit 63 set, which its receiver would read as an
    /// error.
    BadWord = 5,
}

impl InvokeError {
    /// Every error, in code order; the codes are dense from 1.
    pub const ALL: [Self; 5] = [Self::BadCap, Self::Denied, Self::BadMethod, Self::WouldBlock, Self::BadWord];

    /// Decodes an error code (without [`IPC_ERR_FLAG`]), or `None` if unknown.
    #[must_use]
    pub fn from_code(code: u64) -> Option<Self> {
        let index = usize::try_from(code.checked_sub(1)?).ok()?;
        Self::ALL.get(index).copied()
    }
}

/// Method labels for [`Syscall::Invoke`], by object kind.
pub mod invoke_method {
    /// Send `arg0` as a one-word message through an endpoint (needs `WRITE`).
    pub const ENDPOINT_SEND: u64 = 0;
    /// Receive a one-word message from an endpoint (needs `READ`).
    pub const ENDPOINT_RECV: u64 = 1;
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
    /// One page of memory (for example an IPC buffer).
    pub const FRAME: u8 = 5;
    /// An asynchronous notification.
    pub const NOTIFICATION: u8 = 6;
    /// A one-shot reply object for `Call` IPC.
    pub const REPLY: u8 = 7;
    /// The root of an address space.
    pub const VSPACE: u8 = 8;
}

/// Decodes a retype `type_word` into an [`ObjectType`].
///
/// Bits 0 to 7 are the type discriminant ([`object_type_id`]), bits 8 to 15
/// are `size_bits` (for `CNode` and `Untyped`; must be 0 for fixed-size types),
/// and bits 16 and up must be zero. Returns `None` for an unknown discriminant
/// or malformed reserved or size bits.
#[must_use]
pub fn decode_object_type(type_word: u64) -> Option<ObjectType> {
    if type_word >> 16 != 0 {
        return None; // reserved bits must be zero
    }
    let [discriminant, size_bits, ..] = type_word.to_le_bytes();
    match discriminant {
        object_type_id::ENDPOINT if size_bits == 0 => Some(ObjectType::Endpoint),
        object_type_id::PAGE_TABLE if size_bits == 0 => Some(ObjectType::PageTable),
        object_type_id::TCB if size_bits == 0 => Some(ObjectType::Tcb),
        object_type_id::FRAME if size_bits == 0 => Some(ObjectType::Frame),
        object_type_id::NOTIFICATION if size_bits == 0 => Some(ObjectType::Notification),
        object_type_id::REPLY if size_bits == 0 => Some(ObjectType::Reply),
        object_type_id::VSPACE if size_bits == 0 => Some(ObjectType::VSpace),
        object_type_id::CNODE => Some(ObjectType::CNode { size_bits }),
        object_type_id::UNTYPED => Some(ObjectType::Untyped { size_bits }),
        // unknown discriminant, or a fixed-size type given a non-zero size_bits.
        _ => None,
    }
}

/// Encodes an [`ObjectType`] as the `type_word` [`decode_object_type`] reads.
#[must_use]
pub fn encode_object_type(ty: ObjectType) -> u64 {
    let (discriminant, size_bits) = match ty {
        ObjectType::Endpoint => (object_type_id::ENDPOINT, 0),
        ObjectType::CNode { size_bits } => (object_type_id::CNODE, size_bits),
        ObjectType::Untyped { size_bits } => (object_type_id::UNTYPED, size_bits),
        ObjectType::PageTable => (object_type_id::PAGE_TABLE, 0),
        ObjectType::Tcb => (object_type_id::TCB, 0),
        ObjectType::Frame => (object_type_id::FRAME, 0),
        ObjectType::Notification => (object_type_id::NOTIFICATION, 0),
        ObjectType::Reply => (object_type_id::REPLY, 0),
        ObjectType::VSpace => (object_type_id::VSPACE, 0),
    };
    u64::from(discriminant) | u64::from(size_bits) << 8
}

/// Mapping flags a caller passes in the low bits of a page-aligned address.
pub mod map_flags {
    /// Map the frame writable (the capability must carry `WRITE`).
    pub const WRITE: u64 = 1 << 0;
    /// Map the frame executable (never together with [`WRITE`]).
    pub const EXECUTE: u64 = 1 << 1;
}

/// Where the kernel puts the root task, and where userspace may map anything.
///
/// Entry 0 of every top-level table is the kernel's identity map and entries
/// 256 and up are the kernel half, so user addresses live in entries 1 to 255.
/// The root task's stack, IPC buffer, and [`BootInfo`] share one 2 MiB window
/// at the top of its first GiB, so a single page table maps all three.
pub mod layout {
    /// Lowest user virtual address.
    pub const USER_START: u64 = 0x0000_0080_0000_0000;
    /// One past the highest user virtual address.
    pub const USER_END: u64 = 0x0000_8000_0000_0000;
    /// Where the root task's image is loaded: the base its static-PIE
    /// relocations are applied against.
    pub const ROOT_IMAGE_BASE: u64 = USER_START + 0x40_0000;
    /// One past the highest address the root image may occupy.
    pub const ROOT_IMAGE_LIMIT: u64 = ROOT_WINDOW;
    /// The 2 MiB window holding the root task's stack, IPC buffer, and boot
    /// information. Its first page stays unmapped, a guard under the stack.
    pub const ROOT_WINDOW: u64 = USER_START + 0x3FE0_0000;
    /// Pages in the root task's stack.
    pub const ROOT_STACK_PAGES: u64 = 16;
    /// Lowest address of the root task's stack.
    pub const ROOT_STACK_BOTTOM: u64 = ROOT_WINDOW + 0x1000;
    /// Top of the root task's stack, where its stack pointer starts.
    pub const ROOT_STACK_TOP: u64 = ROOT_STACK_BOTTOM + ROOT_STACK_PAGES * 0x1000;
    /// The root task's IPC buffer, one unmapped page above the stack.
    pub const ROOT_IPC_BUFFER: u64 = ROOT_STACK_TOP + 0x1000;
    /// The root task's read-only [`BootInfo`](super::BootInfo) page.
    pub const ROOT_BOOT_INFO: u64 = ROOT_IPC_BUFFER + 0x1000;

    /// Size and alignment of a thread block: the region that holds one
    /// thread's stack and IPC buffer. A thread finds its own IPC buffer by
    /// rounding its stack pointer down to a block boundary and adding
    /// [`THREAD_IPC_BUFFER`], so no thread-local storage is needed.
    pub const THREAD_BLOCK: u64 = 0x2_0000;
    /// Offset in a thread block of the lowest stack page (page 0 is a guard).
    pub const THREAD_STACK: u64 = 0x1000;
    /// Pages of stack a thread block can hold.
    pub const THREAD_STACK_PAGES: u64 = 16;
    /// Offset in a thread block of the IPC buffer, one guard page above the
    /// top of the stack.
    pub const THREAD_IPC_BUFFER: u64 = THREAD_STACK + THREAD_STACK_PAGES * 0x1000 + 0x1000;
    /// Where userspace places the thread blocks of the threads it starts: the
    /// second GiB of user space, clear of the root task's image and window.
    pub const THREAD_BLOCKS_START: u64 = USER_START + 0x4000_0000;
    /// One past the last thread block address.
    pub const THREAD_BLOCKS_END: u64 = USER_START + 0x8000_0000;
    /// Where the root task finds read-only copies of the other boot modules,
    /// one after another: the third GiB of user space.
    pub const ROOT_MODULES: u64 = USER_START + 0x8000_0000;
    /// One past the last address of the module window.
    pub const ROOT_MODULES_END: u64 = USER_START + 0xC000_0000;
    /// A page userspace maps a frame at briefly, to fill it before mapping it
    /// somewhere else, such as into a process it is building: the first page
    /// of the fourth GiB.
    pub const SCRATCH: u64 = USER_START + 0xC000_0000;

    // everything in the window fits in it, and the image ends where it begins.
    const _: () = assert!(ROOT_BOOT_INFO + 0x1000 <= ROOT_WINDOW + 0x20_0000);
    const _: () = assert!(ROOT_WINDOW.is_multiple_of(0x20_0000));
    const _: () = assert!(ROOT_IMAGE_BASE < ROOT_IMAGE_LIMIT);
    // the root task's window is a thread block like any other.
    const _: () = assert!(ROOT_WINDOW.is_multiple_of(THREAD_BLOCK));
    const _: () = assert!(ROOT_STACK_BOTTOM == ROOT_WINDOW + THREAD_STACK);
    const _: () = assert!(ROOT_STACK_PAGES == THREAD_STACK_PAGES);
    const _: () = assert!(ROOT_IPC_BUFFER == ROOT_WINDOW + THREAD_IPC_BUFFER);
    const _: () = assert!(THREAD_IPC_BUFFER + 0x1000 <= THREAD_BLOCK);
}

/// The capability slots the kernel fills in the root task's `CNode`. Slot 0 is
/// left empty, so a zero slot number never names anything by accident.
pub mod root_slot {
    /// The root task's own thread.
    pub const TCB: u64 = 1;
    /// The root task's `CNode` (its own capability space).
    pub const CNODE: u64 = 2;
    /// The root task's address space.
    pub const VSPACE: u64 = 3;
    /// The frame holding the root task's IPC buffer.
    pub const IPC_BUFFER: u64 = 4;
    /// The frame holding the [`BootInfo`](super::BootInfo) page.
    pub const BOOT_INFO: u64 = 5;
    /// The console.
    pub const CONSOLE: u64 = 6;
    /// The machine.
    pub const MACHINE: u64 = 7;
    /// The first untyped region; the rest follow in order.
    pub const FIRST_UNTYPED: u64 = 8;
}

/// The capability slots a process the root task starts finds filled in its
/// `CNode`, the only capabilities it holds. Like the root task, it runs at
/// [`layout::ROOT_IMAGE_BASE`] with its stack and IPC buffer in the window
/// at [`layout::ROOT_WINDOW`], in an address space of its own.
pub mod process_slot {
    /// The console, with `WRITE` only: it can print and nothing else.
    pub const CONSOLE: u64 = 1;
    /// An endpoint to its parent, with `WRITE` only: where it reports, and
    /// where its runtime sends its exit code.
    pub const PARENT: u64 = 2;
    /// The endpoint its faults go to (its fault handler).
    pub const FAULTS: u64 = 3;
}

/// What a process finds at its initial stack pointer: what to tell its
/// runtime and its `main`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessStart {
    /// [`PROCESS_START_MAGIC`].
    pub magic: u64,
    /// The argument its parent gave it.
    pub arg: u64,
}

/// `b"jos proc"` read as a little-endian word: the first field of
/// [`ProcessStart`].
pub const PROCESS_START_MAGIC: u64 = u64::from_le_bytes(*b"jos proc");

/// Where a process's [`ProcessStart`] sits, and its initial stack pointer:
/// at the top of its stack, 16-byte aligned.
pub const PROCESS_START: u64 = layout::ROOT_STACK_TOP - 16;

const _: () = assert!(core::mem::size_of::<ProcessStart>() == 16);
const _: () = assert!(PROCESS_START.is_multiple_of(16));

/// The `size_bits` of a `CNode` object, as [`Syscall::Retype`] takes it for
/// [`ObjectType::CNode`](crate::untyped::ObjectType::CNode): the kernel makes
/// capability spaces of one size.
pub const CNODE_SIZE_BITS: u8 = 12;

/// `b"jos boot"` read as a little-endian word: the first field of [`BootInfo`].
pub const BOOT_INFO_MAGIC: u64 = u64::from_le_bytes(*b"jos boot");

/// The [`BootInfo`] layout version; any incompatible change bumps it.
pub const BOOT_INFO_VERSION: u64 = 2;

/// How many untyped regions [`BootInfo`] can describe.
pub const MAX_BOOT_UNTYPED: usize = 16;

/// How many boot modules [`BootInfo`] can describe.
pub const MAX_BOOT_MODULES: usize = 8;

/// Bytes of a module command line kept in [`BootInfo`].
pub const MODULE_CMDLINE_LEN: usize = 64;

/// Bytes of the root task's own command line kept in [`BootInfo`].
pub const BOOT_CMDLINE_LEN: usize = 256;

/// A half-open range of capability slots.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SlotRange {
    /// The first slot in the range.
    pub start: u64,
    /// One past the last slot in the range.
    pub end: u64,
}

/// One untyped region the root task holds a capability to.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UntypedDesc {
    /// The slot of its capability.
    pub slot: u64,
    /// Physical address of its first byte.
    pub phys: u64,
    /// Its size in bytes.
    pub size: u64,
    /// Bytes already carved from it by the kernel (for the root task's own
    /// objects), so `size - used` is what is left.
    pub used: u64,
}

/// One boot module, as the boot loader placed it.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleDesc {
    /// Physical address of its first byte.
    pub phys: u64,
    /// Where the root task can read it: a read-only copy in
    /// [`layout::ROOT_MODULES`], or zero for the root task's own image and any
    /// module that did not fit.
    pub vaddr: u64,
    /// Its size in bytes.
    pub size: u64,
    /// Its command line (name first), NUL padded and possibly cut short.
    pub cmdline: [u8; MODULE_CMDLINE_LEN],
}

/// What the kernel tells the root task at boot.
///
/// It sits in a read-only page at [`layout::ROOT_BOOT_INFO`], whose address
/// the root task also receives in `rdi`. Every capability it mentions is in
/// the root task's `CNode` at a [`root_slot`] or in a range listed here.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BootInfo {
    /// [`BOOT_INFO_MAGIC`].
    pub magic: u64,
    /// [`BOOT_INFO_VERSION`].
    pub version: u64,
    /// Virtual address of the root task's IPC buffer.
    pub ipc_buffer: u64,
    /// Lowest address of the root task's stack; a guard page lies below it.
    pub stack_bottom: u64,
    /// Top of the root task's stack.
    pub stack_top: u64,
    /// Lowest virtual address of the loaded image.
    pub image_start: u64,
    /// One past the highest virtual address of the loaded image.
    pub image_end: u64,
    /// Number of slots in the root task's `CNode`.
    pub cnode_slots: u64,
    /// The empty slots of the root task's `CNode`.
    pub empty: SlotRange,
    /// Bytes of usable RAM the kernel left out because it lies above the
    /// identity map.
    pub memory_ignored: u64,
    /// How many entries of `untyped` are valid.
    pub untyped_count: u64,
    /// The untyped regions, in slot order from [`root_slot::FIRST_UNTYPED`].
    pub untyped: [UntypedDesc; MAX_BOOT_UNTYPED],
    /// How many entries of `modules` are valid.
    pub module_count: u64,
    /// Every boot module, the root image included.
    pub modules: [ModuleDesc; MAX_BOOT_MODULES],
    /// The root task's command line: the words after its module name, NUL
    /// padded.
    pub cmdline: [u8; BOOT_CMDLINE_LEN],
}

// the page holds it whole, and the start of the layout is fixed.
const _: () = assert!(core::mem::size_of::<BootInfo>() <= 4096);
const _: () = assert!(core::mem::offset_of!(BootInfo, magic) == 0);
const _: () = assert!(core::mem::offset_of!(BootInfo, version) == 8);

impl BootInfo {
    /// The valid untyped descriptors.
    #[must_use]
    pub fn untyped(&self) -> &[UntypedDesc] {
        let count = usize::try_from(self.untyped_count).unwrap_or(0).min(MAX_BOOT_UNTYPED);
        &self.untyped[..count]
    }

    /// The valid module descriptors.
    #[must_use]
    pub fn modules(&self) -> &[ModuleDesc] {
        let count = usize::try_from(self.module_count).unwrap_or(0).min(MAX_BOOT_MODULES);
        &self.modules[..count]
    }

    /// The root task's command line, without the NUL padding.
    #[must_use]
    pub fn cmdline(&self) -> &[u8] {
        until_nul(&self.cmdline)
    }

    /// The module named `name`, if the boot loader loaded one.
    #[must_use]
    pub fn module(&self, name: &[u8]) -> Option<&ModuleDesc> {
        self.modules().iter().find(|m| m.name() == name)
    }
}

impl ModuleDesc {
    /// The module's command line, without the NUL padding.
    #[must_use]
    pub fn cmdline(&self) -> &[u8] {
        until_nul(&self.cmdline)
    }

    /// The module's name: the first word of its command line, past a leading
    /// path word (one starting with `/`) when more words follow it.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        let mut words = self.cmdline().split(|&b| b == b' ').filter(|w| !w.is_empty());
        let first = words.next().unwrap_or_default();
        match words.next() {
            Some(second) if first.first() == Some(&b'/') => second,
            _ => first,
        }
    }
}

/// Returns `bytes` up to (not including) the first NUL, or all of it.
fn until_nul(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    &bytes[..end]
}

/// The exceptions a thread can raise, by vector: what the first word of a
/// [`fault_message`] says happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum FaultKind {
    /// `#DE`: division by zero, or a quotient too large.
    DivideError = 0,
    /// `#DB`: a debug trap.
    Debug = 1,
    /// `#BP`: an `int3`.
    Breakpoint = 3,
    /// `#OF`: an `into` with the overflow flag set.
    Overflow = 4,
    /// `#BR`: a `bound` check failed.
    BoundRange = 5,
    /// `#UD`: an instruction the CPU does not accept.
    InvalidOpcode = 6,
    /// `#NM`: the FPU used while unavailable.
    DeviceNotAvailable = 7,
    /// `#TS`: a bad TSS.
    InvalidTss = 10,
    /// `#NP`: a segment that is not present.
    SegmentNotPresent = 11,
    /// `#SS`: a stack segment fault.
    StackSegment = 12,
    /// `#GP`: a general protection fault.
    GeneralProtection = 13,
    /// `#PF`: a page fault; the message carries the address.
    PageFault = 14,
    /// `#MF`: an x87 floating point error.
    X87 = 16,
    /// `#AC`: an unaligned access with alignment checking on.
    AlignmentCheck = 17,
    /// `#XM`: a SIMD floating point error.
    Simd = 19,
    /// `#VE`: a virtualization exception.
    Virtualization = 20,
    /// `#CP`: a control protection fault.
    ControlProtection = 21,
}

impl FaultKind {
    /// Every kind, in vector order.
    pub const ALL: [Self; 17] = [
        Self::DivideError,
        Self::Debug,
        Self::Breakpoint,
        Self::Overflow,
        Self::BoundRange,
        Self::InvalidOpcode,
        Self::DeviceNotAvailable,
        Self::InvalidTss,
        Self::SegmentNotPresent,
        Self::StackSegment,
        Self::GeneralProtection,
        Self::PageFault,
        Self::X87,
        Self::AlignmentCheck,
        Self::Simd,
        Self::Virtualization,
        Self::ControlProtection,
    ];

    /// Returns the kind of exception `vector` is, or `None` for a vector a
    /// thread cannot raise.
    #[must_use]
    pub fn from_vector(vector: u64) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| *kind as u64 == vector)
    }
}

/// Builds the message a fault is delivered as: word 0 the vector (a
/// [`FaultKind`]), word 1 the address a page fault was about (zero for other
/// faults), word 2 the faulting instruction, word 3 the error code the CPU
/// pushed (zero for vectors without one). The handler receives it like a
/// call, with the badge of the fault endpoint capability, and answers through
/// its reply object to resume the thread at that instruction.
#[must_use]
pub fn fault_message(vector: u64, address: u64, rip: u64, error_code: u64) -> crate::endpoint::Message {
    crate::endpoint::Message::new(0, [vector, address, rip, error_code])
}

/// Packs the third argument of [`Syscall::CNodeCopy`]: the destination slot in
/// bits 0 to 15 and the rights mask in bits 16 to 23.
#[must_use]
pub fn pack_cnode_copy(dest_slot: u16, rights: u8) -> u64 {
    u64::from(dest_slot) | u64::from(rights) << 16
}

/// Unpacks the third argument of [`Syscall::CNodeCopy`] into the destination
/// slot and the rights mask, or `None` if any bit above 23 is set.
#[must_use]
pub fn unpack_cnode_copy(packed: u64) -> Option<(u16, u8)> {
    if packed >> 24 != 0 {
        return None;
    }
    let [slot_lo, slot_hi, rights, ..] = packed.to_le_bytes();
    Some((u16::from_le_bytes([slot_lo, slot_hi]), rights))
}

#[cfg(test)]
mod tests {
    use super::{
        BOOT_CMDLINE_LEN, BOOT_INFO_MAGIC, BOOT_INFO_VERSION, BootInfo, InvokeError,
        IpcSyscallError, MAX_BOOT_MODULES, MAX_BOOT_UNTYPED, MODULE_CMDLINE_LEN, MintSyscallError,
        ModuleDesc, RetypeSyscallError, SlotRange, Syscall, UntypedDesc, decode_object_type,
        encode_object_type, pack_cnode_copy, unpack_cnode_copy,
    };
    use crate::untyped::ObjectType;

    #[test]
    fn boot_info_views_clamp_counts_and_trim_padding() {
        let mut info = BootInfo {
            magic: BOOT_INFO_MAGIC,
            version: BOOT_INFO_VERSION,
            ipc_buffer: 0,
            stack_bottom: 0,
            stack_top: 0,
            image_start: 0,
            image_end: 0,
            cnode_slots: 64,
            empty: SlotRange::default(),
            memory_ignored: 0,
            untyped_count: 99,
            untyped: [UntypedDesc::default(); MAX_BOOT_UNTYPED],
            module_count: 1,
            modules: [ModuleDesc { phys: 0, vaddr: 0, size: 0, cmdline: [0; MODULE_CMDLINE_LEN] }; MAX_BOOT_MODULES],
            cmdline: [0; BOOT_CMDLINE_LEN],
        };
        // a corrupt count never reads past the array.
        assert_eq!(info.untyped().len(), MAX_BOOT_UNTYPED);
        assert_eq!(info.modules().len(), 1);
        info.cmdline[..9].copy_from_slice(b"test ipc\0");
        assert_eq!(info.cmdline(), b"test ipc");
        info.modules[0].cmdline = [b'x'; MODULE_CMDLINE_LEN];
        assert_eq!(info.modules[0].cmdline().len(), MODULE_CMDLINE_LEN);
        // a module is found by its name, past a leading path word.
        info.modules[0].cmdline = [0; MODULE_CMDLINE_LEN];
        info.modules[0].cmdline[..17].copy_from_slice(b"/boot/hello hello");
        assert_eq!(info.modules[0].name(), b"hello");
        assert!(info.module(b"hello").is_some() && info.module(b"root").is_none());
        info.modules[0].cmdline[..17].copy_from_slice(b"hello x  y\0\0\0\0\0\0\0");
        assert_eq!(info.modules[0].name(), b"hello");
    }

    #[test]
    fn syscall_numbers_are_dense_and_round_trip() {
        for (i, s) in Syscall::ALL.iter().enumerate() {
            assert_eq!(*s as u64, i as u64, "ALL is in number order");
            assert_eq!(Syscall::from_u64(i as u64), Some(*s));
        }
        assert_eq!(Syscall::from_u64(Syscall::ALL.len() as u64), None);
        assert_eq!(Syscall::from_u64(u64::MAX), None);
    }

    #[test]
    fn error_codes_are_dense_and_round_trip() {
        for (i, e) in IpcSyscallError::ALL.iter().enumerate() {
            assert_eq!(*e as u64, i as u64 + 1);
            assert_eq!(IpcSyscallError::from_code(*e as u64), Some(*e));
        }
        for (i, e) in RetypeSyscallError::ALL.iter().enumerate() {
            assert_eq!(*e as u64, i as u64 + 1);
            assert_eq!(RetypeSyscallError::from_code(*e as u64), Some(*e));
        }
        for (i, e) in MintSyscallError::ALL.iter().enumerate() {
            assert_eq!(*e as u64, i as u64 + 1);
            assert_eq!(MintSyscallError::from_code(*e as u64), Some(*e));
        }
        for (i, e) in InvokeError::ALL.iter().enumerate() {
            assert_eq!(*e as u64, i as u64 + 1);
            assert_eq!(InvokeError::from_code(*e as u64), Some(*e));
        }
        // zero is success, never an error, and codes past the end decode to nothing.
        let past_the_end = |len: usize| len as u64 + 1;
        assert_eq!(IpcSyscallError::from_code(0), None);
        assert_eq!(IpcSyscallError::from_code(past_the_end(IpcSyscallError::ALL.len())), None);
        assert_eq!(RetypeSyscallError::from_code(past_the_end(RetypeSyscallError::ALL.len())), None);
        assert_eq!(MintSyscallError::from_code(past_the_end(MintSyscallError::ALL.len())), None);
        assert_eq!(InvokeError::from_code(past_the_end(InvokeError::ALL.len())), None);
    }

    #[test]
    fn object_types_round_trip() {
        let types = [
            ObjectType::Endpoint,
            ObjectType::CNode { size_bits: 12 },
            ObjectType::Untyped { size_bits: 20 },
            ObjectType::PageTable,
            ObjectType::Tcb,
            ObjectType::Frame,
            ObjectType::Notification,
            ObjectType::Reply,
            ObjectType::VSpace,
        ];
        for ty in types {
            assert_eq!(decode_object_type(encode_object_type(ty)), Some(ty));
        }
        // a CNode is `1 | 12 << 8`, as docs/syscalls.md says.
        assert_eq!(encode_object_type(ObjectType::CNode { size_bits: 12 }), 1 | 12 << 8);
        // fixed-size types refuse size bits; reserved bits and unknown ids fail.
        assert_eq!(decode_object_type(1 << 8), None);
        assert_eq!(decode_object_type(1 << 16), None);
        assert_eq!(decode_object_type(9), None);
    }

    #[test]
    fn cnode_copy_argument_round_trips() {
        assert_eq!(unpack_cnode_copy(pack_cnode_copy(63, 0b101)), Some((63, 0b101)));
        assert_eq!(unpack_cnode_copy(pack_cnode_copy(u16::MAX, u8::MAX)), Some((u16::MAX, u8::MAX)));
        assert_eq!(unpack_cnode_copy(1 << 24), None);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::{
        IpcSyscallError, RetypeSyscallError, Syscall, decode_object_type, encode_object_type,
        unpack_cnode_copy,
    };

    /// Any number decodes either to the syscall carrying that number or to
    /// nothing, so the dispatcher can never run the wrong call.
    #[kani::proof]
    fn syscall_decode_is_exact() {
        let n: u64 = kani::any();
        if let Some(s) = Syscall::from_u64(n) {
            assert_eq!(s as u64, n);
        } else {
            assert!(n >= Syscall::ALL.len() as u64);
        }
    }

    /// Error codes decode to the variant with that code, and nothing else.
    #[kani::proof]
    fn error_decode_is_exact() {
        let code: u64 = kani::any();
        if let Some(e) = IpcSyscallError::from_code(code) {
            assert_eq!(e as u64, code);
        }
        if let Some(e) = RetypeSyscallError::from_code(code) {
            assert_eq!(e as u64, code);
        }
    }

    /// Every type word the kernel accepts re-encodes to itself, so userspace
    /// and the kernel agree on what each accepted word means.
    #[kani::proof]
    fn object_type_decode_encode_round_trips() {
        let word: u64 = kani::any();
        if let Some(ty) = decode_object_type(word) {
            assert_eq!(encode_object_type(ty), word);
        }
    }

    /// An accepted cnode-copy argument has no bits outside its two fields.
    #[kani::proof]
    fn cnode_copy_unpack_is_exact() {
        let packed: u64 = kani::any();
        if let Some((slot, rights)) = unpack_cnode_copy(packed) {
            assert_eq!(u64::from(slot) | u64::from(rights) << 16, packed);
        }
    }
}
