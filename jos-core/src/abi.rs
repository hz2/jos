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
}

impl Syscall {
    /// Every syscall, in number order; the numbers are dense from 0.
    pub const ALL: [Self; 22] = [
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
}

impl IpcSyscallError {
    /// Every error, in code order; the codes are dense from 1.
    pub const ALL: [Self; 28] = [
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
}

impl MintSyscallError {
    /// Every error, in code order; the codes are dense from 1.
    pub const ALL: [Self; 3] = [Self::BadCap, Self::AlreadyBadged, Self::SpaceFull];

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
}

impl InvokeError {
    /// Every error, in code order; the codes are dense from 1.
    pub const ALL: [Self; 4] = [Self::BadCap, Self::Denied, Self::BadMethod, Self::WouldBlock];

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
        InvokeError, IpcSyscallError, MintSyscallError, RetypeSyscallError, Syscall,
        decode_object_type, encode_object_type, pack_cnode_copy, unpack_cnode_copy,
    };
    use crate::untyped::ObjectType;

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
        assert_eq!(IpcSyscallError::from_code(0), None);
        assert_eq!(IpcSyscallError::from_code(29), None);
        assert_eq!(RetypeSyscallError::from_code(9), None);
        assert_eq!(MintSyscallError::from_code(4), None);
        assert_eq!(InvokeError::from_code(5), None);
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
