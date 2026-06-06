//! Capability microkernel glue: kernel objects placed in untyped memory.
//!
//! This is the kernel-side half of the capability core. The verified, pure
//! logic lives in `jos-core` (`cap_rights`, `untyped`, `cap_space`,
//! `placement`); here we provide the parts that touch real memory and cannot
//! run under Miri/Kani:
//!
//! - the concrete kernel object types (`Endpoint`),
//! - `ObjectId`, the `Copy` handle stored in a capability,
//! - `UntypedRegion`, which owns a real chunk of memory and carves objects from
//!   it via the Miri-checked `jos_core::placement::place`,
//! - `cap_send` / `cap_recv`, rights-checked IPC over an endpoint.
//!
//! No heap is used for kernel objects: they are placed directly in an untyped
//! region's bytes, the seL4 "kernel never allocates" discipline. The initial
//! untyped region is a static byte array, so all object pointers derive from a
//! real Rust allocation with valid provenance.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use jos_core::cap_rights::Rights;
use jos_core::cap_space::CapSpace;
use jos_core::cap_table::CapRef;
// the verified rendezvous state machine. referenced by module path
// (`endpoint::Endpoint` etc.) so it does not collide with this module's own
// `Endpoint` object type or its `SendOutcome` / `RecvOutcome` adapter enums.
use jos_core::endpoint;
// the verified async notification state machine, referenced by module path
// (`notification::Notification`) so it does not collide with this module's own
// `Notification` kernel object type.
use jos_core::notification;
use jos_core::placement::{place, PlaceError};
use jos_core::untyped::{
    ObjectType, CNODE_ALIGN, CNODE_SIZE, ENDPOINT_ALIGN, ENDPOINT_SIZE, NOTIFICATION_ALIGN,
    NOTIFICATION_SIZE, PAGE_TABLE_SIZE, TCB_ALIGN, TCB_SIZE,
};
use spin::Mutex;

/// Number of capability slots in a task's capability space (single-level for now).
pub const CSPACE_SLOTS: usize = 64;

/// The capability space type used by jos: a flat `CapSpace` of [`ObjectId`]s.
pub type KernelCapSpace = CapSpace<ObjectId, CSPACE_SLOTS>;

// --------------------------------------------------------------------------
// Object handle
// --------------------------------------------------------------------------

/// The kind of kernel object an [`ObjectId`] names. Used for a runtime tag
/// check before reinterpreting an object's bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    /// A synchronous IPC endpoint.
    Endpoint,
    /// An `x86_64` page table (one 4 KiB page of 512 entries). Serves as the
    /// `PML4` root of a [`crate::vspace::VSpace`] or an intermediate table.
    PageTable,
    /// A thread control block (saved context + `CSpace`/`VSpace` roots).
    Tcb,
    /// A capability node: a capability space carved from untyped memory.
    CNode,
    /// An untyped memory region, from which typed objects are carved. The
    /// handle's address is the address of the [`UntypedRegion`] struct itself
    /// (kernel memory), not the bytes it manages.
    Untyped,
    /// An asynchronous notification (a coalescing signal word).
    Notification,
}

/// An opaque, `Copy` handle to a kernel object placed in untyped memory.
///
/// Stores the object's address (identity-mapped, so physical == virtual) plus a
/// kind tag. It is `Copy` because authority comes from holding a live `CapRef`
/// in a [`KernelCapSpace`], not from owning this value; many capabilities may
/// name the same object. `jos-core` treats it as an opaque handle and cannot
/// construct one (the fields are private to this module), so the verified core
/// stays free of raw-pointer reasoning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectId {
    addr: usize,
    kind: ObjectKind,
}

impl ObjectId {
    /// Returns the kind of object this handle names.
    #[must_use]
    pub fn kind(self) -> ObjectKind {
        self.kind
    }

    /// Returns a shared reference to the [`Endpoint`] this handle names.
    ///
    /// # Safety
    ///
    /// The caller must ensure (1) `self.kind == ObjectKind::Endpoint`, (2) the
    /// untyped region that owns the endpoint is still live and has not been
    /// reused, and (3) the kernel is in a single-CPU, interrupts-disabled
    /// context so no concurrent access races this one. The returned reference
    /// is to the placed object; its interior mutability (the embedded `Mutex`)
    /// makes shared access sufficient.
    unsafe fn as_endpoint(self) -> &'static Endpoint {
        debug_assert_eq!(self.kind, ObjectKind::Endpoint);
        // with_exposed_provenance re-derives a pointer carrying the provenance
        // that retype_endpoint exposed when it captured this address.
        let ptr = core::ptr::with_exposed_provenance::<Endpoint>(self.addr);
        // SAFETY: the address was captured in UntypedRegion::retype_endpoint
        // from a pointer derived from the region base, where an Endpoint was
        // placement-written; it is live for the kernel's lifetime (the static
        // untyped region is never freed). Per this function's contract the
        // caller guarantees no aliasing live &mut, and the kind is Endpoint.
        unsafe { &*ptr }
    }

    /// Returns a shared reference to the [`Notification`] this handle names.
    ///
    /// # Safety
    ///
    /// As [`as_endpoint`](Self::as_endpoint): the caller must ensure (1)
    /// `self.kind == ObjectKind::Notification`, (2) the owning untyped region is
    /// still live, and (3) a single-CPU, interrupts-disabled context so no
    /// concurrent access races this one. The notification's interior mutability
    /// (its embedded `Mutex`) makes a shared reference sufficient.
    unsafe fn as_notification(self) -> &'static Notification {
        debug_assert_eq!(self.kind, ObjectKind::Notification);
        let ptr = core::ptr::with_exposed_provenance::<Notification>(self.addr);
        // SAFETY: the address was captured in retype (kind Notification) from a
        // pointer derived from the region base where a Notification was placed;
        // it is live for the kernel's lifetime (static untyped region). Per this
        // function's contract the caller guarantees no aliasing live &mut and the
        // kind is Notification.
        unsafe { &*ptr }
    }

    /// Returns the physical address of the object this handle names.
    ///
    /// jos identity-maps the regions objects are carved from, so the captured
    /// address is both the virtual and the physical address. The `VSpace`
    /// mapper needs the physical address of a page-table object to install it
    /// in a parent table entry.
    #[must_use]
    pub fn phys_addr(self) -> u64 {
        self.addr as u64
    }

    /// Returns an exclusive reference to the [`PageTable`] this handle names.
    ///
    /// # Safety
    ///
    /// The caller must ensure (1) `self.kind == ObjectKind::PageTable`, (2) the
    /// untyped region that owns the table is still live, and (3) no other live
    /// reference (shared or exclusive) to this table exists. Unlike an endpoint
    /// (whose state is behind a `Mutex`), a page table has no interior
    /// mutability, so mutation requires a genuinely exclusive `&mut`.
    pub(crate) unsafe fn as_page_table_mut(self) -> &'static mut PageTable {
        debug_assert_eq!(self.kind, ObjectKind::PageTable);
        let ptr = core::ptr::with_exposed_provenance_mut::<PageTable>(self.addr);
        // SAFETY: the address was captured in retype (kind PageTable) from a
        // pointer derived from the region base where a PageTable was placed; it
        // is live for the kernel's lifetime. The caller guarantees exclusivity
        // and the correct kind per this function's contract.
        unsafe { &mut *ptr }
    }

    /// Returns an exclusive reference to the [`Tcb`] this handle names.
    ///
    /// # Safety
    ///
    /// As [`as_page_table_mut`](Self::as_page_table_mut), but for a `Tcb`: the
    /// kind must be `Tcb`, the owning region live, and no aliasing reference
    /// may exist.
    pub unsafe fn as_tcb_mut(self) -> &'static mut Tcb {
        debug_assert_eq!(self.kind, ObjectKind::Tcb);
        let ptr = core::ptr::with_exposed_provenance_mut::<Tcb>(self.addr);
        // SAFETY: the address was captured in retype (kind Tcb) from a pointer
        // derived from the region base where a Tcb was placed; it is live for
        // the kernel's lifetime. The caller guarantees exclusivity and the
        // correct kind per this function's contract.
        unsafe { &mut *ptr }
    }

    /// Returns an exclusive reference to the [`KernelCapSpace`] backing the
    /// [`KernelCNode`] this handle names.
    ///
    /// `KernelCNode` is `repr(C)` with `space` first, so the object's address
    /// is the address of the embedded `CapSpace`; this returns that directly,
    /// which is what every CNode operation (insert/mint/lookup/revoke) needs.
    ///
    /// # Safety
    ///
    /// As [`as_page_table_mut`](Self::as_page_table_mut), but for a CNode: the
    /// kind must be `CNode`, the owning region live, and no aliasing reference
    /// may exist.
    pub unsafe fn as_cnode_mut(self) -> &'static mut KernelCapSpace {
        debug_assert_eq!(self.kind, ObjectKind::CNode);
        // space is at offset 0 of KernelCNode (repr C), so the object address
        // is the CapSpace address.
        let ptr = core::ptr::with_exposed_provenance_mut::<KernelCapSpace>(self.addr);
        // SAFETY: the address was captured in retype (kind CNode) from a pointer
        // derived from the region base where a KernelCNode was placed (space at
        // offset 0); it is live for the kernel's lifetime. The caller guarantees
        // exclusivity and the correct kind per this function's contract.
        unsafe { &mut *ptr }
    }

    /// Returns an exclusive reference to the [`UntypedRegion`] this handle
    /// names.
    ///
    /// # Safety
    ///
    /// (1) `self.kind == ObjectKind::Untyped`, (2) the named `UntypedRegion`
    /// struct is still live (it is a kernel object, typically `'static`), and
    /// (3) no other live reference to it exists. Carving from an untyped region
    /// mutates its watermark, so a genuine exclusive `&mut` is required.
    pub unsafe fn as_untyped_mut(self) -> &'static mut UntypedRegion {
        debug_assert_eq!(self.kind, ObjectKind::Untyped);
        let ptr = core::ptr::with_exposed_provenance_mut::<UntypedRegion>(self.addr);
        // SAFETY: the address was captured in UntypedRegion::as_object_id from a
        // pointer to a live UntypedRegion; the caller guarantees the kind is
        // Untyped, the region is live, and there is no aliasing reference.
        unsafe { &mut *ptr }
    }
}

// --------------------------------------------------------------------------
// Endpoint object
// --------------------------------------------------------------------------

/// A small inline IPC message: a tag plus four data words.
///
/// This is the verified [`jos_core::endpoint::Message`], re-exported so the rest
/// of the kernel keeps naming it `cap::Message`. The rendezvous logic that moves
/// it lives in the verified state machine, so the kernel does not redefine it.
pub use jos_core::endpoint::Message;

/// The mutable state of a synchronous IPC endpoint, behind the endpoint's lock.
///
/// An endpoint owns its blocked peers (the seL4 model: a thread blocked on IPC
/// is queued on the endpoint, not spinning). jos has a single waiter slot per
/// direction for now (capacity-1 rendezvous); a full wait queue arrives when
/// userspace threads can contend an endpoint.
///
/// The rendezvous itself, the slot, the capacity-1 rule, and which peer to wake,
/// is the verified [`jos_core::endpoint::Endpoint`] state machine. This struct
/// adds only the one thing pure logic cannot hold: each parked peer's
/// [`Waker`]. The model's `sender_parked` / `receiver_parked` flags are kept in
/// exact correspondence with `send_waiter` / `recv_waiter` being `Some`, so the
/// model decides the rendezvous and this struct decides who to wake.
#[derive(Debug)]
pub struct EndpointInner {
    /// The verified rendezvous state machine: the message slot and the parked
    /// flags. The single source of truth for the rendezvous.
    rendezvous: endpoint::Endpoint,
    /// Waker of a sender parked because the endpoint already held a message.
    /// `Some` exactly when `rendezvous.sender_parked()`. Woken when a receiver
    /// drains the endpoint and frees the slot.
    send_waiter: Option<Waker>,
    /// Waker of a receiver parked because the endpoint had no message. `Some`
    /// exactly when `rendezvous.receiver_parked()`. Woken when a sender deposits.
    recv_waiter: Option<Waker>,
}

/// A synchronous IPC endpoint, sized and aligned to match
/// [`ObjectType::Endpoint`] so it can be placed in untyped memory.
///
/// The mutable state lives behind a `Mutex` so that a shared `&Endpoint` (all
/// `as_endpoint` can hand out) is enough to operate on it. On single-CPU jos
/// the lock is uncontended (cap ops run with interrupts disabled), so it never
/// actually spins; it is here for sound exclusive access and SMP-readiness.
//
// TODO(locking): the endpoint lock is an uncontended placeholder today. when we
// add SMP / preemption, revisit how it scales: the real anti-busy-wait answer
// for IPC is blocking + waker + hlt via the async executor (a sender with no
// receiver should park, not spin); and if a spinning lock is still needed,
// prefer an adaptive (spin-then-park) or a fair queue lock (MCS/CLH/ticket)
// over a bare spinlock so waiters do not bounce a cache line.
#[repr(C, align(64))]
pub struct Endpoint {
    inner: Mutex<EndpointInner>,
    // pad out to the full ENDPOINT_SIZE so the type's layout matches the
    // untyped object size exactly (asserted below).
    _pad: [u8; Endpoint::PAD],
}

impl Endpoint {
    // bytes of padding needed so size_of::<Endpoint>() == ENDPOINT_SIZE.
    const PAD: usize = ENDPOINT_SIZE - core::mem::size_of::<Mutex<EndpointInner>>();

    /// Creates a fresh idle endpoint.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(EndpointInner {
                rendezvous: endpoint::Endpoint::new(),
                send_waiter: None,
                recv_waiter: None,
            }),
            _pad: [0; Self::PAD],
        }
    }
}

impl Default for Endpoint {
    fn default() -> Self {
        Self::new()
    }
}

// catch any layout drift between Endpoint and ObjectType::Endpoint at compile
// time: placement relies on these matching.
const _: () = assert!(core::mem::size_of::<Endpoint>() == ENDPOINT_SIZE);
const _: () = assert!(core::mem::align_of::<Endpoint>() == ENDPOINT_ALIGN);

// --------------------------------------------------------------------------
// Notification object
// --------------------------------------------------------------------------

/// The mutable state of an asynchronous notification, behind its lock.
///
/// The asynchronous counterpart to [`EndpointInner`]: where an endpoint blocks
/// both peers until they rendezvous, a notification's signaller never blocks.
/// The verified [`notification::Notification`] state machine owns the coalescing
/// badge and the parked flag; this struct adds only the parked waiter's
/// [`Waker`], kept `Some` exactly when the model reports a waiter parked, so the
/// model decides delivery and this struct decides whom to wake.
#[derive(Debug)]
pub struct NotificationInner {
    /// The verified notification state: the pending badge and the parked flag.
    state: notification::Notification,
    /// Waker of a waiter parked because nothing was pending. `Some` exactly when
    /// `state.waiter_parked()`. Woken when a signal arrives.
    waiter: Option<Waker>,
}

/// An asynchronous notification object, sized and aligned to match
/// [`ObjectType::Notification`] so it can be placed in untyped memory.
///
/// Like [`Endpoint`], the mutable state lives behind a `Mutex` so a shared
/// `&Notification` is enough to operate on it (signalling from any context, and
/// the async wait path). On single-CPU jos the lock is uncontended.
#[repr(C, align(64))]
pub struct Notification {
    inner: Mutex<NotificationInner>,
    // pad out to the full NOTIFICATION_SIZE so the type's layout matches the
    // untyped object size exactly (asserted below).
    _pad: [u8; Notification::PAD],
}

impl Notification {
    // bytes of padding so size_of::<Notification>() == NOTIFICATION_SIZE.
    const PAD: usize = NOTIFICATION_SIZE - core::mem::size_of::<Mutex<NotificationInner>>();

    /// Creates a fresh idle notification.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(NotificationInner {
                state: notification::Notification::new(),
                waiter: None,
            }),
            _pad: [0; Self::PAD],
        }
    }
}

impl Default for Notification {
    fn default() -> Self {
        Self::new()
    }
}

const _: () = assert!(core::mem::size_of::<Notification>() == NOTIFICATION_SIZE);
const _: () = assert!(core::mem::align_of::<Notification>() == NOTIFICATION_ALIGN);

// --------------------------------------------------------------------------
// PageTable object
// --------------------------------------------------------------------------

/// An `x86_64` page table: one 4 KiB page of 512 eight-byte entries, sized and
/// aligned to match [`ObjectType::PageTable`] so it can be placed in untyped
/// memory and used directly by the cpu as a table frame.
///
/// The entries are raw `u64`s; the verified [`jos_core::pte`] module encodes
/// and decodes them. A page table serves as the `PML4` root of a
/// [`crate::vspace::VSpace`] or as any intermediate level the mapper carves.
#[repr(C, align(4096))]
pub struct PageTable {
    /// The 512 raw page-table entries.
    pub entries: [u64; 512],
}

impl PageTable {
    /// A page table with every entry zero (all not-present).
    #[must_use]
    pub const fn empty() -> Self {
        Self { entries: [0; 512] }
    }
}

impl Default for PageTable {
    fn default() -> Self {
        Self::empty()
    }
}

const _: () = assert!(core::mem::size_of::<PageTable>() == PAGE_TABLE_SIZE);
const _: () = assert!(core::mem::align_of::<PageTable>() == PAGE_TABLE_SIZE);

// --------------------------------------------------------------------------
// Tcb object
// --------------------------------------------------------------------------

/// A thread's saved register context: enough to resume it where it left off.
///
/// Holds the general-purpose registers plus the architectural state an
/// `iretq` restores (`rip`, `rsp`, `rflags`, `cs`, `ss`). In slice 3c this is
/// the *initial* context the kernel sets before first entering the thread;
/// saving a running thread's context on a trap (for preemptive switching) is a
/// later slice.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct SavedContext {
    /// General-purpose registers.
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
    /// Instruction pointer to resume at.
    pub rip: u64,
    /// Stack pointer to resume with.
    pub rsp: u64,
    /// Flags register.
    pub rflags: u64,
    /// Code segment selector (ring 3 for a user thread).
    pub cs: u64,
    /// Stack segment selector.
    pub ss: u64,
}

/// Run state of a [`Tcb`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcbState {
    /// Created but never run.
    Inactive,
    /// Runnable / running.
    Running,
}

/// A thread control block: a thread's saved context plus the roots of its
/// authority (its `CSpace`) and address space (its `VSpace`).
///
/// This is the retypeable "Task" object, carved from untyped like an
/// [`Endpoint`]. It completes jos's five seL4 object types (Untyped, page
/// table, `CNode`/`CSpace`, `Tcb`, `Endpoint`).
///
/// The `CSpace` root names a [`KernelCNode`] object (carved from untyped via
/// [`UntypedRegion::retype_cnode`]); a freshly carved `Tcb` records `None`
/// until one is assigned. The IPC syscalls still resolve a single active
/// `CSpace` directly for now; wiring per-`Tcb` resolution through
/// `cspace_root` is the per-`Tcb` CSpace follow-up.
#[repr(C, align(64))]
pub struct Tcb {
    /// The thread's saved register context.
    pub context: SavedContext,
    /// Physical address of the thread's `VSpace` `PML4` (its address space
    /// root). Zero means "no address space assigned yet".
    pub vspace_root: u64,
    /// Top of this thread's kernel stack (16-aligned). The per-CPU block's
    /// `kernel_rsp` is loaded from here on a context switch, so the `syscall`
    /// entry stub switches to THIS thread's kernel stack. Zero until assigned.
    pub kernel_stack_top: u64,
    /// Raw pointer to the [`KernelCapSpace`] backing this thread's `CSpace`
    /// (the `space` field of the `cspace_root` `KernelCNode`, or a directly
    /// owned space). Copied into the per-CPU block on a context switch so IPC
    /// syscalls resolve capabilities in THIS thread's space. Null until assigned.
    pub cspace_ptr: *mut KernelCapSpace,
    /// The thread's `CSpace` root: an [`ObjectId`] naming a [`KernelCNode`], or
    /// `None` if no capability space has been assigned yet.
    pub cspace_root: Option<ObjectId>,
    /// The thread's run state. Last of the real fields (a small type), before
    /// the padding, so it introduces no interior alignment gap.
    pub state: TcbState,
    // pad to the full TCB_SIZE so the layout matches ObjectType::Tcb exactly.
    _pad: [u8; Tcb::PAD],
}

impl Tcb {
    // bytes of padding so size_of::<Tcb>() == TCB_SIZE. computed from the sum of
    // the real fields' sizes; if a field is added this const fails to compile
    // until updated, which is the intended tripwire.
    const USED: usize = core::mem::size_of::<SavedContext>()
        + core::mem::size_of::<u64>()
        + core::mem::size_of::<Option<ObjectId>>()
        + core::mem::size_of::<TcbState>()
        + core::mem::size_of::<u64>()
        + core::mem::size_of::<*mut KernelCapSpace>();
    const PAD: usize = TCB_SIZE - Self::USED;

    /// Creates an inactive `Tcb` with a zeroed context and no roots.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            context: SavedContext {
                rax: 0, rbx: 0, rcx: 0, rdx: 0, rsi: 0, rdi: 0, rbp: 0,
                r8: 0, r9: 0, r10: 0, r11: 0, r12: 0, r13: 0, r14: 0, r15: 0,
                rip: 0, rsp: 0, rflags: 0, cs: 0, ss: 0,
            },
            vspace_root: 0,
            cspace_root: None,
            state: TcbState::Inactive,
            kernel_stack_top: 0,
            cspace_ptr: core::ptr::null_mut(),
            _pad: [0; Self::PAD],
        }
    }
}

impl Default for Tcb {
    fn default() -> Self {
        Self::new()
    }
}

const _: () = assert!(core::mem::size_of::<Tcb>() == TCB_SIZE);
const _: () = assert!(core::mem::align_of::<Tcb>() == TCB_ALIGN);

// --------------------------------------------------------------------------
// CNode object
// --------------------------------------------------------------------------

/// `size_bits` of the kernel's `CNode` object: log2 of [`CNODE_SIZE`] (4096),
/// the [`ObjectType::CNode`] argument used when carving one from untyped.
pub const KERNEL_CNODE_SIZE_BITS: u8 = 12;

/// A kernel CNode: a [`KernelCapSpace`] padded and aligned to match
/// [`ObjectType::CNode`] (`size_bits = 12`, i.e. [`CNODE_SIZE`] bytes), so it
/// can be placed in untyped memory and named by an [`ObjectId`].
///
/// This is the retypeable capability-space object: a task's `CSpace` root
/// ([`Tcb::cspace_root`]) names one. `repr(C)` keeps `space` at offset 0, so a
/// handle's address is the address of the embedded `CapSpace` and
/// [`ObjectId::as_cnode_mut`] hands back a `&mut KernelCapSpace` directly.
#[repr(C, align(4096))]
pub struct KernelCNode {
    /// The capability space this CNode backs.
    pub space: KernelCapSpace,
    // pad out to the full CNODE_SIZE so the layout matches ObjectType::CNode.
    _pad: [u8; KernelCNode::PAD],
}

impl KernelCNode {
    // bytes of padding so size_of::<KernelCNode>() == CNODE_SIZE. if the
    // capability space ever outgrows CNODE_SIZE this underflows and fails the
    // build, which is the signal to raise CNODE_SIZE (and KERNEL_CNODE_SIZE_BITS).
    const PAD: usize = CNODE_SIZE - core::mem::size_of::<KernelCapSpace>();

    /// Creates an empty CNode.
    ///
    /// Not `const`: `KernelCapSpace::new` is not const (the cap table builds its
    /// slots with `array::from_fn`), so a CNode cannot initialize a `static`. It
    /// is created at runtime and placed into untyped via [`UntypedRegion::retype_cnode`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            space: KernelCapSpace::new(),
            _pad: [0; Self::PAD],
        }
    }
}

impl Default for KernelCNode {
    fn default() -> Self {
        Self::new()
    }
}

const _: () = assert!(core::mem::size_of::<KernelCNode>() == CNODE_SIZE);
const _: () = assert!(core::mem::align_of::<KernelCNode>() == CNODE_ALIGN);

// --------------------------------------------------------------------------
// Untyped region
// --------------------------------------------------------------------------

/// A contiguous region of untyped memory from which kernel objects are carved.
///
/// Backed by a `&'static mut [u8]` so every object pointer derives from a real
/// Rust allocation (valid provenance). The watermark only advances; objects are
/// never individually freed (reclaiming requires retyping the whole region,
/// deferred).
pub struct UntypedRegion {
    bytes: &'static mut [u8],
    watermark: usize,
    has_children: bool,
}

impl UntypedRegion {
    /// Creates an untyped region over `bytes`.
    ///
    /// `bytes` must be aligned to at least [`ENDPOINT_ALIGN`] so that placed
    /// objects can meet their alignment (debug-asserted).
    pub fn new(bytes: &'static mut [u8]) -> Self {
        debug_assert!(
            (bytes.as_ptr() as usize).is_multiple_of(ENDPOINT_ALIGN),
            "untyped region base must be at least ENDPOINT_ALIGN aligned"
        );
        Self {
            bytes,
            watermark: 0,
            has_children: false,
        }
    }

    /// Returns the number of bytes already carved into objects.
    #[must_use]
    pub fn used(&self) -> usize {
        self.watermark
    }

    /// Returns an [`ObjectId`] (kind [`ObjectKind::Untyped`]) naming this
    /// region, so it can be installed as a capability and named by a syscall.
    ///
    /// The handle's address is the address of `self` (the `UntypedRegion`
    /// struct), exposed for provenance so [`ObjectId::as_untyped_mut`] can
    /// re-derive a pointer to it. The region must outlive every capability
    /// minted from this handle (in practice it is a `'static` kernel object).
    pub fn as_object_id(&mut self) -> ObjectId {
        let addr = core::ptr::from_mut::<UntypedRegion>(self).expose_provenance();
        ObjectId {
            addr,
            kind: ObjectKind::Untyped,
        }
    }

    /// Carves an object of `ty` into this region and returns its handle, or a
    /// [`RetypeError`] describing why it could not (full region, or a base too
    /// misaligned for the object). The fallible, syscall-facing counterpart of
    /// the `retype_*` helpers, which carve a fixed kind and treat misalignment
    /// as a programming-error panic.
    ///
    /// Only the object kinds with a concrete kernel type are supported here
    /// (`Endpoint`, `PageTable`, `Tcb`, `CNode`); a sub-`Untyped` carve is not
    /// yet a typed object, so it is rejected as [`RetypeError::BadType`].
    pub fn retype_object(&mut self, ty: ObjectType) -> Result<ObjectId, RetypeError> {
        // dispatch to the per-type carve helpers (each constructs exactly ONE
        // object in its own frame). do NOT inline the construction of all object
        // types into this match: a PageTable / KernelCNode is 4096 bytes by
        // value, and a match holding every arm's temporary at once (plus place's
        // by-value copy) overflows the syscall kernel stack in debug builds, the
        // same class of bug as the boot stack overflow. routing through the
        // existing single-object helpers keeps the stack profile to one object.
        //
        // these helpers return Option (full region -> None); the syscall path
        // also needs to distinguish a misalignment, so check alignment up front
        // and map None to NoRoom.
        let (_, align) = jos_core::untyped::object_layout(ty);
        if !(self.bytes.as_ptr() as usize).is_multiple_of(align) {
            // the region base is too misaligned for this object (for example a
            // PageTable / CNode in a merely 64-aligned region).
            return Err(RetypeError::BadAlign);
        }
        let carved = match ty {
            ObjectType::Endpoint => self.retype_endpoint(),
            ObjectType::Notification => self.retype_notification(),
            ObjectType::PageTable => self.retype_page_table(),
            ObjectType::Tcb => self.retype_tcb(),
            ObjectType::CNode { size_bits } if size_bits == KERNEL_CNODE_SIZE_BITS => {
                self.retype_cnode()
            }
            // a CNode of a non-kernel size, or a sub-Untyped, has no concrete
            // Rust object type to place: not supported via the syscall yet.
            ObjectType::CNode { .. } | ObjectType::Untyped { .. } => {
                return Err(RetypeError::BadType)
            }
        };
        carved.ok_or(RetypeError::NoRoom)
    }

    /// Carves a fresh [`Endpoint`] out of this region and returns its handle.
    ///
    /// Uses the Miri-checked `jos_core::placement::place` to write the object,
    /// then captures its address as an [`ObjectId`]. Returns `None` if the
    /// region has no room for another endpoint.
    pub fn retype_endpoint(&mut self) -> Option<ObjectId> {
        self.retype(ObjectType::Endpoint, Endpoint::new(), ObjectKind::Endpoint)
    }

    /// Carves a fresh idle [`Notification`] out of this region and returns its
    /// handle. Returns `None` if the region has no room for another one.
    pub fn retype_notification(&mut self) -> Option<ObjectId> {
        self.retype(
            ObjectType::Notification,
            Notification::new(),
            ObjectKind::Notification,
        )
    }

    /// Carves a fresh zeroed [`PageTable`] out of this region and returns its
    /// handle. Returns `None` if the region cannot fit a 4 KiB page table at
    /// the (aligned) watermark.
    ///
    /// Page tables are 4096-aligned, so this only succeeds when the region's
    /// base is itself page-aligned (a page table cannot be placed in a region
    /// whose base is merely 64-aligned). Callers that retype page tables must
    /// provide a page-aligned untyped region.
    pub fn retype_page_table(&mut self) -> Option<ObjectId> {
        self.retype(ObjectType::PageTable, PageTable::empty(), ObjectKind::PageTable)
    }

    /// Carves a fresh inactive [`Tcb`] out of this region and returns its
    /// handle. Returns `None` if the region has no room for another `Tcb`.
    pub fn retype_tcb(&mut self) -> Option<ObjectId> {
        self.retype(ObjectType::Tcb, Tcb::new(), ObjectKind::Tcb)
    }

    /// Carves a fresh empty [`KernelCNode`] (capability space) out of this
    /// region and returns its handle. Returns `None` if the region has no room.
    ///
    /// A CNode is [`CNODE_ALIGN`] (4096) aligned, so this only succeeds when the
    /// region's base is page-aligned; a merely 64-aligned region cannot hold a
    /// CNode (it would surface as a placement panic, like [`retype_page_table`]).
    ///
    /// [`retype_page_table`]: Self::retype_page_table
    pub fn retype_cnode(&mut self) -> Option<ObjectId> {
        self.retype(
            ObjectType::CNode {
                size_bits: KERNEL_CNODE_SIZE_BITS,
            },
            KernelCNode::new(),
            ObjectKind::CNode,
        )
    }

    // shared carving primitive: place `value` (whose layout must match `ty`)
    // into the region at the watermark, advance the watermark, and return an
    // ObjectId tagged `kind` whose address is the placement site. factors out
    // the body retype_endpoint had so every object type carves identically.
    fn retype<T>(&mut self, ty: ObjectType, value: T, kind: ObjectKind) -> Option<ObjectId> {
        match place(self.bytes, self.watermark, ty, value) {
            Ok((start, new_watermark)) => {
                self.watermark = new_watermark;
                self.has_children = true;
                // SAFETY: `start <= new_watermark - size` and `new_watermark <=
                // bytes.len()` (place returned them), so the offset is in bounds
                // and `add` stays within the region's provenance.
                let obj_ptr = unsafe { self.bytes.as_ptr().add(start) };
                let addr = obj_ptr.expose_provenance();
                Some(ObjectId { addr, kind })
            }
            Err(PlaceError::DoesNotFit) => None,
            Err(e) => panic!("retype: unexpected placement error for {kind:?}: {e:?}"),
        }
    }
}

// --------------------------------------------------------------------------
// IPC
// --------------------------------------------------------------------------

/// Errors from [`cap_send`] / [`cap_recv`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    /// The presented capability is stale or absent.
    InvalidCap,
    /// The capability does not carry the right required for this operation
    /// (`WRITE` for send, `READ` for receive).
    InsufficientRights,
    /// The capability names an object that is not an endpoint.
    NotAnEndpoint,
    /// `send` to an endpoint that already has a parked message.
    EndpointBusy,
    /// `recv` from an endpoint with no parked message.
    EndpointEmpty,
}

/// Errors from [`UntypedRegion::retype_object`] (the fallible, syscall-facing
/// carve).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetypeError {
    /// The untyped region has no room left for the requested object.
    NoRoom,
    /// The region's base is too misaligned for the requested object (for
    /// example, a `PageTable`/`CNode` needs page alignment).
    BadAlign,
    /// The requested object type cannot be carved via this path (a `CNode` of a
    /// non-kernel size, or a sub-`Untyped`, which have no concrete kernel type).
    BadType,
}

// resolves a capability ref to the endpoint it names, enforcing that it is
// live, carries `required`, and is actually an endpoint. shared by the send and
// receive paths so the three checks (and their error precedence) stay identical.
fn resolve_endpoint(
    space: &KernelCapSpace,
    cap_ref: CapRef,
    required: Rights,
) -> Result<&'static Endpoint, IpcError> {
    let cap = space.lookup(cap_ref).ok_or(IpcError::InvalidCap)?;
    if !space.check(cap_ref, required) {
        return Err(IpcError::InsufficientRights);
    }
    if cap.object.kind() != ObjectKind::Endpoint {
        return Err(IpcError::NotAnEndpoint);
    }
    // SAFETY: the capability is live (lookup succeeded) and names an endpoint
    // (checked above); single-CPU, interrupts-disabled context, so no aliasing
    // live &mut exists. the object outlives the kernel (static untyped region).
    Ok(unsafe { cap.object.as_endpoint() })
}

// the outcome of trying a non-blocking IPC op on a locked endpoint. on success
// it carries the counterpart waker to wake (a deposit may free a parked
// receiver; a take may free a parked sender) so the caller can wake AFTER
// releasing the endpoint lock, keeping the wake off the locked path.
enum SendOutcome {
    // message deposited; wake this receiver if present.
    Deposited(Option<Waker>),
    // endpoint already held an undelivered message.
    Full,
}

enum RecvOutcome {
    // message taken; wake this sender if present.
    Took(Message, Option<Waker>),
    // endpoint had no message.
    Empty,
}

impl EndpointInner {
    // try to deposit a message without blocking, delegating the rendezvous to
    // the verified state machine. the single locked primitive both cap_send and
    // the CapSend future build on, so the deposit/wake logic lives in exactly one
    // place and the take-or-park stays race-free (it all happens under one lock
    // acquisition by the caller). when the model reports a receiver was released,
    // its stored waker is taken so the caller can fire it after the lock drops.
    fn try_deposit(&mut self, message: Message) -> SendOutcome {
        match self.rendezvous.try_send(message) {
            endpoint::SendOutcome::Deposited { woke_receiver } => {
                // the model cleared its receiver_parked flag iff it released a
                // receiver; keep our waker slot in lockstep by taking it then.
                let waker = if woke_receiver { self.recv_waiter.take() } else { None };
                SendOutcome::Deposited(waker)
            }
            endpoint::SendOutcome::Full => SendOutcome::Full,
        }
    }

    // try to take the parked message without blocking, delegating to the model.
    fn try_take(&mut self) -> RecvOutcome {
        match self.rendezvous.try_recv() {
            endpoint::RecvOutcome::Took { message, woke_sender } => {
                let waker = if woke_sender { self.send_waiter.take() } else { None };
                RecvOutcome::Took(message, waker)
            }
            endpoint::RecvOutcome::Empty => RecvOutcome::Empty,
        }
    }

    // park the current task as the sender waiting for the slot to free, storing
    // its waker. mirrors the model's self-guarding park_sender: the waker is kept
    // iff the model actually records the sender as parked (slot full), so
    // send_waiter.is_some() stays equal to rendezvous.sender_parked().
    fn park_sender(&mut self, waker: Waker) {
        if self.rendezvous.park_sender() {
            self.send_waiter = Some(waker);
        }
    }

    // park the current task as the receiver waiting for a message; mirror of
    // park_sender.
    fn park_receiver(&mut self, waker: Waker) {
        if self.rendezvous.park_receiver() {
            self.recv_waiter = Some(waker);
        }
    }

    // clear both parked peers (on revoke), returning their wakers to fire. the
    // model clears its flags so its invariant holds; the wakers are returned so
    // the blocked tasks observe the cancellation on their next poll.
    fn clear_parked(&mut self) -> (Option<Waker>, Option<Waker>) {
        let (had_sender, had_receiver) = self.rendezvous.clear_parked();
        let send_waiter = if had_sender { self.send_waiter.take() } else { None };
        let recv_waiter = if had_receiver { self.recv_waiter.take() } else { None };
        (send_waiter, recv_waiter)
    }
}

/// Tries to send `message` over the endpoint named by `cap_ref`, without
/// blocking.
///
/// Requires the capability to carry [`Rights::WRITE`]. On success the message
/// is parked on the endpoint and any receiver blocked on it is woken. Returns
/// [`IpcError::EndpointBusy`] (rather than blocking) if the endpoint already
/// holds an undelivered message; [`send`] is the blocking wrapper.
///
/// # Errors
///
/// See [`IpcError`].
pub fn cap_send(space: &KernelCapSpace, cap_ref: CapRef, message: Message) -> Result<(), IpcError> {
    let endpoint = resolve_endpoint(space, cap_ref, Rights::WRITE)?;
    // do the deposit under the lock, then wake the receiver after releasing it.
    let to_wake = match endpoint.inner.lock().try_deposit(message) {
        SendOutcome::Deposited(waker) => waker,
        SendOutcome::Full => return Err(IpcError::EndpointBusy),
    };
    if let Some(waker) = to_wake {
        waker.wake();
    }
    Ok(())
}

/// Tries to receive a message from the endpoint named by `cap_ref`, without
/// blocking.
///
/// Requires the capability to carry [`Rights::READ`]. On success the endpoint
/// is drained and any sender blocked waiting for the slot to free is woken.
/// Returns [`IpcError::EndpointEmpty`] (rather than blocking) if no message is
/// parked; [`recv`] is the blocking wrapper.
///
/// # Errors
///
/// See [`IpcError`].
pub fn cap_recv(space: &KernelCapSpace, cap_ref: CapRef) -> Result<Message, IpcError> {
    let endpoint = resolve_endpoint(space, cap_ref, Rights::READ)?;
    let (message, to_wake) = match endpoint.inner.lock().try_take() {
        RecvOutcome::Took(message, waker) => (message, waker),
        RecvOutcome::Empty => return Err(IpcError::EndpointEmpty),
    };
    if let Some(waker) = to_wake {
        waker.wake();
    }
    Ok(message)
}

// --------------------------------------------------------------------------
// Async IPC
// --------------------------------------------------------------------------
//
// the blocking wrappers turn the non-blocking try-primitives into the
// async-as-scheduler rendezvous: a send to a full endpoint, or a recv from an
// empty one, parks the task's Waker in the endpoint and returns Poll::Pending
// instead of spinning; the counterpart op wakes it. each poll does the
// take-or-park under a SINGLE endpoint lock, so there is no window for a
// counterpart to act between the try and the park (no lost wakeup). the
// rights/liveness check runs on EVERY poll via resolve_endpoint, so revoking
// the capability under a blocked task cancels its IPC with InvalidCap on the
// next wake rather than hanging.

/// Future that sends a message over an endpoint, blocking (parking) while the
/// endpoint is busy. Created by [`send`].
#[must_use = "futures do nothing unless awaited"]
pub struct CapSend<'a> {
    space: &'a KernelCapSpace,
    cap_ref: CapRef,
    message: Message,
}

impl Future for CapSend<'_> {
    type Output = Result<(), IpcError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context) -> Poll<Self::Output> {
        let endpoint = match resolve_endpoint(self.space, self.cap_ref, Rights::WRITE) {
            Ok(endpoint) => endpoint,
            // bad cap / insufficient rights / wrong object: terminal, even if a
            // prior poll parked us. covers revocation while blocked.
            Err(e) => return Poll::Ready(Err(e)),
        };
        // take-or-park under one lock. the waker to wake (if any) is carried out
        // of the locked scope so it is woken after the lock is released.
        let to_wake = {
            let mut inner = endpoint.inner.lock();
            match inner.try_deposit(self.message) {
                SendOutcome::Deposited(waker) => waker,
                SendOutcome::Full => {
                    // endpoint full: park as the sender (storing our waker in the
                    // model + the waker slot together) so a receiver draining it
                    // wakes us, and yield. (lock drops at end of scope.)
                    inner.park_sender(context.waker().clone());
                    return Poll::Pending;
                }
            }
        };
        if let Some(waker) = to_wake {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }
}

/// Future that receives a message from an endpoint, blocking (parking) while
/// the endpoint is empty. Created by [`recv`].
#[must_use = "futures do nothing unless awaited"]
pub struct CapRecv<'a> {
    space: &'a KernelCapSpace,
    cap_ref: CapRef,
}

impl Future for CapRecv<'_> {
    type Output = Result<Message, IpcError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context) -> Poll<Self::Output> {
        let endpoint = match resolve_endpoint(self.space, self.cap_ref, Rights::READ) {
            Ok(endpoint) => endpoint,
            Err(e) => return Poll::Ready(Err(e)),
        };
        let (message, to_wake) = {
            let mut inner = endpoint.inner.lock();
            match inner.try_take() {
                RecvOutcome::Took(message, waker) => (message, waker),
                RecvOutcome::Empty => {
                    // endpoint empty: park as the receiver so a sender depositing
                    // a message wakes us, and yield.
                    inner.park_receiver(context.waker().clone());
                    return Poll::Pending;
                }
            }
        };
        if let Some(waker) = to_wake {
            waker.wake();
        }
        Poll::Ready(Ok(message))
    }
}

/// Sends `message` over the endpoint named by `cap_ref`, awaiting a free slot.
///
/// The async counterpart of [`cap_send`]: instead of returning
/// [`IpcError::EndpointBusy`], it parks until a receiver frees the endpoint.
/// Other terminal errors (invalid cap, insufficient rights, not an endpoint)
/// resolve the future immediately.
pub fn send(space: &KernelCapSpace, cap_ref: CapRef, message: Message) -> CapSend<'_> {
    CapSend {
        space,
        cap_ref,
        message,
    }
}

/// Receives a message from the endpoint named by `cap_ref`, awaiting one.
///
/// The async counterpart of [`cap_recv`]: instead of returning
/// [`IpcError::EndpointEmpty`], it parks until a sender deposits a message.
pub fn recv(space: &KernelCapSpace, cap_ref: CapRef) -> CapRecv<'_> {
    CapRecv { space, cap_ref }
}

// --------------------------------------------------------------------------
// Notification operations
// --------------------------------------------------------------------------
//
// the async counterpart to endpoint IPC: a signaller never blocks (it ORs its
// badge into the notification and returns, waking any parked waiter), and a
// waiter parks only when nothing is pending. like the endpoint path, each poll
// does the collect-or-park under a SINGLE notification lock (no lost-wakeup
// window), the rights/liveness check runs on every poll (so a revoke under a
// blocked waiter cancels it), and the waker is fired after the lock is released.

/// The badge bits a notification carries; the kernel re-export of the verified
/// [`notification::Badge`].
pub use jos_core::notification::Badge;

// resolves a capability ref to the notification it names, enforcing that it is
// live, carries `required`, and is actually a notification. the notification
// mirror of resolve_endpoint.
fn resolve_notification(
    space: &KernelCapSpace,
    cap_ref: CapRef,
    required: Rights,
) -> Result<&'static Notification, IpcError> {
    let cap = space.lookup(cap_ref).ok_or(IpcError::InvalidCap)?;
    if !space.check(cap_ref, required) {
        return Err(IpcError::InsufficientRights);
    }
    if cap.object.kind() != ObjectKind::Notification {
        return Err(IpcError::NotAnEndpoint);
    }
    // SAFETY: the capability is live (lookup succeeded) and names a notification
    // (checked above); single-CPU, interrupts-disabled context, so no aliasing
    // live &mut exists. the object outlives the kernel (static untyped region).
    Ok(unsafe { cap.object.as_notification() })
}

impl NotificationInner {
    // signal the notification, delegating to the verified state machine. returns
    // the waiter waker to fire (if the signal released a parked waiter) so the
    // caller can wake it after the lock drops, keeping the wake off the locked
    // path as the endpoint primitives do.
    fn signal(&mut self, badge: Badge) -> Option<Waker> {
        let outcome = self.state.signal(badge);
        // the model cleared its parked flag iff it released a waiter; keep our
        // waker slot in lockstep by taking it exactly then.
        if outcome.woke_waiter {
            self.waiter.take()
        } else {
            None
        }
    }

    // try to collect the pending badge without blocking, delegating to the model.
    fn try_collect(&mut self) -> notification::PollOutcome {
        self.state.poll()
    }

    // park the current task as the waiter, storing its waker. mirrors the model's
    // self-guarding park: the waker is kept iff the model records the waiter as
    // parked (nothing pending), so waiter.is_some() stays equal to
    // state.waiter_parked().
    fn park(&mut self, waker: Waker) {
        if self.state.park() {
            self.waiter = Some(waker);
        }
    }

    // clear the parked waiter (on revoke), returning its waker to fire.
    fn clear_parked(&mut self) -> Option<Waker> {
        if self.state.clear_parked() {
            self.waiter.take()
        } else {
            None
        }
    }
}

/// Signals the notification named by `cap_ref` with `badge`, without blocking.
///
/// Requires the capability to carry [`Rights::WRITE`]. The badge is coalesced
/// (OR-ed) into the notification's pending set, and any waiter blocked on it is
/// woken. Always succeeds for a live, sufficiently-righted capability (a
/// notification never blocks a signaller, the defining difference from
/// [`cap_send`]).
///
/// # Errors
///
/// See [`IpcError`] (invalid cap, insufficient rights, or not a notification).
pub fn cap_signal(space: &KernelCapSpace, cap_ref: CapRef, badge: Badge) -> Result<(), IpcError> {
    let notification = resolve_notification(space, cap_ref, Rights::WRITE)?;
    let to_wake = notification.inner.lock().signal(badge);
    if let Some(waker) = to_wake {
        waker.wake();
    }
    Ok(())
}

/// Future that waits for a notification, collecting (and clearing) its badge.
/// Parks while nothing is pending. Created by [`wait`].
#[must_use = "futures do nothing unless awaited"]
pub struct CapWait<'a> {
    space: &'a KernelCapSpace,
    cap_ref: CapRef,
}

impl Future for CapWait<'_> {
    type Output = Result<Badge, IpcError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context) -> Poll<Self::Output> {
        let notification = match resolve_notification(self.space, self.cap_ref, Rights::READ) {
            Ok(n) => n,
            // bad cap / insufficient rights / wrong object: terminal, even if a
            // prior poll parked us. covers revocation while blocked.
            Err(e) => return Poll::Ready(Err(e)),
        };
        // collect-or-park under one lock, so no signal can slip in between the
        // poll and the park (no lost wakeup).
        let mut inner = notification.inner.lock();
        match inner.try_collect() {
            notification::PollOutcome::Collected(badge) => Poll::Ready(Ok(badge)),
            notification::PollOutcome::Empty => {
                inner.park(context.waker().clone());
                Poll::Pending
            }
        }
    }
}

/// Waits on the notification named by `cap_ref`, awaiting a signal.
///
/// Requires [`Rights::READ`]. Resolves to the coalesced [`Badge`] once any
/// signal is pending (collecting and clearing it); parks until then. Terminal
/// errors (invalid cap, insufficient rights, not a notification) resolve the
/// future immediately, so revoking the capability under a parked waiter cancels
/// the wait with [`IpcError::InvalidCap`] on its next poll.
pub fn wait(space: &KernelCapSpace, cap_ref: CapRef) -> CapWait<'_> {
    CapWait { space, cap_ref }
}

// --------------------------------------------------------------------------
// Revocation that cancels blocked IPC
// --------------------------------------------------------------------------

/// Revokes `cap_ref` and its derivation subtree from `space`, and wakes any IPC
/// waiter parked on an endpoint named by a revoked capability so the blocked
/// task observes the cancellation instead of hanging forever.
///
/// Returns the number of capabilities removed (as [`CapSpace::revoke`] does).
///
/// The pure [`CapSpace::revoke`] only edits the capability table; it does not
/// know that a removed capability named an [`Endpoint`] with a parked
/// [`Waker`]. That waker would otherwise never fire, leaving a blocked
/// `recv`/`send` future stuck. This kernel-glue wrapper closes that gap: it
/// drains and wakes those wakers. A woken future re-polls, its per-poll
/// `resolve_endpoint` finds the now-stale capability, and it resolves to
/// [`IpcError::InvalidCap]` rather than re-parking.
///
/// The wake is done AFTER `revoke` has bumped the generations, so when the
/// woken task re-validates it genuinely sees the capability as gone. Because
/// the marked set is collected (via `for_each_in_subtree`) before `revoke`
/// clears the slots, the endpoint objects are still reachable to wake.
pub fn revoke_and_wake(space: &mut KernelCapSpace, cap_ref: CapRef) -> usize {
    // mark phase: collect the endpoint and notification objects in the revoke
    // subtree while the parent links are still intact. both own a parked waiter
    // that must be woken so a blocked future observes the cancellation. fixed-
    // size scratch sized to the space (no heap); CSPACE_SLOTS bounds the subtree.
    let mut blockers: [Option<ObjectId>; CSPACE_SLOTS] = [None; CSPACE_SLOTS];
    let mut count = 0;
    space.for_each_in_subtree(cap_ref, |_r, cap| {
        let kind = cap.object.kind();
        if matches!(kind, ObjectKind::Endpoint | ObjectKind::Notification) && count < CSPACE_SLOTS {
            blockers[count] = Some(cap.object);
            count += 1;
        }
    });

    // revoke: removes the capability entries and bumps their generations, so any
    // outstanding ref (including one a blocked future holds) is now stale.
    let removed = space.revoke(cap_ref);

    // wake phase: take and fire each parked waiter, AFTER releasing the object
    // lock (the wake transport is lock-free, but keep the wake off the locked
    // path as the cap_send/cap_recv primitives do). a woken future re-polls,
    // sees the stale cap, and returns InvalidCap.
    for obj in blockers.into_iter().take(count).flatten() {
        match obj.kind() {
            ObjectKind::Endpoint => {
                // SAFETY: obj.kind == Endpoint (checked in the mark phase), the
                // object outlives the kernel (static untyped region), single-CPU
                // interrupts-disabled context so no aliasing live &mut exists.
                let endpoint = unsafe { obj.as_endpoint() };
                let (send_waiter, recv_waiter) = {
                    let mut inner = endpoint.inner.lock();
                    // clear_parked clears the model's parked flags and hands back
                    // the matching wakers, keeping the invariant intact on revoke.
                    inner.clear_parked()
                };
                if let Some(waker) = send_waiter {
                    waker.wake();
                }
                if let Some(waker) = recv_waiter {
                    waker.wake();
                }
            }
            ObjectKind::Notification => {
                // SAFETY: obj.kind == Notification (checked in the mark phase),
                // the object outlives the kernel, single-CPU interrupts-disabled
                // context so no aliasing live &mut exists.
                let notification = unsafe { obj.as_notification() };
                let waiter = notification.inner.lock().clear_parked();
                if let Some(waker) = waiter {
                    waker.wake();
                }
            }
            // only Endpoint / Notification are collected in the mark phase.
            _ => {}
        }
    }

    removed
}

// --------------------------------------------------------------------------
// IPC futures that resolve the capability space afresh on every poll
// --------------------------------------------------------------------------
//
// CapSend/CapRecv borrow `&'a KernelCapSpace`, so the space cannot be mutated
// (revoked) while such a future is in flight: the borrow is held across the
// await. To cancel a PARKED waiter on revoke, the space must be resolved fresh
// on each poll instead, so a concurrent &mut revoke is sound. These futures
// hold a raw `*const KernelCapSpace` and re-derive a transient shared reference
// inside each poll only. This is the in-kernel mirror of the syscall path,
// where the CSpace is resolved per-call (slice 3d); the revoke happens between
// polls (cooperative single-threaded executor), so no reference is live across
// the mutation.

/// Future that receives a message, resolving its capability space on every
/// poll (so a revoke between polls cancels it with [`IpcError::InvalidCap`]).
/// Created by [`recv_resolving`].
#[must_use = "futures do nothing unless awaited"]
pub struct CapRecvResolving {
    space: *const KernelCapSpace,
    cap_ref: CapRef,
}

impl Future for CapRecvResolving {
    type Output = Result<Message, IpcError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context) -> Poll<Self::Output> {
        // SAFETY: the pointer was created from a valid &KernelCapSpace in
        // recv_resolving and the space outlives the future (its owner keeps it
        // alive for the IPC's duration). The executor is cooperative and single-
        // threaded, so no &mut to the space is live concurrently with this
        // transient shared borrow; any revoke runs between polls, not during one.
        let space = unsafe { &*self.space };
        let endpoint = match resolve_endpoint(space, self.cap_ref, Rights::READ) {
            Ok(endpoint) => endpoint,
            Err(e) => return Poll::Ready(Err(e)),
        };
        let (message, to_wake) = {
            let mut inner = endpoint.inner.lock();
            match inner.try_take() {
                RecvOutcome::Took(message, waker) => (message, waker),
                RecvOutcome::Empty => {
                    inner.park_receiver(context.waker().clone());
                    return Poll::Pending;
                }
            }
        };
        if let Some(waker) = to_wake {
            waker.wake();
        }
        Poll::Ready(Ok(message))
    }
}

/// Receives a message from the endpoint named by `cap_ref`, resolving the
/// capability `space` afresh on every poll.
///
/// Unlike [`recv`], which borrows the space for the future's whole lifetime,
/// this holds only a pointer and re-resolves each poll, so the space may be
/// mutated (a capability revoked) between polls. Revoking `cap_ref` (via
/// [`revoke_and_wake`]) while this future is parked wakes it, and the next poll
/// returns [`IpcError::InvalidCap`].
///
/// # Safety
///
/// `space` must remain valid and not be dropped for as long as the returned
/// future is alive, and the future must be polled only on the single-threaded
/// cooperative executor (no concurrent `&mut` to `*space` during a poll).
pub unsafe fn recv_resolving(space: *const KernelCapSpace, cap_ref: CapRef) -> CapRecvResolving {
    CapRecvResolving { space, cap_ref }
}
