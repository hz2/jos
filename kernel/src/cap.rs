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

use crate::clock;
use jos_core::cap_rights::Rights;
use jos_core::cap_space::{CapLink, CapSpace, SpaceId, relink_out_of, revoke_across};
use jos_core::cap_table::CapRef;
use jos_core::clock::Instant;
use jos_core::timer::TimerId;
// the verified rendezvous state machine. referenced by module path
// (`endpoint::Endpoint` etc.) so it does not collide with this module's own
// `Endpoint` object type or its `SendOutcome` / `RecvOutcome` adapter enums.
use jos_core::endpoint;
// the verified async notification state machine, referenced by module path
// (`notification::Notification`) so it does not collide with this module's own
// `Notification` kernel object type.
use jos_core::notification;
// the verified one-shot reply state machine, by module path for the same reason.
use jos_core::reply;
use jos_core::ipc_buffer::IpcBuffer;
use jos_core::placement::{place, place_zeroed, PlaceError};
use jos_core::untyped::{
    ObjectType, CNODE_ALIGN, CNODE_SIZE, ENDPOINT_ALIGN, ENDPOINT_SIZE, FRAME_ALIGN, FRAME_SIZE,
    NOTIFICATION_ALIGN, NOTIFICATION_SIZE, PAGE_TABLE_SIZE, REPLY_ALIGN, REPLY_SIZE, TCB_ALIGN,
    TCB_GUARD_OFFSET, TCB_HEADER_SIZE, TCB_SIZE, TCB_STACK_OFFSET,
};
use spin::Mutex;

/// End of the physical range the boot trampoline identity-maps (the first
/// 1 GiB). Kernel objects and IPC buffer frames must live below it.
pub const IDENTITY_MAPPED_LIMIT: u64 = 1 << 30;

/// Number of capability slots in a task's capability space (single-level for now).
pub const CSPACE_SLOTS: usize = 64;

/// The capability space type used by jos: a flat `CapSpace` of [`ObjectId`]s.
pub type KernelCapSpace = CapSpace<ObjectId, CSPACE_SLOTS>;

/// The most capability spaces the kernel tracks for copying and cross-space
/// revocation at once. A `CNode`'s entry is freed for the next one when
/// nothing can reach the `CNode` any more (see [`collect_cnodes`]).
pub const MAX_CSPACES: usize = 128;

const _: () = assert!(MAX_CSPACES <= SpaceId::MAX_ENTRIES, "a SpaceId names at most 255 entries");

/// Every registered capability space, by registry entry (a space's
/// [`SpaceId`] names its entry); null marks a free entry. An unregistered
/// space (id 0) keeps revocation local to itself.
static mut CSPACES: [*mut KernelCapSpace; MAX_CSPACES] = [core::ptr::null_mut(); MAX_CSPACES];
/// How many spaces each entry has held: a reused entry gives its new space a
/// fresh id, so a link left behind to the old space reaches nothing.
static mut CSPACE_GENERATIONS: [u32; MAX_CSPACES] = [0; MAX_CSPACES];
/// Whether each entry's space lives in a `CNode` object, and so is released
/// once nothing reaches it; the others are the kernel's own, never released.
static mut CSPACE_IS_CNODE: [bool; MAX_CSPACES] = [false; MAX_CSPACES];

/// Registers `space` so capabilities can be copied into it and revoked across
/// spaces, giving it a unique [`SpaceId`]. Returns `None` if the registry is
/// full or `space` already holds capabilities (their links would carry the old
/// id). For the kernel's own spaces; a `CNode` registers when it is retyped.
///
/// # Safety
///
/// `space` must stay live for the kernel's lifetime, and the caller must run
/// single-CPU with interrupts disabled (or during boot).
pub unsafe fn register_cspace(space: *mut KernelCapSpace) -> Option<SpaceId> {
    // SAFETY: per this function's contract.
    unsafe { register(space, false) }
}

/// Registers `space` in the lowest free entry; `cnode` marks a space that
/// lives in a `CNode` object.
///
/// # Safety
///
/// As [`register_cspace`].
unsafe fn register(space: *mut KernelCapSpace, cnode: bool) -> Option<SpaceId> {
    // SAFETY: per this function's contract, nothing else touches the registry
    // or `space` concurrently.
    unsafe {
        let entry = (*core::ptr::addr_of!(CSPACES)).iter().position(|s| s.is_null())?;
        let id = SpaceId::new(entry, CSPACE_GENERATIONS[entry])?;
        if !(*space).set_id(id) {
            return None;
        }
        CSPACES[entry] = space;
        CSPACE_IS_CNODE[entry] = cnode;
        Some(id)
    }
}

/// Returns `true` if the registry has a free entry.
pub fn registry_has_room() -> bool {
    // SAFETY: reads the table of pointers; single-CPU.
    unsafe { (*core::ptr::addr_of!(CSPACES)).iter().any(|s| s.is_null()) }
}

/// Returns the registered space `id` names, if it is still registered.
///
/// # Safety
///
/// Single-CPU with interrupts disabled.
unsafe fn registered(id: SpaceId) -> Option<*mut KernelCapSpace> {
    // SAFETY: per this function's contract; a non-null entry is a live space.
    unsafe {
        let space = *(*core::ptr::addr_of!(CSPACES)).get(id.entry()?)?;
        (!space.is_null() && (*space).id() == id).then_some(space)
    }
}

/// Runs `f` with every registered capability space, as a slice indexed by
/// registry entry with `None` for a free one.
///
/// # Safety
///
/// Single-CPU with interrupts disabled, and the caller must hold no other
/// reference into a registered space while `f` runs (or never use it again).
unsafe fn with_registered_spaces<R>(f: impl FnOnce(&mut [Option<&mut KernelCapSpace>]) -> R) -> R {
    // SAFETY: `Option<&mut T>` has the layout of `*mut T` with null as `None`,
    // every non-null entry is an aligned pointer to a space that lives for the
    // kernel lifetime, and distinct entries name distinct spaces, so the table
    // is a valid slice of non-aliasing `Option<&mut>`.
    unsafe {
        let ptr = core::ptr::addr_of_mut!(CSPACES).cast::<Option<&mut KernelCapSpace>>();
        f(core::slice::from_raw_parts_mut(ptr, MAX_CSPACES))
    }
}

/// Copies the capability `source` names into `slot` of `dest`, for a capability
/// sent with an IPC message. The copy keeps the source's rights and badge and
/// descends from it, so revoking the source reaches it. Returns `false` if the
/// source is gone (revoked since the send), lives in `dest` itself, or the slot
/// is out of range or taken.
///
/// # Safety
///
/// `dest` must point to a live capability space, and the caller must run
/// single-CPU with interrupts disabled and hold no reference into `dest`.
pub unsafe fn transfer_cap(source: CapLink, dest: *mut KernelCapSpace, slot: usize) -> bool {
    // SAFETY: per this function's contract; registered spaces live for the
    // kernel lifetime, and the source is distinct from dest (checked), so the
    // shared and exclusive references below do not alias.
    unsafe {
        let Some(src) = registered(source.space) else {
            return false;
        };
        if core::ptr::eq(src, dest) {
            return false;
        }
        (*src).copy_into(source.cap, &mut *dest, slot, Rights::ALL).is_ok()
    }
}

/// Returns `true` if a live capability in `local` or in any registered space
/// still names `object`.
///
/// # Safety
///
/// Single-CPU with interrupts disabled, and no exclusive reference into a
/// registered space may be live.
unsafe fn still_named(object: ObjectId, local: Option<&KernelCapSpace>) -> bool {
    if local.is_some_and(|s| s.any(|c| c.object == object)) {
        return true;
    }
    // SAFETY: per this function's contract; the registered entries live for the
    // kernel lifetime and are only read here.
    unsafe {
        let all: &[*mut KernelCapSpace; MAX_CSPACES] = &*core::ptr::addr_of!(CSPACES);
        all.iter().any(|&s| !s.is_null() && (*s).any(|c| c.object == object))
    }
}

/// Returns `true` if `space` is registered under the id it carries.
///
/// # Safety
///
/// `space` must be null or point to a live capability space; single-CPU.
pub(crate) unsafe fn is_registered(space: *mut KernelCapSpace) -> bool {
    // SAFETY: per this function's contract.
    !space.is_null() && unsafe { registered((*space).id()) }.is_some_and(|s| core::ptr::eq(s, space))
}

/// Checks the capability-space invariants for [`crate::selfcheck`] and
/// returns the bits of `REGISTRY`, `LINKS`, and `CNODES`
/// ([`jos_core::abi::invariant`]) that do not hold.
///
/// # Safety
///
/// Single-CPU with interrupts disabled, and no exclusive reference into a
/// registered space may be live.
pub(crate) unsafe fn check_spaces() -> u64 {
    use jos_core::abi::invariant::{CNODES, LINKS, REGISTRY};
    let mut failed = 0;
    // SAFETY: per this function's contract; the registry and every space in it
    // are only read.
    unsafe {
        let all = &*core::ptr::addr_of!(CSPACES);
        for (entry, &space) in all.iter().enumerate() {
            if space.is_null() {
                if CSPACE_IS_CNODE[entry] {
                    failed |= REGISTRY;
                }
                continue;
            }
            let own_id = SpaceId::new(entry, CSPACE_GENERATIONS[entry]);
            if Some((*space).id()) != own_id || all[..entry].iter().any(|&s| core::ptr::eq(s, space)) {
                failed |= REGISTRY;
            }
            (*space).for_each(|cap_ref, cap| {
                // a derivation keeps the object, and so does a relink.
                if let Some(parent) = cap.parent {
                    let resolved = registered(parent.space).and_then(|s| (*s).lookup(parent.cap));
                    if resolved.is_none_or(|p| p.object != cap.object) {
                        failed |= LINKS;
                    }
                }
                // every chain ends before it could have visited every slot.
                let mut link = Some(CapLink { space: (*space).id(), cap: cap_ref });
                for _ in 0..=MAX_CSPACES * CSPACE_SLOTS {
                    let Some(at) = link else { break };
                    link = registered(at.space).and_then(|s| (*s).lookup(at.cap)).and_then(|c| c.parent);
                }
                if link.is_some() {
                    failed |= LINKS;
                }
                if cap.object.kind() == ObjectKind::CNode
                    && !is_registered(core::ptr::with_exposed_provenance_mut(cap.object.addr))
                {
                    failed |= CNODES;
                }
            });
        }
    }
    failed
}

/// Releases every `CNode` that nothing can reach any more, and returns how
/// many it released.
///
/// A space is reached by a registered thread that runs in it, by being one of
/// the kernel's own registered spaces, or through a capability in a reached
/// space: to a `CNode`, or to a thread not yet retired, which keeps the space
/// it was configured with. Nothing can name a `CNode` that is not reached, so
/// its capabilities are dropped (what was derived from them elsewhere is
/// relinked past them first) and its entry is free for the next one. This
/// collects `CNode`s that name each other in a cycle too, which a count of
/// capabilities would keep forever.
///
/// # Safety
///
/// Single-CPU with interrupts disabled, and no reference into a registered
/// space may be live.
pub unsafe fn collect_cnodes() -> usize {
    let mut released = 0;
    loop {
        // SAFETY: per this function's contract.
        let reached = unsafe { reached_spaces() };
        let mut any = false;
        for (entry, &reached) in reached.iter().enumerate() {
            // SAFETY: per this function's contract; one flag read.
            if !reached && unsafe { CSPACE_IS_CNODE[entry] } {
                // SAFETY: per this function's contract, and the entry holds a
                // CNode that nothing reaches.
                unsafe { release_cnode(entry) };
                released += 1;
                any = true;
            }
        }
        // dropping capabilities can retire a thread, and leave more behind.
        if !any {
            return released;
        }
    }
}

/// Returns which registry entries are reached (see [`collect_cnodes`]).
///
/// # Safety
///
/// Single-CPU with interrupts disabled, and no exclusive reference into a
/// registered space or a thread may be live.
unsafe fn reached_spaces() -> [bool; MAX_CSPACES] {
    let mut reached = [false; MAX_CSPACES];
    let mut scanned = [false; MAX_CSPACES];
    // SAFETY: per this function's contract; entries and threads are only read.
    unsafe {
        for (entry, mark) in reached.iter_mut().enumerate() {
            *mark = !CSPACES[entry].is_null() && !CSPACE_IS_CNODE[entry];
        }
        crate::sched::for_each_thread(|_, tcb| {
            reach(&mut reached, (*tcb).cspace_ptr);
        });
        // each reached space is scanned once; a scan can reach more.
        while let Some(entry) = (0..MAX_CSPACES).find(|&e| reached[e] && !scanned[e]) {
            scanned[entry] = true;
            (*CSPACES[entry]).for_each(|_, cap| match cap.object.kind() {
                ObjectKind::CNode => {
                    reach(&mut reached, core::ptr::with_exposed_provenance_mut(cap.object.addr));
                }
                ObjectKind::Tcb => {
                    let tcb = core::ptr::with_exposed_provenance::<Tcb>(cap.object.addr);
                    if (*tcb).state != TcbState::Retired {
                        reach(&mut reached, (*tcb).cspace_ptr);
                    }
                }
                _ => {}
            });
        }
    }
    reached
}

/// Marks the registry entry of `space` reached, if it is registered.
///
/// # Safety
///
/// `space` must be null or point to a live capability space; single-CPU.
unsafe fn reach(reached: &mut [bool; MAX_CSPACES], space: *mut KernelCapSpace) {
    if space.is_null() {
        return;
    }
    // SAFETY: per this function's contract.
    let id = unsafe { (*space).id() };
    // SAFETY: single-CPU, per this function's contract.
    if unsafe { registered(id) }.is_some_and(|s| core::ptr::eq(s, space))
        && let Some(entry) = id.entry()
    {
        reached[entry] = true;
    }
}

/// Releases the `CNode` at registry entry `entry`: what was derived from its
/// capabilities elsewhere is relinked past them, its entry is freed, and each
/// of its capabilities is dropped, its object handled as [`capability_gone`]
/// handles a drop.
///
/// # Safety
///
/// As [`collect_cnodes`], and the entry must hold a `CNode` nothing reaches.
unsafe fn release_cnode(entry: usize) {
    // SAFETY: per this function's contract; the space stays live (its memory is
    // never reused), and once unregistered it is reached only through `space`.
    unsafe {
        let space = CSPACES[entry];
        with_registered_spaces(|spaces| relink_out_of(spaces, entry));
        CSPACES[entry] = core::ptr::null_mut();
        CSPACE_IS_CNODE[entry] = false;
        CSPACE_GENERATIONS[entry] = CSPACE_GENERATIONS[entry].wrapping_add(1);
        // out of the registry, so the liveness checks below see only the rest.
        for slot in 0..CSPACE_SLOTS {
            let Some(cap_ref) = (*space).ref_at(slot) else { continue };
            if let Some(cap) = (*space).remove(cap_ref) {
                capability_gone(cap.object, None, false);
            }
        }
        // an empty space takes id 0 again: a thread left pointing at it holds
        // nothing and links to nothing.
        let _ = (*space).set_id(SpaceId(0));
    }
}

/// Returns `true` if the thread `tcb` is `object`, or runs in it (its `CSpace`
/// or `VSpace`).
fn runs_on(tcb: &Tcb, object: ObjectId) -> bool {
    match object.kind() {
        ObjectKind::Tcb => core::ptr::from_ref(tcb).addr() == object.addr,
        ObjectKind::CNode => tcb.cspace_root == Some(object),
        ObjectKind::VSpace => tcb.vspace_root == object.phys_addr(),
        _ => false,
    }
}

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
    /// A one-shot reply object: binds to a caller, answered exactly once.
    Reply,
    /// One page of memory granted to a thread, for example as its IPC buffer.
    Frame,
    /// The root of an address space (a top-level page table).
    VSpace,
    /// The kernel console. Not carved from untyped: there is one, and only the
    /// root task is handed a capability to it at boot.
    Console,
    /// The machine itself: halting it, and later its diagnostics. One instance,
    /// handed only to the root task.
    Machine,
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

    /// Returns a shared reference to the [`Reply`] this handle names.
    ///
    /// # Safety
    ///
    /// As [`as_notification`](Self::as_notification): `self.kind` must be
    /// `ObjectKind::Reply`, the owning untyped region must be live, and the
    /// caller must be in a single-CPU, interrupts-disabled context.
    unsafe fn as_reply(self) -> &'static Reply {
        debug_assert_eq!(self.kind, ObjectKind::Reply);
        let ptr = core::ptr::with_exposed_provenance::<Reply>(self.addr);
        // SAFETY: the address was captured in retype (kind Reply) from a pointer
        // derived from the region base where a Reply was placed; it is live for
        // the kernel's lifetime. the caller guarantees the kind and that no
        // aliasing live &mut exists.
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
    /// The caller must ensure (1) `self.kind` is `ObjectKind::PageTable` or
    /// `ObjectKind::VSpace` (a root is a page table too), (2) the
    /// untyped region that owns the table is still live, and (3) no other live
    /// reference (shared or exclusive) to this table exists. Unlike an endpoint
    /// (whose state is behind a `Mutex`), a page table has no interior
    /// mutability, so mutation requires a genuinely exclusive `&mut`.
    pub(crate) unsafe fn as_page_table_mut(self) -> &'static mut PageTable {
        debug_assert!(matches!(self.kind, ObjectKind::PageTable | ObjectKind::VSpace));
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
// Platform objects
// --------------------------------------------------------------------------

/// A singleton kernel object that is not carved from untyped memory: the
/// console or the machine. Capabilities name its address; it holds no state
/// yet.
pub struct PlatformObject {
    /// Keeps the object non-zero-sized, so each instance has its own address.
    _byte: u8,
}

/// The one console object.
static CONSOLE: PlatformObject = PlatformObject { _byte: 0 };

/// The one machine object.
static MACHINE: PlatformObject = PlatformObject { _byte: 0 };

/// Returns the handle that console capabilities carry.
#[must_use]
pub fn console_object() -> ObjectId {
    ObjectId {
        addr: core::ptr::addr_of!(CONSOLE).expose_provenance(),
        kind: ObjectKind::Console,
    }
}

/// Returns the handle that machine capabilities carry.
#[must_use]
pub fn machine_object() -> ObjectId {
    ObjectId {
        addr: core::ptr::addr_of!(MACHINE).expose_provenance(),
        kind: ObjectKind::Machine,
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
// LOCK DISCIPLINE (load-bearing): no interrupt handler may acquire this lock.
// It is held only from task context, so unlike the timer locks in `clock.rs` it
// needs no `without_interrupts` guard. If a future device-IRQ path ever signals
// an endpoint (or notification) from interrupt context, that acquisition WOULD
// race a task holding the lock and spin-deadlock on single-core (spin::Mutex is
// not reentrant); such a path must either avoid the lock in the IRQ or wrap
// every TASK-context acquisition in `without_interrupts`, the way clock.rs does.
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
    /// Pad out to the full ENDPOINT_SIZE so the type's layout matches the
    /// untyped object size exactly (asserted below).
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
/// `&Notification` is enough to operate on it (signalling and the async wait
/// path). On single-CPU jos the lock is uncontended.
///
/// Same LOCK DISCIPLINE as [`Endpoint`]: this lock is acquired only from task
/// context and so needs no `without_interrupts` guard. A future device-IRQ that
/// signals a notification from interrupt context would reintroduce the
/// single-core spin-deadlock the timer locks in `clock.rs` avoid; such a path
/// must guard every task-context acquisition (or signal without the lock).
#[repr(C, align(64))]
pub struct Notification {
    inner: Mutex<NotificationInner>,
    /// Pad out to the full NOTIFICATION_SIZE so the type's layout matches the
    /// untyped object size exactly (asserted below).
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
// Reply object
// --------------------------------------------------------------------------

/// The mutable state of a reply object, behind its lock.
///
/// The verified [`reply::Reply`] state machine decides whether a bind or an
/// answer is allowed (one answer per bind); this struct adds only the thread id
/// of the bound caller, kept `Some` exactly when the model is waiting, so the
/// model decides delivery and this struct decides whom to resume.
#[derive(Debug)]
pub struct ReplyInner {
    /// The verified one-shot reply state.
    state: reply::Reply,
    /// Scheduler token of the bound caller (see [`crate::sched::token`]), so a
    /// caller that retires is never confused with the next thread in its slot;
    /// `Some` exactly when `state` is waiting.
    caller: Option<usize>,
}

impl ReplyInner {
    /// Returns `true` if no caller is bound and no answer is pending.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.state.is_idle()
    }

    /// Binds `caller` (a scheduler token) as the thread awaiting an answer.
    ///
    /// # Errors
    ///
    /// [`reply::ReplyError::Busy`] if a caller is already bound.
    pub fn bind(&mut self, caller: usize) -> Result<(), reply::ReplyError> {
        self.state.bind()?;
        self.caller = Some(caller);
        Ok(())
    }

    /// Answers the bound caller with `message`, returning its token so the
    /// kernel can resume it if it still runs. The message passes through the model (reply, then
    /// take), so the one-shot rule enforced is the verified one.
    ///
    /// # Errors
    ///
    /// [`reply::ReplyError::NotWaiting`] if no caller is bound.
    pub fn answer(&mut self, message: Message) -> Result<usize, reply::ReplyError> {
        self.state.reply(message)?;
        let _ = self.state.take();
        self.caller.take().ok_or(reply::ReplyError::NotWaiting)
    }

    /// Abandons the binding (the reply capability was revoked), returning the
    /// caller's token, if any, so it can be failed instead of hanging.
    pub fn cancel(&mut self) -> Option<usize> {
        self.state.cancel();
        self.caller.take()
    }
}

/// A one-shot reply object, sized and aligned to match [`ObjectType::Reply`].
///
/// A server names one when it receives with `RecvReply`; a `Call` binds it to
/// the calling thread, and the server answers through it exactly once with
/// `Reply`. The right to answer is the capability, not knowledge of who called.
/// Same lock discipline as [`Notification`]: task (syscall) context only.
#[repr(C, align(64))]
pub struct Reply {
    /// The reply state and bound caller.
    pub inner: Mutex<ReplyInner>,
    /// Pad out to the full REPLY_SIZE (asserted below).
    _pad: [u8; Reply::PAD],
}

impl Reply {
    // bytes of padding so size_of::<Reply>() == REPLY_SIZE.
    const PAD: usize = REPLY_SIZE - core::mem::size_of::<Mutex<ReplyInner>>();

    /// Creates a fresh idle reply object.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(ReplyInner {
                state: reply::Reply::new(),
                caller: None,
            }),
            _pad: [0; Self::PAD],
        }
    }
}

impl Default for Reply {
    fn default() -> Self {
        Self::new()
    }
}

const _: () = assert!(core::mem::size_of::<Reply>() == REPLY_SIZE);
const _: () = assert!(core::mem::align_of::<Reply>() == REPLY_ALIGN);

/// Returns the [`Reply`] object `obj` names, or `None` if it is not a reply.
///
/// The kind check makes this safe to call with any handle; it must run in the
/// single-CPU, interrupts-disabled syscall or revoke path like every other
/// object access.
#[must_use]
pub fn reply_object(obj: ObjectId) -> Option<&'static Reply> {
    if obj.kind() != ObjectKind::Reply {
        return None;
    }
    // SAFETY: the kind is Reply (checked above); the object lives in a static
    // untyped region for the kernel's lifetime; callers run single-CPU with
    // interrupts disabled, so no aliasing live &mut exists.
    Some(unsafe { obj.as_reply() })
}

// --------------------------------------------------------------------------
// Frame object
// --------------------------------------------------------------------------

/// One page of memory, sized and aligned to match [`ObjectType::Frame`].
///
/// The kernel never interprets a frame's bytes; holding a capability to it is
/// the authority to use the page, for example to register it as a thread's IPC
/// buffer. Carved from untyped memory, it is zeroed when created.
#[repr(C, align(4096))]
pub struct Frame {
    bytes: [u8; FRAME_SIZE],
}

impl Frame {
    /// Creates a zeroed frame.
    #[must_use]
    pub const fn new() -> Self {
        Self { bytes: [0; FRAME_SIZE] }
    }
}

impl Default for Frame {
    fn default() -> Self {
        Self::new()
    }
}

const _: () = assert!(core::mem::size_of::<Frame>() == FRAME_SIZE);
const _: () = assert!(core::mem::align_of::<Frame>() == FRAME_ALIGN);

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
    /// Parked after a fault until its fault handler answers; an answer
    /// resumes it at the faulting instruction with its registers untouched.
    Faulted,
    /// Stopped for good: its TCB, `CNode`, or `VSpace` lost its last capability.
    Retired,
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
    /// Physical address of the thread's `VSpace` root, loaded into `CR3` by
    /// [`switch_to`](crate::cpu_local::switch_to). Zero means "no address space
    /// assigned yet": the thread runs in whatever address space is active.
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
    /// Physical address of the frame this thread registered as its IPC buffer,
    /// or zero for none. The kernel reaches the buffer through its own identity
    /// mapping of this frame, never through a user virtual address.
    pub ipc_buffer: u64,
    /// The slot, in the thread's own capability space, of the endpoint its
    /// faults are delivered to, plus one; zero for none. Resolved when a fault
    /// happens, so revoking that capability takes the handler away.
    pub fault_slot: u64,
    /// The thread's run state. Last of the real fields (a small type), before
    /// the padding, so it introduces no interior alignment gap.
    pub state: TcbState,
    /// Pad to the full TCB_HEADER_SIZE: the header at the start of a TCB object.
    _pad: [u8; Tcb::PAD],
}

impl Tcb {
    // bytes of padding so size_of::<Tcb>() == TCB_HEADER_SIZE, from the sum of the real
    // fields' sizes. This is sound only because every field is 8-byte-sized and
    // 8-aligned, so repr(C) inserts NO inter-field padding and the sum equals the
    // true used-bytes offset. (offset_of!(Tcb, _pad) would be exact regardless,
    // but it cycles here: _pad's type is [u8; PAD] and PAD would depend on its
    // own offset.) The real backstop is the `size_of::<Tcb>() == TCB_SIZE`
    // assertion below: if a future field introduces inter-field padding, or the
    // sum drifts, PAD is wrong and that assertion fails the build loudly. Keep
    // new fields 8-aligned (or update this sum) so the no-padding premise holds.
    const USED: usize = core::mem::size_of::<SavedContext>()
        + core::mem::size_of::<u64>()
        + core::mem::size_of::<u64>()
        + core::mem::size_of::<Option<ObjectId>>()
        + core::mem::size_of::<u64>()
        + core::mem::size_of::<TcbState>()
        + core::mem::size_of::<u64>()
        + core::mem::size_of::<*mut KernelCapSpace>();
    const PAD: usize = TCB_HEADER_SIZE - Self::USED;

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
            ipc_buffer: 0,
            fault_slot: 0,
            state: TcbState::Inactive,
            kernel_stack_top: 0,
            cspace_ptr: core::ptr::null_mut(),
            _pad: [0; Self::PAD],
        }
    }
}

impl Tcb {
    /// Returns a pointer to this thread's IPC buffer through the kernel's
    /// identity mapping, or `None` if no buffer is registered or the address is
    /// not a page-aligned frame inside the identity-mapped range.
    #[must_use]
    pub fn ipc_buffer_ptr(&self) -> Option<*mut IpcBuffer> {
        let phys = self.ipc_buffer;
        if phys == 0 || !phys.is_multiple_of(4096) || phys >= IDENTITY_MAPPED_LIMIT {
            return None;
        }
        let addr = usize::try_from(phys).ok()?;
        // the frame is reached like any other physical memory the kernel owns:
        // through the boot identity map, where virtual equals physical.
        Some(core::ptr::with_exposed_provenance_mut::<IpcBuffer>(addr))
    }
}

impl Default for Tcb {
    fn default() -> Self {
        Self::new()
    }
}

const _: () = assert!(core::mem::size_of::<Tcb>() == TCB_HEADER_SIZE);

/// A whole TCB object as placed in untyped memory: the [`Tcb`] header page, an
/// unmapped guard page, then the thread's kernel stack, which grows down from
/// the end of the object toward the guard.
///
/// Sized and aligned to match [`ObjectType::Tcb`], so carving one object gives
/// a complete thread and the kernel never allocates a stack.
#[repr(C, align(4096))]
pub struct TcbObject {
    /// The thread control block itself.
    pub tcb: Tcb,
    /// The rest of the header page.
    _header_rest: [u8; TCB_GUARD_OFFSET - TCB_HEADER_SIZE],
    /// Left unmapped by [`UntypedRegion::retype_tcb`], so a kernel stack
    /// overflow faults here instead of overwriting the header.
    _guard: [u8; TCB_STACK_OFFSET - TCB_GUARD_OFFSET],
    /// The thread's kernel stack.
    stack: [u8; TCB_SIZE - TCB_STACK_OFFSET],
}

const _: () = assert!(core::mem::size_of::<TcbObject>() == TCB_SIZE);
const _: () = assert!(core::mem::align_of::<TcbObject>() == TCB_ALIGN);
const _: () = assert!(core::mem::offset_of!(TcbObject, tcb) == 0);
const _: () = assert!(core::mem::offset_of!(TcbObject, _guard) == TCB_GUARD_OFFSET);
const _: () = assert!(core::mem::offset_of!(TcbObject, stack) == TCB_STACK_OFFSET);

// --------------------------------------------------------------------------
// CNode object
// --------------------------------------------------------------------------

/// `size_bits` of the kernel's `CNode` object: log2 of [`CNODE_SIZE`] (4096),
/// the [`ObjectType::CNode`] argument used when carving one from untyped.
pub const KERNEL_CNODE_SIZE_BITS: u8 = jos_core::abi::CNODE_SIZE_BITS;

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
    /// Pad out to the full CNODE_SIZE so the layout matches ObjectType::CNode.
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

    /// Returns the address of the region's first byte.
    #[must_use]
    pub fn base(&self) -> usize {
        self.bytes.as_ptr().addr()
    }

    /// Returns the size of the region in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.bytes.len()
    }

    /// Returns the number of bytes not yet carved.
    #[must_use]
    pub fn free(&self) -> usize {
        self.bytes.len() - self.watermark
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
        //
        // a CNode of a non-kernel size, or a sub-Untyped, has no concrete Rust
        // object type to place: say so first, since no alignment would help.
        let supported = match ty {
            ObjectType::CNode { size_bits } => size_bits == KERNEL_CNODE_SIZE_BITS,
            ObjectType::Untyped { .. } => false,
            _ => true,
        };
        if !supported {
            return Err(RetypeError::BadType);
        }
        let (_, align) = jos_core::untyped::object_layout(ty);
        if !(self.bytes.as_ptr() as usize).is_multiple_of(align) {
            // the region base is too misaligned for this object (for example a
            // PageTable / CNode in a merely 64-aligned region).
            return Err(RetypeError::BadAlign);
        }
        let carved = match ty {
            ObjectType::Endpoint => self.retype_endpoint(),
            ObjectType::Notification => self.retype_notification(),
            ObjectType::Reply => self.retype_reply(),
            ObjectType::Frame => self.retype_frame(),
            ObjectType::VSpace => self.retype_vspace(),
            ObjectType::PageTable => self.retype_page_table(),
            ObjectType::Tcb => self.retype_tcb(),
            ObjectType::CNode { size_bits } if size_bits == KERNEL_CNODE_SIZE_BITS => {
                self.retype_cnode()
            }
            // refused above.
            ObjectType::CNode { .. } | ObjectType::Untyped { .. } => return Err(RetypeError::BadType),
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

    /// Carves a fresh address-space root out of this region: a zeroed top-level
    /// table with the kernel's own root entries copied in, so the kernel stays
    /// mapped when it is loaded. Returns `None` if the region has no room or is
    /// not page aligned.
    pub fn retype_vspace(&mut self) -> Option<ObjectId> {
        let root = self.retype_zeroed(ObjectType::VSpace, ObjectKind::VSpace)?;
        // SAFETY: root was just carved as a VSpace and nothing else refers to it;
        // CR3 holds the kernel's boot root, which every VSpace copies from.
        unsafe { crate::vspace::clone_kernel_entries(root) };
        Some(root)
    }

    /// Carves a fresh zeroed [`Frame`] out of this region and returns its handle.
    /// Returns `None` if the region has no room, or if its base is not page
    /// aligned (a frame is 4096-aligned, like a page table).
    pub fn retype_frame(&mut self) -> Option<ObjectId> {
        self.retype_zeroed(ObjectType::Frame, ObjectKind::Frame)
    }

    /// Carves a fresh idle [`Reply`] out of this region and returns its handle.
    /// Returns `None` if the region has no room for another one.
    pub fn retype_reply(&mut self) -> Option<ObjectId> {
        self.retype(ObjectType::Reply, Reply::new(), ObjectKind::Reply)
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
        self.retype_zeroed(ObjectType::PageTable, ObjectKind::PageTable)
    }

    /// Carves a fresh inactive [`Tcb`] out of this region and returns its
    /// handle, with the guard page under its kernel stack unmapped. Returns
    /// `None` if the region has no room for another `Tcb`, or if the guard
    /// cannot be unmapped (the split-table pool is exhausted); the memory is
    /// spent either way, since untyped memory is never reclaimed.
    pub fn retype_tcb(&mut self) -> Option<ObjectId> {
        // reserve the whole object zeroed (the stack needs no other start), then
        // write only the small header in place: the object is five pages, far
        // too big to build by value on a syscall stack.
        let id = self.retype_zeroed(ObjectType::Tcb, ObjectKind::Tcb)?;
        let ptr = core::ptr::with_exposed_provenance_mut::<TcbObject>(id.addr);
        // SAFETY: id names the object just reserved, aligned for TcbObject, and
        // nothing else refers to it yet. the header is written field-wise in
        // place, and the stack top is the end of the object.
        unsafe {
            core::ptr::addr_of_mut!((*ptr).tcb).write(Tcb::new());
            (*ptr).tcb.kernel_stack_top = (id.addr + TCB_SIZE) as u64;
        }
        // SAFETY: the guard page lies inside the object just carved, and nothing
        // reads or writes it; retype runs single-CPU with interrupts disabled.
        unsafe { crate::guard_page::unmap_identity_page((id.addr + TCB_GUARD_OFFSET) as u64) }.ok()?;
        Some(id)
    }

    /// Carves a fresh empty [`KernelCNode`] (capability space) out of this
    /// region, registered so capabilities can be copied into it and revoked
    /// across spaces, and returns its handle. Returns `None` if the region has
    /// no room, or the registry has no free entry (nothing is carved then;
    /// [`collect_cnodes`] frees the entries of `CNode`s nothing reaches).
    ///
    /// A CNode is [`CNODE_ALIGN`] (4096) aligned, so this only succeeds when the
    /// region's base is page-aligned; a merely 64-aligned region cannot hold a
    /// CNode (it would surface as a placement panic, like [`retype_page_table`]).
    ///
    /// [`retype_page_table`]: Self::retype_page_table
    pub fn retype_cnode(&mut self) -> Option<ObjectId> {
        // an unregistered CNode would keep revocation from reaching copies in it.
        if !registry_has_room() {
            return None;
        }
        // reserve the page zeroed, then build the capability space in place: a
        // KernelCNode is 4 KiB, too big to build by value on a syscall stack.
        let ty = ObjectType::CNode { size_bits: KERNEL_CNODE_SIZE_BITS };
        let id = self.retype_zeroed(ty, ObjectKind::CNode)?;
        let ptr = core::ptr::with_exposed_provenance_mut::<KernelCNode>(id.addr);
        // SAFETY: id names the page just reserved for this CNode, aligned for
        // KernelCNode, and nothing else refers to it yet. repr(C) puts `space`
        // first, and the padding after it is already zero.
        unsafe { KernelCapSpace::init_in_place(core::ptr::addr_of_mut!((*ptr).space)) };
        // SAFETY: the space lives in the static untyped region for the kernel's
        // lifetime; retype runs single-CPU with interrupts disabled. the space is
        // empty and the registry has room, so this succeeds.
        unsafe { register(core::ptr::addr_of_mut!((*ptr).space), true) }?;
        Some(id)
    }

    /// Records a successful placement at `start` and returns a handle to it.
    fn commit(&mut self, start: usize, new_watermark: usize, kind: ObjectKind) -> ObjectId {
        self.watermark = new_watermark;
        self.has_children = true;
        // derive from as_MUT_ptr, not as_ptr: the address is later
        // reconstructed as a *mut T (as_page_table_mut / as_tcb_mut /
        // as_cnode_mut / as_untyped_mut) and WRITTEN through. as_ptr
        // would expose read-only provenance, so a write through the
        // reconstructed pointer would be UB under strict provenance
        // (Stacked/Tree Borrows); as_mut_ptr exposes write provenance.
        // SAFETY: `start <= new_watermark - size` and `new_watermark <=
        // bytes.len()` (the placement returned them), so the offset is in
        // bounds and `add` stays within the region's provenance.
        let obj_ptr = unsafe { self.bytes.as_mut_ptr().add(start) };
        let addr = obj_ptr.expose_provenance();
        ObjectId { addr, kind }
    }

    /// Carves an object whose initial state is all zeros (a frame or an empty
    /// page table) by zeroing its bytes in place.
    ///
    /// Building a 4 KiB value and copying it through [`place`] costs two pages
    /// of kernel stack, which overflows the per-thread syscall stack in debug
    /// builds and silently corrupts the handle being built.
    fn retype_zeroed(&mut self, ty: ObjectType, kind: ObjectKind) -> Option<ObjectId> {
        match place_zeroed(self.bytes, self.watermark, ty) {
            Ok((start, new_watermark)) => Some(self.commit(start, new_watermark, kind)),
            Err(PlaceError::DoesNotFit) => None,
            Err(e) => panic!("retype: unexpected placement error for {kind:?}: {e:?}"),
        }
    }

    /// Shared carving primitive: places `value` (whose layout must match `ty`)
    /// into the region at the watermark, advances the watermark, and returns an
    /// `ObjectId` tagged `kind` whose address is the placement site. Only for
    /// small objects; page-sized ones use [`retype_zeroed`](Self::retype_zeroed).
    fn retype<T>(&mut self, ty: ObjectType, value: T, kind: ObjectKind) -> Option<ObjectId> {
        match place(self.bytes, self.watermark, ty, value) {
            Ok((start, new_watermark)) => Some(self.commit(start, new_watermark, kind)),
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

/// Resolves a capability ref to the endpoint it names, enforcing that it is
/// live, carries `required`, and is actually an endpoint. Shared by the send and
/// receive paths so the three checks (and their error precedence) stay identical.
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

/// The outcome of trying a non-blocking IPC op on a locked endpoint. On success
/// it carries the counterpart waker to wake (a deposit may free a parked
/// receiver; a take may free a parked sender) so the caller can wake AFTER
/// releasing the endpoint lock, keeping the wake off the locked path.
enum SendOutcome {
    /// Message deposited; wake this receiver if present.
    Deposited(Option<Waker>),
    /// Endpoint already held an undelivered message.
    Full,
}

enum RecvOutcome {
    /// Message taken with the sender badge; wake this sender if present.
    Took(Message, Badge, Option<Waker>),
    /// Endpoint had no message.
    Empty,
}

impl EndpointInner {
    /// Try to deposit a message without blocking, delegating the rendezvous to
    /// the verified state machine. The single locked primitive both cap_send and
    /// the CapSend future build on, so the deposit/wake logic lives in exactly one
    /// place and the take-or-park stays race-free (it all happens under one lock
    /// acquisition by the caller). When the model reports a receiver was released,
    /// its stored waker is taken so the caller can fire it after the lock drops.
    fn try_deposit(&mut self, message: Message, badge: Badge) -> SendOutcome {
        match self.rendezvous.try_send_badged(message, badge) {
            endpoint::SendOutcome::Deposited { woke_receiver } => {
                // the model cleared its receiver_parked flag iff it released a
                // receiver; keep our waker slot in lockstep by taking it then.
                let waker = if woke_receiver { self.recv_waiter.take() } else { None };
                SendOutcome::Deposited(waker)
            }
            endpoint::SendOutcome::Full => SendOutcome::Full,
        }
    }

    /// Try to take the parked message without blocking, delegating to the model.
    fn try_take(&mut self) -> RecvOutcome {
        match self.rendezvous.try_recv() {
            endpoint::RecvOutcome::Took { message, badge, woke_sender } => {
                let waker = if woke_sender { self.send_waiter.take() } else { None };
                RecvOutcome::Took(message, badge, waker)
            }
            endpoint::RecvOutcome::Empty => RecvOutcome::Empty,
        }
    }

    /// Park the current task as the sender waiting for the slot to free, storing
    /// its waker. Mirrors the model's self-guarding park_sender: the waker is kept
    /// iff the model actually records the sender as parked (slot full), so
    /// send_waiter.is_some() stays equal to rendezvous.sender_parked().
    fn park_sender(&mut self, waker: Waker) {
        if self.rendezvous.park_sender() {
            self.send_waiter = Some(waker);
        }
    }

    /// Park the current task as the receiver waiting for a message; mirror of
    /// park_sender.
    fn park_receiver(&mut self, waker: Waker) {
        if self.rendezvous.park_receiver() {
            self.recv_waiter = Some(waker);
        }
    }

    /// Clear just the parked receiver (a receive-with-timeout abandoning its
    /// blocked recv when the deadline passes), returning its waker if any. Mirrors
    /// the model's cancel_receiver: only the receiver is cleared, so send_waiter
    /// and the slot are untouched and the lockstep invariant holds.
    fn cancel_receiver(&mut self) -> Option<Waker> {
        if self.rendezvous.cancel_receiver() {
            self.recv_waiter.take()
        } else {
            None
        }
    }

    /// Clear both parked peers (on revoke), returning their wakers to fire. The
    /// model clears its flags so its invariant holds; the wakers are returned so
    /// the blocked tasks observe the cancellation on their next poll.
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
    let badge = cap_badge(space, cap_ref);
    // do the deposit under the lock, then wake the receiver after releasing it.
    let to_wake = match endpoint.inner.lock().try_deposit(message, badge) {
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
    cap_recv_badged(space, cap_ref).map(|(message, _)| message)
}

/// Like [`cap_recv`], but also returns the badge of the capability the message
/// was sent through, so a server can tell which client sent it.
///
/// # Errors
///
/// See [`IpcError`].
pub fn cap_recv_badged(
    space: &KernelCapSpace,
    cap_ref: CapRef,
) -> Result<(Message, Badge), IpcError> {
    let endpoint = resolve_endpoint(space, cap_ref, Rights::READ)?;
    let (message, badge, to_wake) = match endpoint.inner.lock().try_take() {
        RecvOutcome::Took(message, badge, waker) => (message, badge, waker),
        RecvOutcome::Empty => return Err(IpcError::EndpointEmpty),
    };
    if let Some(waker) = to_wake {
        waker.wake();
    }
    Ok((message, badge))
}

/// Returns the badge stamped on the capability at `cap_ref`, or
/// [`Badge::NONE`] if the reference is stale.
fn cap_badge(space: &KernelCapSpace, cap_ref: CapRef) -> Badge {
    space.lookup(cap_ref).map_or(Badge::NONE, |cap| cap.badge)
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
            match inner.try_deposit(self.message, cap_badge(self.space, self.cap_ref)) {
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
                RecvOutcome::Took(message, _, waker) => (message, waker),
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

/// The outcome of a [`recv_timeout`]: a delivered message, or a timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvTimeout {
    /// A message was received before the deadline.
    Message(Message),
    /// The deadline passed before any message arrived.
    TimedOut,
}

/// Future that receives a message from an endpoint, giving up at a deadline.
/// Created by [`recv_timeout`].
///
/// This is the consumer that makes IPC deadlock-freedom real: a blocked `recv`
/// can no longer wait forever. Each poll resolves the endpoint and tries to
/// receive; if the slot is empty it parks the receiver AND (once) arms a global
/// timer for the deadline, registering this task's waker. Whichever fires first
/// wins: a sender's deposit wakes the parked receiver (and the next poll cancels
/// the timer), or the timer fires at the deadline (and the next poll observes
/// the deadline passed, cancels the parked receiver, and reports
/// [`RecvTimeout::TimedOut`]). The endpoint stays clock-free; the timer lives one
/// layer up, exactly as the deterministic-simulation slice plan prescribed.
#[must_use = "futures do nothing unless awaited"]
pub struct CapRecvTimeout<'a> {
    space: &'a KernelCapSpace,
    cap_ref: CapRef,
    deadline: Instant,
    /// The armed timer's id, set on the first poll that parks. Used to cancel the
    /// timer if a message wins, and to avoid arming more than once.
    timer: Option<TimerId>,
}

impl Future for CapRecvTimeout<'_> {
    type Output = Result<RecvTimeout, IpcError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context) -> Poll<Self::Output> {
        let endpoint = match resolve_endpoint(self.space, self.cap_ref, Rights::READ) {
            Ok(endpoint) => endpoint,
            Err(e) => return Poll::Ready(Err(e)),
        };

        // try to receive. on success, cancel any armed timer and deliver.
        let (message, to_wake) = {
            let mut inner = endpoint.inner.lock();
            match inner.try_take() {
                RecvOutcome::Took(message, _, waker) => (message, waker),
                RecvOutcome::Empty => {
                    // nothing waiting. if the deadline has passed, time out:
                    // cancel our parked receiver and report TimedOut.
                    if clock::now().reached(self.deadline) {
                        inner.cancel_receiver();
                        drop(inner);
                        if let Some(id) = self.timer.take() {
                            clock::cancel(id);
                            clock::forget_timer_waker(id);
                        }
                        return Poll::Ready(Ok(RecvTimeout::TimedOut));
                    }
                    // not yet due: park the receiver so a sender wakes us.
                    inner.park_receiver(context.waker().clone());
                    drop(inner);
                    // arm a timer for the deadline (once), so the timer IRQ wakes
                    // us at the deadline even if no sender ever arrives, and
                    // register this task's waker under the returned id (the IRQ
                    // fires it by id). the timer's data word is unused here.
                    // arm once. if the global queue is full, arm returns None and
                    // we fall back to a bare park: a sender can still wake us, and
                    // the deadline is then enforced on a later poll that observes
                    // now >= deadline, so progress still holds.
                    if self.timer.is_none()
                        && let Some(id) = clock::arm(self.deadline, 0)
                    {
                        clock::register_timer_waker(id, context.waker().clone());
                        self.timer = Some(id);
                    }
                    return Poll::Pending;
                }
            }
        };
        // a message won: cancel the timer so it cannot fire a stale wakeup.
        if let Some(id) = self.timer.take() {
            clock::cancel(id);
            clock::forget_timer_waker(id);
        }
        if let Some(waker) = to_wake {
            waker.wake();
        }
        Poll::Ready(Ok(RecvTimeout::Message(message)))
    }
}

/// Receives a message from the endpoint named by `cap_ref`, giving up at
/// `deadline` (a [`jos_core::clock::Instant`] on the kernel's TSC clock).
///
/// The bounded counterpart of [`recv`]: it parks until a message arrives or the
/// deadline passes, resolving to [`RecvTimeout::Message`] or
/// [`RecvTimeout::TimedOut`]. This is what makes a blocked receive provably
/// terminate (IPC deadlock-freedom): the timer IRQ guarantees a wakeup at the
/// deadline even with no sender.
pub fn recv_timeout(
    space: &KernelCapSpace,
    cap_ref: CapRef,
    deadline: Instant,
) -> CapRecvTimeout<'_> {
    CapRecvTimeout {
        space,
        cap_ref,
        deadline,
        timer: None,
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

/// Resolves a capability ref to the notification it names, enforcing that it is
/// live, carries `required`, and is actually a notification. The notification
/// mirror of resolve_endpoint.
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
    /// Signal the notification, delegating to the verified state machine. Returns
    /// the waiter waker to fire (if the signal released a parked waiter) so the
    /// caller can wake it after the lock drops, keeping the wake off the locked
    /// path as the endpoint primitives do.
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

    /// Try to collect the pending badge without blocking, delegating to the model.
    fn try_collect(&mut self) -> notification::PollOutcome {
        self.state.poll()
    }

    /// Park the current task as the waiter, storing its waker. Mirrors the model's
    /// self-guarding park: the waker is kept iff the model records the waiter as
    /// parked (nothing pending), so waiter.is_some() stays equal to
    /// state.waiter_parked().
    fn park(&mut self, waker: Waker) {
        if self.state.park() {
            self.waiter = Some(waker);
        }
    }

    /// Clear the parked waiter (on revoke), returning its waker to fire.
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
    resolve_notification(space, cap_ref, Rights::WRITE)?;
    let object = space.lookup(cap_ref).ok_or(IpcError::InvalidCap)?.object;
    // the same path as the signal syscall, so a thread blocked in wait hears it.
    crate::syscall::signal_notification(object, badge.0);
    Ok(())
}

/// Coalesces `badge` into the pending bits of the notification `object`, and
/// wakes a kernel task waiting on it. `syscall::signal_notification` calls
/// this when no thread is blocked in `wait` to take the bits instead.
///
/// `object` must name a notification.
pub fn notification_signal(object: ObjectId, badge: Badge) {
    if object.kind() != ObjectKind::Notification {
        return;
    }
    // SAFETY: the kind was checked above, the object lives as long as the
    // kernel (a static untyped region), and on the single-CPU syscall or task
    // path no aliasing exclusive reference exists.
    let notification = unsafe { object.as_notification() };
    let to_wake = notification.inner.lock().signal(badge);
    if let Some(waker) = to_wake {
        waker.wake();
    }
}

/// Collects and clears the pending bits of the notification `object`, if any
/// are pending.
pub fn notification_poll(object: ObjectId) -> Option<Badge> {
    if object.kind() != ObjectKind::Notification {
        return None;
    }
    // SAFETY: as in notification_signal.
    let notification = unsafe { object.as_notification() };
    match notification.inner.lock().try_collect() {
        notification::PollOutcome::Collected(badge) => Some(badge),
        notification::PollOutcome::Empty => None,
    }
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
/// Every capability in a subtree names the object the root names (a
/// derivation keeps the object, the `derivation_keeps_the_object` proof), so
/// that one object is acted on, after the revoke has bumped the generations:
/// a woken task re-validating its capability genuinely sees it gone.
pub fn revoke_and_wake(space: &mut KernelCapSpace, cap_ref: CapRef) -> usize {
    let Some(object) = space.lookup(cap_ref).map(|cap| cap.object) else {
        return 0;
    };
    // revoke: removes the capability entries and bumps their generations, so any
    // outstanding ref (including one a blocked future holds) is now stale. a
    // registered space revokes across every registered space, so copies in other
    // threads' CNodes go too; an unregistered one (id 0) stays local.
    let is_local = space.id() == SpaceId(0);
    let removed = if is_local {
        space.revoke(cap_ref)
    } else {
        let root = CapLink { space: space.id(), cap: cap_ref };
        // SAFETY: single-CPU with interrupts disabled on every revoke path, and
        // `space` is not used again below, so the registry's references are the
        // only live ones into the registered spaces.
        unsafe { with_registered_spaces(|spaces| revoke_across(spaces, root)) }
    };
    // an unregistered space is not in the registry, so it is searched on its own
    // for capabilities that survived the revoke.
    let local = if is_local { Some(&*space) } else { None };
    capability_gone(object, local, true);
    // a thread, CNode or VSpace that went can leave CNodes nothing reaches. only
    // a registered space's revoke collects them: an unregistered space can name
    // a CNode the registry does not see.
    if !is_local && matches!(object.kind(), ObjectKind::Tcb | ObjectKind::CNode | ObjectKind::VSpace) {
        // SAFETY: single-CPU revoke path, and `space` is not used again.
        unsafe { collect_cnodes() };
    }
    removed
}

/// Acts on `object` once capabilities to it are gone, `revoked` by a revoke or
/// dropped with a released `CNode` (see [`collect_cnodes`]).
///
/// A revoke always wakes what waits on the object, and takes its mappings and
/// a reply's caller with it; a drop leaves an object another capability still
/// names as it is. Once no capability to the object is left anywhere (`local`
/// is an unregistered space to search as well), the blocked waits and the
/// threads that depend on it end.
fn capability_gone(object: ObjectId, local: Option<&KernelCapSpace>, revoked: bool) {
    let acted_on = matches!(
        object.kind(),
        ObjectKind::Endpoint
            | ObjectKind::Notification
            | ObjectKind::Reply
            | ObjectKind::Frame
            | ObjectKind::PageTable
            | ObjectKind::Tcb
            | ObjectKind::CNode
            | ObjectKind::VSpace
    );
    if !acted_on {
        return;
    }
    // SAFETY: single-CPU revoke path; the spaces are only read.
    let named = unsafe { still_named(object, local) };
    if named && !revoked {
        return;
    }
    // wake phase: take and fire each parked waiter, AFTER releasing the object
    // lock (the wake transport is lock-free, but keep the wake off the locked
    // path as the cap_send/cap_recv primitives do). a woken future re-polls,
    // sees the stale cap, and returns InvalidCap.
    match object.kind() {
        ObjectKind::Endpoint => {
            // SAFETY: object.kind == Endpoint (matched), the object outlives the
            // kernel (static untyped region), single-CPU interrupts-disabled
            // context so no aliasing live &mut exists.
            let endpoint = unsafe { object.as_endpoint() };
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
            // threads parked in blocking calls hold no capability to find
            // stale: once none is left anywhere, their waits end here.
            if !named {
                crate::syscall::cancel_waits_on(object.phys_addr());
            }
        }
        ObjectKind::Notification => {
            // SAFETY: object.kind == Notification (matched), the object outlives
            // the kernel, single-CPU interrupts-disabled context so no aliasing
            // live &mut exists.
            let notification = unsafe { object.as_notification() };
            let waiter = notification.inner.lock().clear_parked();
            if let Some(waker) = waiter {
                waker.wake();
            }
            // as for an endpoint: threads blocked in wait end with it.
            if !named {
                crate::syscall::cancel_waits_on(object.phys_addr());
            }
        }
        ObjectKind::Reply => {
            // a caller blocked on a revoked reply could never be answered:
            // fail its call instead of leaving it parked forever.
            let caller = reply_object(object).and_then(|r| r.inner.lock().cancel());
            if let Some(tid) = caller.and_then(crate::sched::thread_of) {
                crate::syscall::abort_call(tid);
            }
        }
        ObjectKind::Frame => {
            // a thread must not keep using a buffer it no longer has the
            // capability for: unregister it everywhere.
            crate::syscall::forget_ipc_buffer(object.phys_addr());
            // and the frame must stop being reachable through its mapping.
            let _ = crate::mapping::unmap_object(object.phys_addr());
        }
        ObjectKind::PageTable => {
            // unmap the table and everything mapped beneath it.
            let _ = crate::mapping::unmap_object(object.phys_addr());
        }
        // a thread stops for good once its TCB, or the CNode or VSpace it runs
        // in, has no capability left anywhere; revoking only a copy leaves it
        // running.
        ObjectKind::Tcb | ObjectKind::CNode | ObjectKind::VSpace if !named => {
            crate::syscall::retire_threads(|tcb| runs_on(tcb, object));
        }
        _ => {}
    }
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
                RecvOutcome::Took(message, _, waker) => (message, waker),
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
