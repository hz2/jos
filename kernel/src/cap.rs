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

use jos_core::cap_rights::Rights;
use jos_core::cap_space::CapSpace;
use jos_core::cap_table::CapRef;
use jos_core::placement::{place, PlaceError};
use jos_core::untyped::{ObjectType, ENDPOINT_ALIGN, ENDPOINT_SIZE};
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
}

// --------------------------------------------------------------------------
// Endpoint object
// --------------------------------------------------------------------------

/// The mutable state of a synchronous IPC endpoint, behind the endpoint's lock.
#[derive(Debug)]
pub struct EndpointInner {
    /// Current rendezvous state.
    pub state: EndpointState,
    /// The parked message when `state == SendBlocked`.
    pub message: Option<Message>,
}

/// Endpoint rendezvous state (seL4-style synchronous endpoint).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointState {
    /// No sender or receiver is waiting.
    Idle,
    /// A sender has parked a message, waiting for a receiver.
    SendBlocked,
}

/// A small inline IPC message. No IPC buffer / pages yet: a tag plus four data
/// words, mirroring seL4's short register-passed messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message {
    /// Message tag / method label.
    pub label: u64,
    /// Up to four inline data words.
    pub words: [u64; 4],
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
                state: EndpointState::Idle,
                message: None,
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

    /// Carves a fresh [`Endpoint`] out of this region and returns its handle.
    ///
    /// Uses the Miri-checked `jos_core::placement::place` to write the object,
    /// then captures its address as an [`ObjectId`]. Returns `None` if the
    /// region has no room for another endpoint.
    pub fn retype_endpoint(&mut self) -> Option<ObjectId> {
        match place(
            self.bytes,
            self.watermark,
            ObjectType::Endpoint,
            Endpoint::new(),
        ) {
            Ok((start, new_watermark)) => {
                self.watermark = new_watermark;
                self.has_children = true;
                // re-derive the object pointer from the region base (preserving
                // provenance) and expose its address for the Copy handle.
                // SAFETY: `start` is in bounds and `start + ENDPOINT_SIZE ==
                // new_watermark <= bytes.len()` (place returned it), so the add
                // stays within the region's provenance.
                let obj_ptr = unsafe { self.bytes.as_ptr().add(start) };
                let addr = obj_ptr.expose_provenance();
                Some(ObjectId {
                    addr,
                    kind: ObjectKind::Endpoint,
                })
            }
            // a full region is the only expected error; the others are
            // programming bugs (wrong layout / misaligned base) caught in tests.
            Err(PlaceError::DoesNotFit) => None,
            Err(e) => panic!("retype_endpoint: unexpected placement error: {e:?}"),
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

/// Sends `message` over the endpoint named by `cap_ref` in `space`.
///
/// Requires the capability to carry [`Rights::WRITE`]. Parks the message on the
/// endpoint (synchronous rendezvous; a real receiver hand-off / blocking comes
/// with the async executor in a later slice).
///
/// # Errors
///
/// See [`IpcError`].
pub fn cap_send(space: &KernelCapSpace, cap_ref: CapRef, message: Message) -> Result<(), IpcError> {
    let cap = space.lookup(cap_ref).ok_or(IpcError::InvalidCap)?;
    if !space.check(cap_ref, Rights::WRITE) {
        return Err(IpcError::InsufficientRights);
    }
    if cap.object.kind() != ObjectKind::Endpoint {
        return Err(IpcError::NotAnEndpoint);
    }
    // SAFETY: the capability is live (lookup succeeded) and names an endpoint
    // (checked above); single-CPU, interrupts-disabled context, so no aliasing.
    let endpoint = unsafe { cap.object.as_endpoint() };
    let mut inner = endpoint.inner.lock();
    if inner.state == EndpointState::SendBlocked {
        return Err(IpcError::EndpointBusy);
    }
    inner.message = Some(message);
    inner.state = EndpointState::SendBlocked;
    Ok(())
}

/// Receives a message from the endpoint named by `cap_ref` in `space`.
///
/// Requires the capability to carry [`Rights::READ`].
///
/// # Errors
///
/// See [`IpcError`].
pub fn cap_recv(space: &KernelCapSpace, cap_ref: CapRef) -> Result<Message, IpcError> {
    let cap = space.lookup(cap_ref).ok_or(IpcError::InvalidCap)?;
    if !space.check(cap_ref, Rights::READ) {
        return Err(IpcError::InsufficientRights);
    }
    if cap.object.kind() != ObjectKind::Endpoint {
        return Err(IpcError::NotAnEndpoint);
    }
    // SAFETY: as in cap_send: live endpoint capability, single-CPU context.
    let endpoint = unsafe { cap.object.as_endpoint() };
    let mut inner = endpoint.inner.lock();
    match inner.message.take() {
        Some(message) => {
            inner.state = EndpointState::Idle;
            Ok(message)
        }
        None => Err(IpcError::EndpointEmpty),
    }
}
