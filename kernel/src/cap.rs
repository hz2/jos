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
///
/// An endpoint owns its blocked peers (the seL4 model: a thread blocked on IPC
/// is queued on the endpoint, not spinning). jos has a single waiter slot per
/// direction for now (capacity-1 rendezvous); a full wait queue arrives when
/// userspace threads can contend an endpoint. A waiter is woken by storing the
/// counterpart message / clearing the slot and calling its [`Waker`].
#[derive(Debug)]
pub struct EndpointInner {
    /// Current rendezvous state.
    pub state: EndpointState,
    /// The parked message when `state == SendBlocked`.
    pub message: Option<Message>,
    /// Waker of a sender parked because the endpoint already held a message.
    /// Woken when a receiver drains the endpoint and frees the slot.
    send_waiter: Option<Waker>,
    /// Waker of a receiver parked because the endpoint had no message. Woken
    /// when a sender deposits a message.
    recv_waiter: Option<Waker>,
}

/// Endpoint rendezvous state (seL4-style synchronous endpoint).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointState {
    /// No message is parked. A receiver may be blocked (see `recv_waiter`),
    /// waiting for a sender.
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
    // try to deposit a message without blocking. the single locked primitive
    // both cap_send and the CapSend future build on, so the deposit/wake logic
    // lives in exactly one place and the take-or-park stays race-free (it all
    // happens under one lock acquisition by the caller).
    fn try_deposit(&mut self, message: Message) -> SendOutcome {
        if self.state == EndpointState::SendBlocked {
            return SendOutcome::Full;
        }
        self.message = Some(message);
        self.state = EndpointState::SendBlocked;
        SendOutcome::Deposited(self.recv_waiter.take())
    }

    // try to take the parked message without blocking.
    fn try_take(&mut self) -> RecvOutcome {
        match self.message.take() {
            Some(message) => {
                self.state = EndpointState::Idle;
                RecvOutcome::Took(message, self.send_waiter.take())
            }
            None => RecvOutcome::Empty,
        }
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
                    // endpoint full: register our waker so a receiver draining
                    // it wakes us, and yield. (lock drops at end of scope.)
                    inner.send_waiter = Some(context.waker().clone());
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
                    // endpoint empty: register our waker so a sender depositing
                    // a message wakes us, and yield.
                    inner.recv_waiter = Some(context.waker().clone());
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
