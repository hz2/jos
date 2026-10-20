//! IPC syscalls: send and receive, blocking rendezvous, call and reply, and
//! the IPC buffer that carries message words and capabilities.

use super::*;

/// Maps an IpcError from the cap layer to the userspace-visible errno. The cap
/// layer distinguishes more cases than userspace needs, so several collapse.
fn ipc_errno(e: IpcError) -> u64 {
    let code = match e {
        IpcError::InvalidCap => IpcSyscallError::BadCap,
        IpcError::InsufficientRights => IpcSyscallError::Denied,
        IpcError::NotAnEndpoint => IpcSyscallError::NotEndpoint,
        IpcError::EndpointBusy | IpcError::EndpointEmpty => IpcSyscallError::WouldBlock,
    };
    code as u64
}

/// ipc_send: resolve cap_slot in the current CSpace per call, then send a
/// one-word message. The per-call resolution (ref_at reconstructs the
/// generation-checked CapRef) is what makes a revoked capability fail here
/// rather than the borrow being held across the block.
pub(super) fn sys_ipc_send(cap_slot: u64, word: u64) -> u64 {
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
    let message = match compose_with_cap(cap_slot, word) {
        Ok(message) => message,
        Err(e) => return e as u64,
    };
    // a receiver parked in a blocking receive takes the message directly; it
    // would never look in the endpoint's slot again.
    if let Ok((endpoint_addr, badge)) = resolve_endpoint_slot(cap_slot, Rights::WRITE)
        && hand_to_parked_receiver(endpoint_addr, &message, badge)
    {
        return 0;
    }
    match cap_send(space, cap_ref, message) {
        Ok(()) => 0,
        Err(e) => ipc_errno(e),
    }
}

/// ipc_recv: resolve cap_slot per call, then receive a one-word message. Returns
/// the message's first word on success, or (errno | IPC_ERR_FLAG) on failure so
/// userspace can distinguish a real word from an error. The sender badge goes
/// back in rdx.
pub(super) fn sys_ipc_recv(cap_slot: u64) -> SyscallRet {
    let bad_cap = (IpcSyscallError::BadCap as u64 | IPC_ERR_FLAG).into();
    let Some(space) = current_cspace() else {
        return bad_cap;
    };
    let Ok(slot) = usize::try_from(cap_slot) else {
        return bad_cap;
    };
    let Some(cap_ref) = space.ref_at(slot) else {
        return bad_cap;
    };
    match cap_recv_badged(space, cap_ref) {
        Ok((message, badge)) => return SyscallRet { rax: deliver_to(&message, current_tcb()), rdx: badge.0 },
        Err(IpcError::EndpointEmpty) => {}
        Err(e) => return (ipc_errno(e) | IPC_ERR_FLAG).into(),
    }
    // the slot is empty: a sender parked in a blocking send goes next.
    if let Ok((endpoint_addr, _)) = resolve_endpoint_slot(cap_slot, Rights::READ)
        && let Some((message, badge)) = take_from_parked_sender(endpoint_addr, None)
    {
        return SyscallRet { rax: deliver_to(&message, current_tcb()), rdx: badge };
    }
    (IpcSyscallError::WouldBlock as u64 | IPC_ERR_FLAG).into()
}

/// Takes the message deposited in the slot of the endpoint at `cap_slot`, if
/// the capability allows the receive and there is one.
fn take_deposited(cap_slot: u64) -> Option<(Message, u64)> {
    let space = current_cspace()?;
    let cap_ref = usize::try_from(cap_slot).ok().and_then(|slot| space.ref_at(slot))?;
    cap_recv_badged(space, cap_ref).ok().map(|(message, badge)| (message, badge.0))
}

// --- blocking IPC -----------------------------------------------------------

use spin::Mutex;

const MAX_THREADS: usize = crate::sched::MAX_THREADS;

/// A parked thread waiting to send on a specific endpoint.
#[derive(Clone, Copy)]
struct BlockedSend {
    /// Endpoint identity (the `phys_addr` of its `ObjectId`).
    endpoint_addr: u64,
    /// Scheduler id of the parked sender.
    thread_id: usize,
    /// The message: word 0 from the register, words 1 to 3 from the sender's
    /// IPC buffer, captured when it parked.
    message: Message,
    /// Badge of the sending capability, delivered to the receiver in `rdx`.
    badge: u64,
    /// The sender is in a `Call` and waits for an answer through a reply object.
    call: bool,
    /// When it parked ([`PARK_SEQ`]), so parked senders are taken oldest first.
    seq: u64,
}

/// A parked thread waiting to receive on a specific endpoint.
#[derive(Clone, Copy)]
struct BlockedRecv {
    /// Endpoint identity (the `phys_addr` of its `ObjectId`).
    endpoint_addr: u64,
    /// Scheduler id of the parked receiver.
    thread_id: usize,
    /// For `RecvReply`: the reply object a `Call` binds to its caller.
    reply: Option<ObjectId>,
    /// When it parked ([`PARK_SEQ`]), so parked receivers are served oldest
    /// first.
    seq: u64,
}

/// Counts parks, so the blocking tables (whose entries are reused in any
/// order) can still hand out the oldest waiter first.
static PARK_SEQ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Returns the next park sequence number.
fn next_seq() -> u64 {
    PARK_SEQ.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

static BLOCKED_SENDS: Mutex<[Option<BlockedSend>; MAX_THREADS]> =
    Mutex::new([None; MAX_THREADS]);
static BLOCKED_RECVS: Mutex<[Option<BlockedRecv>; MAX_THREADS]> =
    Mutex::new([None; MAX_THREADS]);

/// Saves the current thread's user-space context into its Tcb so it can be
/// resumed via iretq when woken. `wake_rax` is placed in rax (the syscall
/// return value the thread will see when it resumes). Called from a blocking
/// syscall handler before setting need_yield.
fn save_blocking_context(wake_rax: u64) {
    // SAFETY: ring-0, interrupts disabled on syscall path; single access.
    unsafe {
        let local = &*cpu_local::cpu_local_ptr();
        let tcb = local.current_tcb;
        if tcb.is_null() {
            return;
        }
        let sel = crate::gdt::selectors();
        (*tcb).context = crate::cap::SavedContext {
            rip: local.saved_user_rip,
            rsp: local.user_rsp_scratch,
            rflags: local.saved_user_rflags,
            cs: u64::from(sel.user_code.0),
            ss: u64::from(sel.user_data.0),
            rax: wake_rax,
            rbx: local.saved_user_rbx,
            rbp: local.saved_user_rbp,
            // rcx/r11 are clobbered by SYSCALL; zero is safe (iretq restores
            // rip/rflags from the frame, not from rcx/r11).
            rcx: 0,
            r11: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r12: local.saved_user_r12,
            r13: local.saved_user_r13,
            r14: local.saved_user_r14,
            r15: local.saved_user_r15,
        };
    }
}

/// ipc_send_blocking: try to rendezvous with a waiting receiver; if none is
/// present, park this thread in the BLOCKED_SENDS table and signal the syscall
/// stub to yield via need_yield.
pub(super) fn sys_ipc_send_blocking(cap_slot: u64, word: u64) -> u64 {
    let Some(space) = current_cspace() else {
        return IpcSyscallError::BadCap as u64;
    };
    let Ok(slot) = usize::try_from(cap_slot) else {
        return IpcSyscallError::BadCap as u64;
    };
    let Some(cap_ref) = space.ref_at(slot) else {
        return IpcSyscallError::BadCap as u64;
    };
    let Some(cap) = space.lookup(cap_ref) else {
        return IpcSyscallError::BadCap as u64;
    };
    if cap.object.kind() != ObjectKind::Endpoint {
        return IpcSyscallError::NotEndpoint as u64;
    }
    if !cap.rights.contains(Rights::WRITE) {
        return IpcSyscallError::Denied as u64;
    }
    let endpoint_addr = cap.object.phys_addr();
    let badge = cap.badge.0;
    let message = match compose_with_cap(cap_slot, word) {
        Ok(message) => message,
        Err(e) => return e as u64,
    };

    // a parked receiver takes the message directly; otherwise it goes into the
    // endpoint's slot if that is free, and only a full slot makes us wait.
    if hand_to_parked_receiver(endpoint_addr, &message, badge) {
        return 0;
    }
    match cap_send(space, cap_ref, message) {
        Ok(()) => return 0,
        Err(IpcError::EndpointBusy) => {}
        Err(e) => return ipc_errno(e),
    }

    // still would-block: park ourselves.
    let cur = crate::sched::current_thread_id();
    if cur == usize::MAX {
        return IpcSyscallError::WouldBlock as u64;
    }
    {
        let mut sends = BLOCKED_SENDS.lock();
        if let Some(entry) = sends.iter_mut().find(|e| e.is_none()) {
            *entry = Some(BlockedSend {
                endpoint_addr,
                thread_id: cur,
                message,
                badge,
                call: false,
                seq: next_seq(),
            });
        } else {
            return IpcSyscallError::WouldBlock as u64; // table full
        }
    }
    save_blocking_context(0); // rax = 0 when woken (send returned success)
    // SAFETY: ring-0, single-CPU; need_yield is read by the syscall stub after
    // dispatch_syscall returns.
    unsafe {
        (*cpu_local::cpu_local_ptr()).need_yield = 1;
    }
    0 // ignored: the stub yields instead of sysretq'ing
}

/// Blocking receive with no reply object; see [`recv_blocking`].
pub(super) fn sys_ipc_recv_blocking(cap_slot: u64) -> SyscallRet {
    recv_blocking(cap_slot, None)
}

/// The shared blocking receive behind [`Syscall::IpcRecvBlocking`] and
/// [`Syscall::RecvReply`].
///
/// Rendezvous with a sender already parked on the endpoint, or take a message
/// already deposited; otherwise park this thread in `BLOCKED_RECVS` and yield.
/// `reply` is the reply object a `RecvReply` named: a `Call` that meets it binds
/// it to the caller, and a `Call` that meets a plain receive fails with
/// [`IpcSyscallError::NoReply`] rather than waiting forever.
fn recv_blocking(cap_slot: u64, reply: Option<ObjectId>) -> SyscallRet {
    let err = |e: IpcSyscallError| SyscallRet::from(e as u64 | IPC_ERR_FLAG);
    let (endpoint_addr, _) = match resolve_endpoint_slot(cap_slot, Rights::READ) {
        Ok(found) => found,
        Err(e) => return err(e),
    };

    // a message deposited in the slot is the oldest one: a sender parks only
    // once the slot is full. only plain sends deposit; a Call always parks.
    if let Some((message, badge)) = take_deposited(cap_slot) {
        return SyscallRet { rax: deliver_to(&message, current_tcb()), rdx: badge };
    }
    // then the oldest sender parked on the endpoint rendezvouses now.
    if let Some((message, badge)) = take_from_parked_sender(endpoint_addr, reply) {
        return SyscallRet { rax: deliver_to(&message, current_tcb()), rdx: badge };
    }

    // park ourselves.
    let cur = crate::sched::current_thread_id();
    if cur == usize::MAX {
        return err(IpcSyscallError::WouldBlock);
    }
    {
        let mut recvs = BLOCKED_RECVS.lock();
        let Some(entry) = recvs.iter_mut().find(|e| e.is_none()) else {
            return err(IpcSyscallError::WouldBlock);
        };
        *entry = Some(BlockedRecv { endpoint_addr, thread_id: cur, reply, seq: next_seq() });
    }
    // the sender overwrites rax/rdx with the word and badge before readying us.
    park_current();
    0.into() // ignored: the stub yields instead of sysretq'ing
}

/// Hands `message` straight to a thread parked in a blocking receive on the
/// endpoint at `endpoint_addr`, if there is one: its buffer gets the words,
/// its saved `rax` word 0 and `rdx` the badge. Returns whether one took it.
pub(super) fn hand_to_parked_receiver(endpoint_addr: u64, message: &Message, badge: u64) -> bool {
    let waiting = {
        let mut recvs = BLOCKED_RECVS.lock();
        // the oldest receiver parked on the endpoint is served first.
        recvs
            .iter_mut()
            .filter(|e| e.is_some_and(|r| r.endpoint_addr == endpoint_addr))
            .min_by_key(|e| e.map_or(u64::MAX, |r| r.seq))
            .and_then(Option::take)
    };
    let Some(recv) = waiting else {
        return false;
    };
    resume_with(recv.thread_id, message, badge);
    true
}

/// Takes the message of a thread parked in a blocking send on the endpoint at
/// `endpoint_addr`, if there is one, and returns it with its badge. A plain
/// sender is woken with success; a caller stays parked with `reply` bound to
/// it, or, with no reply object to answer through, is failed with
/// [`IpcSyscallError::NoReply`].
pub(super) fn take_from_parked_sender(endpoint_addr: u64, reply: Option<ObjectId>) -> Option<(Message, u64)> {
    let send = {
        let mut sends = BLOCKED_SENDS.lock();
        // the oldest sender parked on the endpoint goes first.
        sends
            .iter_mut()
            .filter(|e| e.is_some_and(|s| s.endpoint_addr == endpoint_addr))
            .min_by_key(|e| e.map_or(u64::MAX, |s| s.seq))
            .and_then(Option::take)
    }?;
    if send.call {
        let bound = reply
            .and_then(cap::reply_object)
            .is_some_and(|r| r.inner.lock().bind(crate::sched::token(send.thread_id)).is_ok());
        if !bound {
            abort_call(send.thread_id);
        }
    } else {
        resume(send.thread_id, 0, 0);
    }
    Some((send.message, send.badge))
}

/// Resolves `cap_slot` in the current `CSpace` to an endpoint the capability
/// grants `right` on, returning the endpoint identity and the capability's badge.
///
/// # Errors
///
/// [`IpcSyscallError::BadCap`], [`NotEndpoint`](IpcSyscallError::NotEndpoint),
/// or [`Denied`](IpcSyscallError::Denied).
fn resolve_endpoint_slot(cap_slot: u64, right: Rights) -> Result<(u64, u64), IpcSyscallError> {
    let cap = current_cap(cap_slot).ok_or(IpcSyscallError::BadCap)?;
    if cap.object.kind() != ObjectKind::Endpoint {
        return Err(IpcSyscallError::NotEndpoint);
    }
    if !cap.rights.contains(right) {
        return Err(IpcSyscallError::Denied);
    }
    Ok((cap.object.phys_addr(), cap.badge.0))
}

/// Resolves `cap_slot` to a reply object the capability grants `WRITE` on.
///
/// # Errors
///
/// [`IpcSyscallError::BadCap`], [`NotReply`](IpcSyscallError::NotReply), or
/// [`Denied`](IpcSyscallError::Denied).
fn resolve_reply_slot(cap_slot: u64) -> Result<ObjectId, IpcSyscallError> {
    let cap = current_cap(cap_slot).ok_or(IpcSyscallError::BadCap)?;
    if cap.object.kind() != ObjectKind::Reply {
        return Err(IpcSyscallError::NotReply);
    }
    if !cap.rights.contains(Rights::WRITE) {
        return Err(IpcSyscallError::Denied);
    }
    Ok(cap.object)
}

/// Makes a blocked thread ready, resuming it with `rax` and `rdx` as its
/// syscall return registers.
fn resume(thread_id: usize, rax: u64, rdx: u64) {
    // SAFETY: thread_id came from register_thread, and THREAD_TABLE entries
    // live for the kernel lifetime; single-CPU with interrupts disabled on the
    // syscall and revoke paths, so nothing else touches the saved context.
    unsafe {
        let tcb = crate::sched::thread_table_entry(thread_id);
        if !tcb.is_null() {
            (*tcb).context.rax = rax;
            (*tcb).context.rdx = rdx;
        }
    }
    crate::sched::mark_ready(thread_id);
}

/// Returns the current thread's TCB, or null before any thread runs.
fn current_tcb() -> *mut Tcb {
    // SAFETY: the per-CPU block is read on the single-CPU syscall path.
    unsafe { (*cpu_local::cpu_local_ptr()).current_tcb }
}

/// Returns the IPC buffer registered by the current thread, if any.
fn current_buffer() -> Option<*mut IpcBuffer> {
    let tcb = current_tcb();
    if tcb.is_null() {
        return None;
    }
    // SAFETY: switch_to installed a live Tcb as current; single-CPU syscall path.
    unsafe { (*tcb).ipc_buffer_ptr() }
}

/// Builds the message the current thread sends: `word0` from the register,
/// words 1 to 3 from its IPC buffer (zeros if it has none).
fn compose_current(word0: u64) -> Message {
    let buffer = current_buffer();
    // SAFETY: the pointer is a registered, page-aligned, identity-mapped buffer
    // frame; the shared reference lives only for this call, on the single-CPU
    // syscall path, so no write to the frame overlaps it.
    ipc_buffer::compose(word0, buffer.map(|p| unsafe { &*p }))
}

/// Builds the message the current thread sends on the endpoint at `ep_slot`:
/// [`compose_current`], plus the capability its IPC buffer names in
/// `send_cap`, if any. Replies never carry one.
///
/// # Errors
///
/// [`IpcSyscallError::Denied`] if a capability is named but the endpoint
/// capability lacks `GRANT`, [`BadCap`](IpcSyscallError::BadCap) if the named
/// slot is empty, and [`NotRegistered`](IpcSyscallError::NotRegistered) if the
/// sender's space is not registered, so no copy could link back to it.
fn compose_with_cap(ep_slot: u64, word0: u64) -> Result<Message, IpcSyscallError> {
    let mut message = compose_current(word0);
    // SAFETY: as in compose_current; the reference lives only for this read.
    let Some(slot) = current_buffer().and_then(|p| unsafe { (*p).send_slot() }) else {
        return Ok(message);
    };
    let endpoint = current_cap(ep_slot).ok_or(IpcSyscallError::BadCap)?;
    if !endpoint.rights.contains(Rights::GRANT) {
        return Err(IpcSyscallError::Denied);
    }
    let space = current_cspace().ok_or(IpcSyscallError::BadCap)?;
    let cap = space.ref_at(slot).ok_or(IpcSyscallError::BadCap)?;
    if space.id() == SpaceId(0) {
        return Err(IpcSyscallError::NotRegistered);
    }
    message.cap = Some(CapLink { space: space.id(), cap });
    Ok(message)
}

/// Delivers `message` to the thread `tcb`: its buffer, if any, gets the words,
/// and a capability the message carries lands in the buffer's `recv_slot`, with
/// `caps_received` reporting whether it did. Returns word 0.
fn deliver_to(message: &Message, tcb: *mut Tcb) -> u64 {
    if tcb.is_null() {
        return message.words[0];
    }
    // SAFETY: a non-null tcb is the current thread or a thread table entry, both
    // live; read on the single-CPU syscall path.
    let (buffer, space) = unsafe { ((*tcb).ipc_buffer_ptr(), (*tcb).cspace_ptr) };
    // SAFETY: as in compose_current; the exclusive reference lives only for this
    // call, and the message was already copied out of any sender buffer.
    let word0 = ipc_buffer::deliver(message, buffer.map(|p| unsafe { &mut *p }));
    if let (Some(buf), Some(source)) = (buffer, message.cap) {
        // SAFETY: as above; the reference from deliver has ended.
        let slot = unsafe { (*buf).receive_slot() };
        // SAFETY: the receiver's space lives as long as its thread; single-CPU
        // syscall path, and no reference into it is held across this call.
        let arrived = slot.is_some_and(|s| !space.is_null() && unsafe { cap::transfer_cap(source, space, s) });
        // SAFETY: as above.
        unsafe { (*buf).caps_received = u64::from(arrived) };
    }
    word0
}

/// Resumes a blocked thread with a delivered message: its buffer gets the
/// words, its saved `rax` word 0, and its saved `rdx` the given value. A
/// thread parked by a fault is answered differently: it resumes at the
/// faulting instruction with every register as it was.
fn resume_with(thread_id: usize, message: &Message, rdx: u64) {
    // SAFETY: thread_id came from register_thread, and THREAD_TABLE entries live
    // for the kernel lifetime; deliver_to handles a null entry.
    let tcb = unsafe { crate::sched::thread_table_entry(thread_id) };
    // SAFETY: a non-null entry is a live TCB; single-CPU with interrupts off.
    if !tcb.is_null() && unsafe { (*tcb).state } == TcbState::Faulted {
        // SAFETY: as above.
        unsafe { (*tcb).state = TcbState::Running };
        crate::sched::mark_ready(thread_id);
        return;
    }
    let word0 = deliver_to(message, tcb);
    resume(thread_id, word0, rdx);
}

/// Fails a thread blocked in [`Syscall::Call`] that can never be answered (its
/// reply object was revoked), resuming it with [`IpcSyscallError::NoReply`].
/// A thread parked by a fault has no call to fail: it is stopped instead.
pub fn abort_call(thread_id: usize) {
    // SAFETY: thread_id came from register_thread; a null entry is skipped.
    let tcb = unsafe { crate::sched::thread_table_entry(thread_id) };
    // SAFETY: a non-null entry is a live TCB; single-CPU with interrupts off.
    if !tcb.is_null() && unsafe { (*tcb).state } == TcbState::Faulted {
        retire_threads(|t| core::ptr::eq(t, tcb));
        return;
    }
    resume(thread_id, IpcSyscallError::NoReply as u64 | IPC_ERR_FLAG, 0);
}

/// Returns the endpoint a thread's faults go to, and the badge of the
/// capability naming it: the capability in its fault slot, looked up in its
/// own capability space now, so a revoked capability names nothing. It must
/// be an endpoint capability with `WRITE`.
pub fn fault_endpoint(tcb: &Tcb) -> Option<(u64, u64)> {
    let slot = usize::try_from(tcb.fault_slot.checked_sub(1)?).ok()?;
    if tcb.cspace_ptr.is_null() {
        return None;
    }
    // SAFETY: a thread's capability space lives as long as the thread, and
    // nothing else touches it while interrupts are off.
    let space = unsafe { &*tcb.cspace_ptr };
    let cap = space.lookup(space.ref_at(slot)?)?;
    (cap.object.kind() == ObjectKind::Endpoint && cap.rights.contains(Rights::WRITE))
        .then(|| (cap.object.phys_addr(), cap.badge.0))
}

/// Delivers a fault as a call from thread `thread_id` on the endpoint at
/// `endpoint_addr`: handed to a receiver parked with a reply object, or
/// parked until one arrives. Returns `false` if nothing could ever answer it
/// (the parked receiver has no reply object), so the caller stops the thread.
pub fn deliver_fault(thread_id: usize, endpoint_addr: u64, badge: u64, message: &Message) -> bool {
    let waiting = {
        let mut recvs = BLOCKED_RECVS.lock();
        recvs
            .iter_mut()
            .filter(|e| e.is_some_and(|r| r.endpoint_addr == endpoint_addr))
            .min_by_key(|e| e.map_or(u64::MAX, |r| r.seq))
            .and_then(Option::take)
    };
    if let Some(recv) = waiting {
        let bound = recv
            .reply
            .and_then(cap::reply_object)
            .is_some_and(|r| r.inner.lock().bind(crate::sched::token(thread_id)).is_ok());
        resume_with(recv.thread_id, message, badge);
        return bound;
    }
    let mut sends = BLOCKED_SENDS.lock();
    let Some(entry) = sends.iter_mut().find(|e| e.is_none()) else {
        return false;
    };
    *entry = Some(BlockedSend { endpoint_addr, thread_id, message: *message, badge, call: true, seq: next_seq() });
    true
}

/// Stops every thread `doomed` picks, for good: it leaves the scheduler and any
/// IPC wait, so nothing resumes it. If the current thread is among them, the
/// syscall stub idles instead of returning to it.
pub fn retire_threads(mut doomed: impl FnMut(&Tcb) -> bool) {
    let mut ids = [usize::MAX; MAX_THREADS];
    let mut count = 0;
    // SAFETY: the revoke paths run single-CPU with interrupts disabled, and the
    // closure only reads each TCB.
    unsafe {
        crate::sched::for_each_thread(|id, tcb| {
            if count < MAX_THREADS && doomed(&*tcb) {
                ids[count] = id;
                count += 1;
            }
        });
    }
    for &id in &ids[..count] {
        // a parked sender or receiver must not be handed a message later.
        for entry in BLOCKED_SENDS.lock().iter_mut() {
            if entry.is_some_and(|s| s.thread_id == id) {
                *entry = None;
            }
        }
        for entry in BLOCKED_RECVS.lock().iter_mut() {
            if entry.is_some_and(|r| r.thread_id == id) {
                *entry = None;
            }
        }
        // SAFETY: id came from for_each_thread, so its entry is a live TCB;
        // single-CPU with interrupts disabled, as retire_thread requires.
        unsafe {
            (*crate::sched::thread_table_entry(id)).state = TcbState::Retired;
            if crate::sched::retire_thread(id) {
                (*cpu_local::cpu_local_ptr()).need_yield = 1;
            }
        }
    }
}

/// Parks the current thread: saves its user context for a later [`resume`] and
/// tells the syscall stub to yield instead of returning to user mode.
fn park_current() {
    save_blocking_context(0);
    // SAFETY: ring-0, single-CPU; need_yield is read by the syscall stub after
    // dispatch_syscall returns and before the sysretq decision.
    unsafe {
        (*cpu_local::cpu_local_ptr()).need_yield = 1;
    }
}

/// Implements [`Syscall::Call`]: sends `word` and blocks until a server answers
/// through a reply object.
///
/// If a server is already parked in `RecvReply`, the word is handed over
/// directly and its reply object is bound to the caller; otherwise the caller
/// parks as a call-flagged sender for the next receive to find.
pub(super) fn sys_call(cap_slot: u64, word: u64) -> u64 {
    let err = |e: IpcSyscallError| e as u64 | IPC_ERR_FLAG;
    let (endpoint_addr, badge) = match resolve_endpoint_slot(cap_slot, Rights::WRITE) {
        Ok(found) => found,
        Err(e) => return err(e),
    };
    let message = match compose_with_cap(cap_slot, word) {
        Ok(message) => message,
        Err(e) => return err(e),
    };
    let cur = crate::sched::current_thread_id();
    if cur == usize::MAX {
        return err(IpcSyscallError::WouldBlock);
    }

    let waiting = {
        let mut recvs = BLOCKED_RECVS.lock();
        recvs
            .iter_mut()
            .find(|e| e.is_some_and(|r| r.endpoint_addr == endpoint_addr))
            .and_then(Option::take)
    };
    if let Some(recv) = waiting {
        let bound = recv
            .reply
            .and_then(cap::reply_object)
            .is_some_and(|r| r.inner.lock().bind(crate::sched::token(cur)).is_ok());
        resume_with(recv.thread_id, &message, badge);
        if !bound {
            // a plain receive took the message but cannot answer it.
            return err(IpcSyscallError::NoReply);
        }
        // the Reply syscall overwrites our rax with the answer.
        park_current();
        return 0; // ignored: the stub yields instead of sysretq'ing
    }

    {
        let mut sends = BLOCKED_SENDS.lock();
        let Some(entry) = sends.iter_mut().find(|e| e.is_none()) else {
            return err(IpcSyscallError::WouldBlock);
        };
        *entry = Some(BlockedSend { endpoint_addr, thread_id: cur, message, badge, call: true, seq: next_seq() });
    }
    park_current();
    0 // ignored
}

/// Implements [`Syscall::RecvReply`]: a blocking receive that names an idle reply
/// object, so a `Call` that arrives can be answered later.
pub(super) fn sys_recv_reply(ep_slot: u64, reply_slot: u64) -> SyscallRet {
    let err = |e: IpcSyscallError| SyscallRet::from(e as u64 | IPC_ERR_FLAG);
    let reply = match resolve_reply_slot(reply_slot) {
        Ok(obj) => obj,
        Err(e) => return err(e),
    };
    if !cap::reply_object(reply).is_some_and(|r| r.inner.lock().is_idle()) {
        return err(IpcSyscallError::ReplyBusy);
    }
    recv_blocking(ep_slot, Some(reply))
}

/// Implements [`Syscall::ReplyRecv`]: answers the bound caller, if any, then
/// receives the next message through [`sys_recv_reply`].
pub(super) fn sys_reply_recv(ep_slot: u64, reply_slot: u64, word: u64) -> SyscallRet {
    let reply = match resolve_reply_slot(reply_slot) {
        Ok(obj) => obj,
        Err(e) => return SyscallRet::from(e as u64 | IPC_ERR_FLAG),
    };
    // compose before receiving: the receive overwrites the buffer.
    let message = compose_current(word);
    let answered = cap::reply_object(reply).and_then(|r| r.inner.lock().answer(message).ok());
    // a caller that retired since it was bound gets nothing.
    if let Some(caller) = answered.and_then(crate::sched::thread_of) {
        resume_with(caller, &message, 0);
    }
    sys_recv_reply(ep_slot, reply_slot)
}

/// Implements [`Syscall::SetIpcBuffer`]: registers the frame at `frame_slot` as
/// the calling thread's IPC buffer.
pub(super) fn sys_set_ipc_buffer(frame_slot: u64) -> u64 {
    let Some(cap) = current_cap(frame_slot) else {
        return IpcSyscallError::BadCap as u64;
    };
    if cap.object.kind() != ObjectKind::Frame {
        return IpcSyscallError::NotFrame as u64;
    }
    if !cap.rights.contains(Rights::READ_WRITE) {
        return IpcSyscallError::Denied as u64;
    }
    // SAFETY: the per-CPU block is read on the single-CPU syscall path.
    let tcb = unsafe { (*cpu_local::cpu_local_ptr()).current_tcb };
    if tcb.is_null() {
        return IpcSyscallError::NoThread as u64;
    }
    // SAFETY: switch_to installed a live Tcb as current; single-CPU syscall
    // path, so nothing else touches it while we update one field.
    unsafe {
        (*tcb).ipc_buffer = cap.object.phys_addr();
    }
    0
}

/// Unregisters the IPC buffer at physical address `frame` from every thread
/// using it. Called when a Frame capability is revoked, so no thread keeps a
/// buffer it no longer has the right to.
pub fn forget_ipc_buffer(frame: u64) {
    for thread_id in 0..crate::sched::MAX_THREADS {
        // SAFETY: THREAD_TABLE entries live for the kernel lifetime (null when
        // unused); single-CPU with interrupts disabled on the revoke path.
        unsafe {
            let tcb = crate::sched::thread_table_entry(thread_id);
            if !tcb.is_null() && (*tcb).ipc_buffer == frame {
                (*tcb).ipc_buffer = 0;
            }
        }
    }
}

/// Implements [`Syscall::Reply`]: answers the caller bound to the reply object,
/// exactly once.
pub(super) fn sys_reply(reply_slot: u64, word: u64) -> u64 {
    let reply = match resolve_reply_slot(reply_slot) {
        Ok(obj) => obj,
        Err(e) => return e as u64,
    };
    let message = compose_current(word);
    let answered = cap::reply_object(reply).map(|r| r.inner.lock().answer(message));
    match answered {
        Some(Ok(caller)) => {
            // a caller that retired since it was bound gets nothing.
            if let Some(caller) = crate::sched::thread_of(caller) {
                resume_with(caller, &message, 0);
            }
            0
        }
        _ => IpcSyscallError::NoCaller as u64,
    }
}

