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
    if word & IPC_ERR_FLAG != 0 {
        return IpcSyscallError::BadWord as u64;
    }
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

use jos_core::abi::{NO_REPLY, NO_TIMEOUT};
use jos_core::clock::{Duration, Instant};
use jos_core::wait_table::{WaitTable, Waiter};
use spin::Mutex;

const MAX_THREADS: usize = crate::sched::MAX_THREADS;

/// What a parked sender needs to finish its send.
#[derive(Clone, Copy)]
struct Send {
    /// The message: word 0 from the register, words 1 to 3 from the sender's
    /// IPC buffer, captured when it parked.
    message: Message,
    /// Badge of the sending capability, delivered to the receiver in `rdx`.
    badge: u64,
    /// The sender is in a `Call` and waits for an answer through a reply object.
    call: bool,
}

/// Threads parked in a blocking send or call, by endpoint address. The table
/// serves them oldest first and lets each leave once (BLOCK-1).
static BLOCKED_SENDS: Mutex<WaitTable<Send, MAX_THREADS>> = Mutex::new(WaitTable::new());

/// Threads parked in a blocking receive, by endpoint address, each with the
/// reply object its `RecvReply` named, if any. A timed receive carries its
/// deadline in timer ticks.
static BLOCKED_RECVS: Mutex<WaitTable<Option<ObjectId>, MAX_THREADS>> = Mutex::new(WaitTable::new());

/// Threads parked in `wait`, by notification address. A notification never
/// holds bits while a thread waits on it: a signal hands them straight over.
static NTFN_WAITERS: Mutex<WaitTable<(), MAX_THREADS>> = Mutex::new(WaitTable::new());

/// Threads parked in `console_read`, each with the most bytes it takes. There
/// is one console, so every reader waits on the same key.
static CONSOLE_READERS: Mutex<WaitTable<usize, MAX_THREADS>> = Mutex::new(WaitTable::new());

/// The console's key in [`CONSOLE_READERS`].
const CONSOLE: u64 = 0;

/// Milliseconds per timer tick, rounded down: the PIT runs at its power-on
/// rate, a tick every 54.9 ms, so dividing by 54 never waits less than asked.
const TICK_MS: u64 = 54;

/// The timer tick count, as an [`Instant`] the deadlines compare against.
fn ticks_now() -> Instant {
    Instant::new(crate::interrupts::TICK_COUNT.load(core::sync::atomic::Ordering::Relaxed) as u64)
}

/// The deadline of a wait of `ms` milliseconds starting now: whole ticks,
/// rounded up, plus the tick in progress.
pub(super) fn deadline_after(ms: u64) -> Instant {
    ticks_now().saturating_add(Duration::new(ms.div_ceil(TICK_MS).saturating_add(1)))
}

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
    if word & IPC_ERR_FLAG != 0 {
        return IpcSyscallError::BadWord as u64;
    }
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
    let parked = BLOCKED_SENDS.lock().park(endpoint_addr, cur, None, Send { message, badge, call: false });
    if parked.is_err() {
        return IpcSyscallError::WouldBlock as u64; // table full
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
    recv_blocking(cap_slot, None, None)
}

/// The shared blocking receive behind [`Syscall::IpcRecvBlocking`],
/// [`Syscall::RecvReply`], and [`Syscall::RecvTimeout`].
///
/// Rendezvous with a sender already parked on the endpoint, or take a message
/// already deposited; otherwise park this thread in `BLOCKED_RECVS` and yield.
/// `reply` is the reply object a `RecvReply` named: a `Call` that meets it binds
/// it to the caller, and a `Call` that meets a plain receive fails with
/// [`IpcSyscallError::NoReply`] rather than waiting forever. A thread parked
/// with a `deadline` is woken at that tick with [`IpcSyscallError::TimedOut`]
/// if nothing arrived (see [`expire_timed_waits`]).
fn recv_blocking(cap_slot: u64, reply: Option<ObjectId>, deadline: Option<Instant>) -> SyscallRet {
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
    if BLOCKED_RECVS.lock().park(endpoint_addr, cur, deadline, reply).is_err() {
        return err(IpcSyscallError::WouldBlock);
    }
    // the sender overwrites rax/rdx with the word and badge before readying us.
    park_current();
    0.into() // ignored: the stub yields instead of sysretq'ing
}

/// Implements [`Syscall::RecvTimeout`]: [`recv_blocking`] until `ms`
/// milliseconds from now, with the reply object in `reply_slot` unless that
/// is [`NO_REPLY`].
pub(super) fn sys_recv_timeout(ep_slot: u64, reply_slot: u64, ms: u64) -> SyscallRet {
    let reply = if reply_slot == NO_REPLY {
        None
    } else {
        match idle_reply(reply_slot) {
            Ok(reply) => Some(reply),
            Err(e) => return SyscallRet::from(e as u64 | IPC_ERR_FLAG),
        }
    };
    recv_blocking(ep_slot, reply, Some(deadline_after(ms)))
}

/// Wakes every thread whose timed receive has run out of time, with
/// [`IpcSyscallError::TimedOut`]. Called on every timer tick.
///
/// The table is only tried, never waited for: code that holds it with
/// interrupts enabled (a revoke run from a kernel task) must not deadlock the
/// tick, and a tick that finds it busy only puts the wake off to the next one.
pub fn expire_timed_waits() {
    let now = ticks_now();
    expire(&BLOCKED_RECVS, now);
    expire(&CONSOLE_READERS, now);
    expire(&NTFN_WAITERS, now);
    // input a receive interrupt could not hand over waits at most a tick.
    console_input_arrived();
}

/// Resumes every waiter in `table` whose deadline `now` has reached with
/// [`IpcSyscallError::TimedOut`], oldest first, trying the lock only (see
/// [`expire_timed_waits`]).
fn expire<T: Copy>(table: &Mutex<WaitTable<T, MAX_THREADS>>, now: Instant) {
    loop {
        let expired = table.try_lock().and_then(|mut waiters| waiters.take_expired(now));
        let Some(waiter) = expired else { break };
        resume(waiter.thread, IpcSyscallError::TimedOut as u64 | IPC_ERR_FLAG, 0);
    }
}

/// Signals the notification `object` with `bits`: the thread that has waited
/// longest in `wait` takes them at once; with none waiting they join the
/// pending bits, and a kernel task waiting on it is woken (see
/// `cap::notification_signal`).
pub fn signal_notification(object: ObjectId, bits: u64) {
    let waiter = NTFN_WAITERS.lock().take_oldest(object.phys_addr());
    match waiter {
        Some(waiter) => resume(waiter.thread, bits, 0),
        None => cap::notification_signal(object, Badge(bits)),
    }
}

/// Implements [`Syscall::Signal`]: signals with the capability's badge, or
/// bit 0 for an unbadged capability, so a signal is never empty.
pub(super) fn sys_signal(ntfn_slot: u64) -> u64 {
    match resolve_notification_slot(ntfn_slot, Rights::WRITE) {
        Ok((object, badge)) => {
            signal_notification(object, if badge == 0 { 1 } else { badge });
            0
        }
        Err(e) => e as u64,
    }
}

/// Implements [`Syscall::Wait`]: collects the pending bits, or waits for a
/// signal as `ms` says.
pub(super) fn sys_wait(ntfn_slot: u64, ms: u64) -> SyscallRet {
    let err = |e: IpcSyscallError| SyscallRet::from(e as u64 | IPC_ERR_FLAG);
    let object = match resolve_notification_slot(ntfn_slot, Rights::READ) {
        Ok((object, _)) => object,
        Err(e) => return err(e),
    };
    if let Some(Badge(bits)) = cap::notification_poll(object) {
        return SyscallRet::from(bits);
    }
    let cur = crate::sched::current_thread_id();
    if ms == 0 || cur == usize::MAX {
        return err(IpcSyscallError::WouldBlock);
    }
    let deadline = (ms != NO_TIMEOUT).then(|| deadline_after(ms));
    if NTFN_WAITERS.lock().park(object.phys_addr(), cur, deadline, ()).is_err() {
        return err(IpcSyscallError::WouldBlock);
    }
    // the signaller sets rax to the bits before readying us.
    park_current();
    0.into() // ignored: the stub yields instead of sysretq'ing
}

/// Resolves `slot` in the current `CSpace` to a notification the capability
/// grants `right` on, returning it and the capability's badge.
fn resolve_notification_slot(slot: u64, right: Rights) -> Result<(ObjectId, u64), IpcSyscallError> {
    let cap = current_cap(slot).ok_or(IpcSyscallError::BadCap)?;
    if cap.object.kind() != ObjectKind::Notification {
        return Err(IpcSyscallError::NotNotification);
    }
    if !cap.rights.contains(right) {
        return Err(IpcSyscallError::Denied);
    }
    Ok((cap.object, cap.badge.0))
}

/// Parks the current thread until console input arrives, or until
/// `deadline`, to take up to `max` bytes of it (see `sys_console_read`).
pub(super) fn park_console_reader(max: usize, deadline: Option<Instant>) -> SyscallRet {
    let err = |e: IpcSyscallError| SyscallRet::from(e as u64 | IPC_ERR_FLAG);
    let cur = crate::sched::current_thread_id();
    if cur == usize::MAX || CONSOLE_READERS.lock().park(CONSOLE, cur, deadline, max).is_err() {
        return err(IpcSyscallError::WouldBlock);
    }
    // whoever delivers the input sets rax to the byte count before readying us.
    park_current();
    0.into() // ignored: the stub yields instead of sysretq'ing
}

/// Hands waiting console input to the threads parked in `console_read`,
/// oldest first, as much as each asked for. Called when input arrives and on
/// every timer tick, from interrupt context, so it only tries its locks: a
/// busy one puts the delivery off to the next tick.
pub fn console_input_arrived() {
    loop {
        let reader = {
            let Some(mut readers) = CONSOLE_READERS.try_lock() else { return };
            if crate::console::try_pending() != Some(true) {
                return;
            }
            readers.take_oldest(CONSOLE)
        };
        let Some(reader) = reader else { return };
        // SAFETY: the id came from register_thread; a null entry is skipped.
        let tcb = unsafe { crate::sched::thread_table_entry(reader.thread) };
        let buffer = if tcb.is_null() {
            None
        } else {
            // SAFETY: a parked thread's TCB is live and not running, so nothing
            // else uses its buffer; interrupts are off on this path.
            unsafe { (*tcb).ipc_buffer_ptr() }
        };
        let count = buffer.and_then(|buffer| {
            // SAFETY: the buffer is a whole registered frame reached through
            // the identity map, so its data area is in bounds; the reader asked
            // for at most DATA_LEN bytes, and u8 has no invalid values.
            let data = unsafe {
                let start = buffer.cast::<u8>().add(ipc_buffer::DATA_OFFSET);
                core::slice::from_raw_parts_mut(start, reader.data.min(ipc_buffer::DATA_LEN))
            };
            crate::console::try_take(data)
        });
        resume(reader.thread, count.unwrap_or(0) as u64, 0);
    }
}

/// Hands `message` straight to a thread parked in a blocking receive on the
/// endpoint at `endpoint_addr`, if there is one: its buffer gets the words,
/// its saved `rax` word 0 and `rdx` the badge. Returns whether one took it.
pub(super) fn hand_to_parked_receiver(endpoint_addr: u64, message: &Message, badge: u64) -> bool {
    // the oldest receiver parked on the endpoint is served first.
    let waiting = BLOCKED_RECVS.lock().take_oldest(endpoint_addr);
    let Some(recv) = waiting else {
        return false;
    };
    resume_with(recv.thread, message, badge);
    true
}

/// Takes the message of a thread parked in a blocking send on the endpoint at
/// `endpoint_addr`, if there is one, and returns it with its badge. A plain
/// sender is woken with success; a caller stays parked with `reply` bound to
/// it, or, with no reply object to answer through, is failed with
/// [`IpcSyscallError::NoReply`].
pub(super) fn take_from_parked_sender(endpoint_addr: u64, reply: Option<ObjectId>) -> Option<(Message, u64)> {
    // the oldest sender parked on the endpoint goes first.
    let send = BLOCKED_SENDS.lock().take_oldest(endpoint_addr)?;
    if send.data.call {
        let bound = reply
            .and_then(cap::reply_object)
            .is_some_and(|r| r.inner.lock().bind(crate::sched::token(send.thread)).is_ok());
        if !bound {
            abort_call(send.thread);
        }
    } else {
        resume(send.thread, 0, 0);
    }
    Some((send.data.message, send.data.badge))
}

/// Ends every wait on the endpoint at `endpoint_addr`, which no capability
/// names any more, so nothing could ever complete them (seL4's
/// `cancelAllIPC`). Parked receivers, senders, and callers resume with
/// [`IpcSyscallError::BadCap`]; a thread parked by a fault, which has no call
/// to fail, is stopped.
pub fn cancel_waits_on(endpoint_addr: u64) {
    let bad_cap = IpcSyscallError::BadCap as u64;
    loop {
        let recv = BLOCKED_RECVS.lock().take_oldest(endpoint_addr);
        let Some(recv) = recv else { break };
        resume(recv.thread, bad_cap | IPC_ERR_FLAG, 0);
    }
    // a notification's waiters, when the address names one.
    loop {
        let waiter = NTFN_WAITERS.lock().take_oldest(endpoint_addr);
        let Some(waiter) = waiter else { break };
        resume(waiter.thread, bad_cap | IPC_ERR_FLAG, 0);
    }
    loop {
        let send = BLOCKED_SENDS.lock().take_oldest(endpoint_addr);
        let Some(send) = send else { break };
        fail_sender(&send, bad_cap);
    }
}

/// Resumes a parked sender with error `code`, flagged for a caller the way
/// [`Syscall::Call`] returns errors, or stops it if a fault parked it.
fn fail_sender(send: &Waiter<Send>, code: u64) {
    // SAFETY: the id came from register_thread; a null entry is skipped.
    let tcb = unsafe { crate::sched::thread_table_entry(send.thread) };
    // SAFETY: a non-null entry is a live TCB; single-CPU with interrupts off.
    if !tcb.is_null() && unsafe { (*tcb).state } == TcbState::Faulted {
        retire_threads(|t| core::ptr::eq(t, tcb));
        return;
    }
    resume(send.thread, if send.data.call { code | IPC_ERR_FLAG } else { code }, 0);
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
    let waiting = BLOCKED_RECVS.lock().take_oldest(endpoint_addr);
    if let Some(recv) = waiting {
        let bound = recv
            .data
            .and_then(cap::reply_object)
            .is_some_and(|r| r.inner.lock().bind(crate::sched::token(thread_id)).is_ok());
        resume_with(recv.thread, message, badge);
        return bound;
    }
    let call = Send { message: *message, badge, call: true };
    BLOCKED_SENDS.lock().park(endpoint_addr, thread_id, None, call).is_ok()
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
        let _ = BLOCKED_SENDS.lock().take_thread(id);
        let _ = BLOCKED_RECVS.lock().take_thread(id);
        let _ = CONSOLE_READERS.lock().take_thread(id);
        let _ = NTFN_WAITERS.lock().take_thread(id);
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

/// Checks the blocking tables for [`crate::selfcheck`]: returns
/// [`jos_core::abi::invariant::WAITS`] if a parked thread is not registered,
/// is parked twice, or is ready or running, and 0 otherwise.
pub fn check_waits() -> u64 {
    let mut parked = [false; MAX_THREADS];
    let mut bad = false;
    let current = crate::sched::current_thread_id();
    let mut visit = |thread: usize| {
        // SAFETY: thread_table_entry reads one entry, and an out-of-range id
        // reads as null.
        let registered = !unsafe { crate::sched::thread_table_entry(thread) }.is_null();
        if !registered || parked[thread] || thread == current || crate::sched::is_ready(thread) {
            bad = true;
        } else {
            parked[thread] = true;
        }
    };
    BLOCKED_SENDS.lock().for_each(|w| visit(w.thread));
    BLOCKED_RECVS.lock().for_each(|w| visit(w.thread));
    CONSOLE_READERS.lock().for_each(|w| visit(w.thread));
    NTFN_WAITERS.lock().for_each(|w| visit(w.thread));
    if bad { jos_core::abi::invariant::WAITS } else { 0 }
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
    if word & IPC_ERR_FLAG != 0 {
        return err(IpcSyscallError::BadWord);
    }
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

    // the oldest receiver parked on the endpoint takes the call.
    let waiting = BLOCKED_RECVS.lock().take_oldest(endpoint_addr);
    if let Some(recv) = waiting {
        let bound = recv
            .data
            .and_then(cap::reply_object)
            .is_some_and(|r| r.inner.lock().bind(crate::sched::token(cur)).is_ok());
        resume_with(recv.thread, &message, badge);
        if !bound {
            // a plain receive took the message but cannot answer it.
            return err(IpcSyscallError::NoReply);
        }
        // the Reply syscall overwrites our rax with the answer.
        park_current();
        return 0; // ignored: the stub yields instead of sysretq'ing
    }

    if BLOCKED_SENDS.lock().park(endpoint_addr, cur, None, Send { message, badge, call: true }).is_err() {
        return err(IpcSyscallError::WouldBlock);
    }
    park_current();
    0 // ignored
}

/// Implements [`Syscall::RecvReply`]: a blocking receive that names an idle reply
/// object, so a `Call` that arrives can be answered later.
pub(super) fn sys_recv_reply(ep_slot: u64, reply_slot: u64) -> SyscallRet {
    match idle_reply(reply_slot) {
        Ok(reply) => recv_blocking(ep_slot, Some(reply), None),
        Err(e) => SyscallRet::from(e as u64 | IPC_ERR_FLAG),
    }
}

/// Resolves `reply_slot` to a reply object no caller is bound to, which a
/// receive may hand to the next `Call`.
///
/// # Errors
///
/// Why [`resolve_reply_slot`] refused the slot, or
/// [`IpcSyscallError::ReplyBusy`] if a caller is bound already.
fn idle_reply(reply_slot: u64) -> Result<ObjectId, IpcSyscallError> {
    let reply = resolve_reply_slot(reply_slot)?;
    if cap::reply_object(reply).is_some_and(|r| r.inner.lock().is_idle()) {
        Ok(reply)
    } else {
        Err(IpcSyscallError::ReplyBusy)
    }
}

/// Implements [`Syscall::ReplyRecv`]: answers the bound caller, if any, then
/// receives the next message through [`sys_recv_reply`].
pub(super) fn sys_reply_recv(ep_slot: u64, reply_slot: u64, word: u64) -> SyscallRet {
    if word & IPC_ERR_FLAG != 0 {
        return SyscallRet::from(IpcSyscallError::BadWord as u64 | IPC_ERR_FLAG);
    }
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
    if word & IPC_ERR_FLAG != 0 {
        return IpcSyscallError::BadWord as u64;
    }
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

