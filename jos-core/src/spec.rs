//! An executable specification of one thread's non-blocking syscalls.
//!
//! A deliberately plain model of what the syscall reference promises a thread
//! that stays inside its own capability space and never blocks: slots and
//! their rights and badges, minting and its derivation tree, revocation and
//! the count it returns, retyping out of an untyped region, and the
//! non-blocking halves of endpoints (one message deep) and notifications
//! (coalescing bits). It answers each call with the exact `rax` (and, for a
//! receive, `rdx`) the kernel must return.
//!
//! The fuzzer's differential mode runs every call on the live kernel and on
//! this model and stops at the first answer that differs, so each checks the
//! other: a divergence is a kernel bug, a spec bug, or a hole in the
//! reference. It is written from the reference and stays simple on purpose:
//! a flat array of slots, a parent index per capability, and a linear scan
//! for every question, with none of the kernel's structure shared.
//!
//! Out of scope: other capability spaces (so no `cnode_copy`), blocking,
//! mapping, threads, and running out of memory. A retype the kernel refuses
//! with `NoRoom` is taken as making nothing.

use crate::abi::{IPC_ERR_FLAG, InvokeError, IpcSyscallError, MintSyscallError, RetypeSyscallError, decode_object_type};
use crate::cap_rights::Rights;
use crate::untyped::ObjectType;

/// Slots in a capability space.
pub const SLOTS: usize = 64;

/// The most objects one run makes, the given ones included.
pub const MAX_OBJECTS: usize = 64;

/// What an object is, as far as the calls the spec answers can tell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An untyped region, which retypes make objects from.
    Untyped,
    /// An endpoint, holding at most one message: its word and badge.
    Endpoint(Option<(u64, u64)>),
    /// A notification and its pending bits.
    Notification(u64),
    /// Any other object: the calls here only see what it is not.
    Other,
}

/// A capability in the model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cap {
    /// Index of its object.
    pub object: usize,
    /// Its rights.
    pub rights: Rights,
    /// Its badge, zero for none.
    pub badge: u64,
    /// The slot of the capability it was minted from, if it was.
    pub parent: Option<usize>,
}

/// One thread's capability space and the objects it can reach.
pub struct Spec {
    /// The capability in each slot.
    slots: [Option<Cap>; SLOTS],
    /// The objects, by index.
    objects: [Kind; MAX_OBJECTS],
    /// How many of `objects` exist.
    object_count: usize,
}

/// The answer of a call: its `rax`, and `rdx` where it matters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer {
    /// What `rax` must hold.
    pub rax: u64,
    /// What `rdx` must hold, for a receive.
    pub rdx: Option<u64>,
}

impl Answer {
    /// An answer in `rax` alone.
    const fn rax(rax: u64) -> Self {
        Self { rax, rdx: None }
    }

    /// An IPC error, as a status call returns it.
    const fn status(e: IpcSyscallError) -> Self {
        Self::rax(e as u64)
    }

    /// An IPC error, as a call that returns a value flags it.
    const fn flagged(e: IpcSyscallError) -> Self {
        Self::rax(e as u64 | IPC_ERR_FLAG)
    }
}

impl Default for Spec {
    fn default() -> Self {
        Self::new()
    }
}

impl Spec {
    /// Returns an empty space with no objects.
    #[must_use]
    pub const fn new() -> Self {
        Self { slots: [None; SLOTS], objects: [Kind::Other; MAX_OBJECTS], object_count: 0 }
    }

    /// Puts a capability with `rights` to a new object of kind `kind` in
    /// `slot`, as a space starts out: the given capabilities. Returns `false`
    /// if the slot is taken or out of range, or there is no room for the
    /// object.
    pub fn give(&mut self, slot: usize, kind: Kind, rights: Rights) -> bool {
        match self.new_object(kind) {
            Some(object) if slot < SLOTS && self.slots[slot].is_none() => {
                self.slots[slot] = Some(Cap { object, rights, badge: 0, parent: None });
                true
            }
            _ => false,
        }
    }

    /// Returns the capability in `slot`, if there is one.
    #[must_use]
    pub fn cap(&self, slot: u64) -> Option<Cap> {
        let slot = usize::try_from(slot).ok()?;
        self.slots.get(slot).copied().flatten()
    }

    /// Returns whether `slot` holds a capability.
    #[must_use]
    pub fn is_live(&self, slot: u64) -> bool {
        self.cap(slot).is_some()
    }

    /// Makes a new object of kind `kind`, if there is room for one.
    fn new_object(&mut self, kind: Kind) -> Option<usize> {
        let object = self.object_count;
        *self.objects.get_mut(object)? = kind;
        self.object_count += 1;
        Some(object)
    }

    /// `add(a, b)`.
    #[must_use]
    pub const fn add(a: u64, b: u64) -> Answer {
        Answer::rax(a.wrapping_add(b))
    }

    /// `retype(untyped, type_word, dest)`. `kernel_said_no_room` says whether
    /// the kernel answered `NoRoom`, which the spec does not predict but
    /// accepts, as making nothing.
    pub fn retype(&mut self, untyped: u64, type_word: u64, dest: u64, kernel_said_no_room: bool) -> Answer {
        let error = |e: RetypeSyscallError| Answer::rax(e as u64);
        let Some(ty) = decode_object_type(type_word) else {
            return error(RetypeSyscallError::BadArgs);
        };
        if dest >= SLOTS as u64 {
            return error(RetypeSyscallError::DestOutOfRange);
        }
        let Some(source) = self.cap(untyped) else {
            return error(RetypeSyscallError::BadCap);
        };
        if self.objects[source.object] != Kind::Untyped {
            return error(RetypeSyscallError::NotUntyped);
        }
        if self.is_live(dest) {
            return error(RetypeSyscallError::DestOccupied);
        }
        let kind = match ty {
            ObjectType::Endpoint => Kind::Endpoint(None),
            ObjectType::Notification => Kind::Notification(0),
            // only the kernel's own size of capability space can be made.
            ObjectType::CNode { size_bits } if size_bits != crate::abi::CNODE_SIZE_BITS => {
                return error(RetypeSyscallError::BadType);
            }
            ObjectType::Untyped { .. } => return error(RetypeSyscallError::BadType),
            _ => Kind::Other,
        };
        if kernel_said_no_room {
            return error(RetypeSyscallError::NoRoom);
        }
        match self.new_object(kind) {
            // a retyped object's capability has no parent: revoking the
            // untyped does not reach it.
            Some(object) => {
                self.slots[index(dest)] = Some(Cap { object, rights: Rights::ALL, badge: 0, parent: None });
                Answer::rax(0)
            }
            None => error(RetypeSyscallError::NoRoom),
        }
    }

    /// `mint(source, rights, badge)`: a copy in the lowest free slot.
    pub fn mint(&mut self, source: u64, rights: u64, badge: u64) -> Answer {
        let error = |e: MintSyscallError| Answer::rax(e as u64 | IPC_ERR_FLAG);
        if badge & IPC_ERR_FLAG != 0 {
            return error(MintSyscallError::BadBadge);
        }
        let Some(parent) = self.cap(source) else {
            return error(MintSyscallError::BadCap);
        };
        if badge != 0 && parent.badge != 0 {
            return error(MintSyscallError::AlreadyBadged);
        }
        let Some(slot) = self.slots.iter().position(Option::is_none) else {
            return error(MintSyscallError::SpaceFull);
        };
        let mask = Rights::from_bits_truncate(rights.to_le_bytes()[0]);
        self.slots[slot] = Some(Cap {
            object: parent.object,
            rights: parent.rights.attenuate(mask),
            badge: if badge == 0 { parent.badge } else { badge },
            parent: Some(index(source)),
        });
        Answer::rax(slot as u64)
    }

    /// `revoke(slot)`: removes the capability and everything minted from it,
    /// and answers how many went.
    pub fn revoke(&mut self, slot: u64) -> Answer {
        if !self.is_live(slot) {
            return Answer::flagged(IpcSyscallError::BadCap);
        }
        let root = index(slot);
        // decide the whole subtree before removing anything: a removed
        // capability's children could no longer be traced to it.
        let doomed: [bool; SLOTS] = core::array::from_fn(|s| self.descends(s, root));
        let mut removed = 0;
        for (s, gone) in doomed.into_iter().enumerate() {
            if gone {
                self.slots[s] = None;
                removed += 1;
            }
        }
        Answer::rax(removed)
    }

    /// Whether the capability in `slot` is the one in `root` or was minted,
    /// directly or not, from it.
    fn descends(&self, slot: usize, root: usize) -> bool {
        let mut current = slot;
        // a parent chain is at most as long as there are slots.
        for _ in 0..=SLOTS {
            if current == root {
                return self.slots[slot].is_some();
            }
            match self.slots[current].and_then(|cap| cap.parent) {
                Some(parent) => current = parent,
                None => return false,
            }
        }
        false
    }

    /// Resolves `slot` to an endpoint the capability grants `right` on, in the
    /// kernel's order: a live capability, then the right, then the kind.
    fn endpoint(&self, slot: u64, right: Rights) -> Result<(Cap, Option<(u64, u64)>), IpcSyscallError> {
        let cap = self.cap(slot).ok_or(IpcSyscallError::BadCap)?;
        if !cap.rights.contains(right) {
            return Err(IpcSyscallError::Denied);
        }
        match self.objects[cap.object] {
            Kind::Endpoint(message) => Ok((cap, message)),
            _ => Err(IpcSyscallError::NotEndpoint),
        }
    }

    /// `ipc_send(slot, word)`, with no receiver waiting.
    pub fn send(&mut self, slot: u64, word: u64) -> Answer {
        if word & IPC_ERR_FLAG != 0 {
            return Answer::status(IpcSyscallError::BadWord);
        }
        match self.endpoint(slot, Rights::WRITE) {
            Err(e) => Answer::status(e),
            Ok((_, Some(_))) => Answer::status(IpcSyscallError::WouldBlock),
            Ok((cap, None)) => {
                self.objects[cap.object] = Kind::Endpoint(Some((word, cap.badge)));
                Answer::rax(0)
            }
        }
    }

    /// `ipc_recv(slot)`, with no sender waiting.
    pub fn recv(&mut self, slot: u64) -> Answer {
        match self.endpoint(slot, Rights::READ) {
            Err(e) => Answer::flagged(e),
            Ok((_, None)) => Answer::flagged(IpcSyscallError::WouldBlock),
            Ok((cap, Some((word, badge)))) => {
                self.objects[cap.object] = Kind::Endpoint(None);
                Answer { rax: word, rdx: Some(badge) }
            }
        }
    }

    /// `invoke(slot, method, argument)` on an endpoint: `send` and `recv`
    /// through the generic path, with its own errors.
    pub fn invoke(&mut self, slot: u64, method: u64, argument: u64) -> Answer {
        use crate::abi::invoke_method::{ENDPOINT_RECV, ENDPOINT_SEND};
        let error = |e: InvokeError| Answer::rax(e as u64 | IPC_ERR_FLAG);
        let Some(cap) = self.cap(slot) else {
            return error(InvokeError::BadCap);
        };
        let Kind::Endpoint(message) = self.objects[cap.object] else {
            return error(InvokeError::BadMethod);
        };
        match method {
            ENDPOINT_SEND if argument & IPC_ERR_FLAG != 0 => error(InvokeError::BadWord),
            ENDPOINT_SEND if !cap.rights.contains(Rights::WRITE) => error(InvokeError::Denied),
            ENDPOINT_SEND if message.is_some() => error(InvokeError::WouldBlock),
            ENDPOINT_SEND => {
                self.objects[cap.object] = Kind::Endpoint(Some((argument, cap.badge)));
                Answer::rax(0)
            }
            ENDPOINT_RECV if !cap.rights.contains(Rights::READ) => error(InvokeError::Denied),
            ENDPOINT_RECV => match message {
                Some((word, _)) => {
                    self.objects[cap.object] = Kind::Endpoint(None);
                    Answer::rax(word)
                }
                None => error(InvokeError::WouldBlock),
            },
            _ => error(InvokeError::BadMethod),
        }
    }

    /// Resolves `slot` to a notification the capability grants `right` on, in
    /// the kernel's order: a live capability, then the kind, then the right.
    fn notification(&self, slot: u64, right: Rights) -> Result<(Cap, u64), IpcSyscallError> {
        let cap = self.cap(slot).ok_or(IpcSyscallError::BadCap)?;
        let Kind::Notification(bits) = self.objects[cap.object] else {
            return Err(IpcSyscallError::NotNotification);
        };
        if !cap.rights.contains(right) {
            return Err(IpcSyscallError::Denied);
        }
        Ok((cap, bits))
    }

    /// `signal(slot)`, with no thread waiting.
    pub fn signal(&mut self, slot: u64) -> Answer {
        match self.notification(slot, Rights::WRITE) {
            Err(e) => Answer::status(e),
            Ok((cap, bits)) => {
                let signal = if cap.badge == 0 { 1 } else { cap.badge };
                self.objects[cap.object] = Kind::Notification(bits | signal);
                Answer::rax(0)
            }
        }
    }

    /// `wait(slot, 0)`: a poll.
    pub fn poll(&mut self, slot: u64) -> Answer {
        match self.notification(slot, Rights::READ) {
            Err(e) => Answer::flagged(e),
            Ok((_, 0)) => Answer::flagged(IpcSyscallError::WouldBlock),
            Ok((cap, bits)) => {
                self.objects[cap.object] = Kind::Notification(0);
                Answer::rax(bits)
            }
        }
    }
}

/// Converts a slot the caller checked to be in range into an index.
fn index(slot: u64) -> usize {
    usize::try_from(slot).unwrap_or(SLOTS)
}

#[cfg(test)]
mod tests {
    use super::{Answer, Kind, Spec};
    use crate::abi::{IPC_ERR_FLAG, IpcSyscallError, MintSyscallError, encode_object_type};
    use crate::cap_rights::Rights;
    use crate::untyped::ObjectType;

    /// A space with an untyped region in slot 4, as the fuzzer starts.
    fn space() -> Spec {
        let mut spec = Spec::new();
        assert!(spec.give(4, Kind::Untyped, Rights::ALL));
        spec
    }

    #[test]
    fn retyped_endpoints_carry_one_message_with_the_senders_badge() {
        let mut spec = space();
        assert_eq!(spec.retype(4, encode_object_type(ObjectType::Endpoint), 5, false), Answer { rax: 0, rdx: None });
        let badged = spec.mint(5, Rights::ALL.bits().into(), 9).rax;
        assert_eq!(badged, 0, "the lowest free slot");
        assert_eq!(spec.send(badged, 7).rax, 0);
        assert_eq!(spec.send(5, 8).rax, IpcSyscallError::WouldBlock as u64);
        assert_eq!(spec.recv(5), Answer { rax: 7, rdx: Some(9) });
        assert_eq!(spec.recv(5).rax, IpcSyscallError::WouldBlock as u64 | IPC_ERR_FLAG);
        assert_eq!(spec.send(5, 1 << 63).rax, IpcSyscallError::BadWord as u64);
    }

    #[test]
    fn revoke_takes_the_whole_subtree_and_counts_it() {
        let mut spec = space();
        spec.retype(4, encode_object_type(ObjectType::Notification), 6, false);
        let child = spec.mint(6, Rights::ALL.bits().into(), 0).rax;
        let grandchild = spec.mint(child, Rights::READ.bits().into(), 0).rax;
        let unrelated = spec.mint(4, Rights::ALL.bits().into(), 0).rax;
        assert_eq!(spec.revoke(6).rax, 3);
        assert!(!spec.is_live(child) && !spec.is_live(grandchild) && spec.is_live(unrelated));
        assert_eq!(spec.revoke(6).rax, IpcSyscallError::BadCap as u64 | IPC_ERR_FLAG);
    }

    #[test]
    fn mint_attenuates_and_badges_once() {
        let mut spec = space();
        spec.retype(4, encode_object_type(ObjectType::Notification), 6, false);
        let read_only = spec.mint(6, Rights::READ.bits().into(), 0b100).rax;
        assert_eq!(spec.signal(read_only).rax, IpcSyscallError::Denied as u64);
        assert_eq!(spec.mint(read_only, 0xff, 1).rax, MintSyscallError::AlreadyBadged as u64 | IPC_ERR_FLAG);
        let writer = spec.mint(read_only, 0xff, 0).rax;
        assert_eq!(spec.cap(writer).map(|c| (c.rights, c.badge)), Some((Rights::READ, 0b100)));
        assert_eq!(spec.signal(6).rax, 0);
        assert_eq!(spec.poll(read_only).rax, 1);
        assert_eq!(spec.mint(6, 0xff, 1 << 63).rax, MintSyscallError::BadBadge as u64 | IPC_ERR_FLAG);
    }
}
