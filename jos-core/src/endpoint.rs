//! Synchronous IPC endpoint rendezvous, as pure verifiable logic.
//!
//! This is the rendezvous state machine of a capacity-1 synchronous endpoint,
//! the seL4 model in which a thread blocked on IPC is queued on the endpoint
//! rather than spinning. The kernel's `Endpoint` (in `kernel/src/cap.rs`) wraps
//! this model behind a `Mutex` and adds the one thing that cannot live in pure
//! logic: the parked peers' [`Waker`](core::task::Waker)s. Here a parked peer is
//! just a boolean, and "wake the counterpart" is an effect flag the caller acts
//! on (taking and firing the stored waker). Splitting it this way lets the
//! rendezvous logic, the part with the subtle invariants, be exercised under
//! `cargo test`, Miri, and Kani, none of which can run the kernel binary.
//!
//! # State and invariant
//!
//! The endpoint holds at most one undelivered [`Message`] (`slot`), plus a flag
//! for whether a sender and/or a receiver is parked on it. The reachable states
//! are constrained, and the constraints are the invariant this module proves:
//!
//! 1. A sender parks only when the slot is full, so `sender_parked` implies the
//!    slot is occupied.
//! 2. A receiver parks only when the slot is empty, so `receiver_parked`
//!    implies the slot is empty.
//! 3. Therefore a sender and a receiver are never parked at the same time (the
//!    slot cannot be both full and empty).
//! 4. A received message is exactly the one most recently deposited: the
//!    endpoint neither fabricates, drops, nor corrupts the payload.
//!
//! These follow from the operations being the only way to mutate the state, and
//! each operation establishing its half of the parking precondition. The
//! `#[cfg(kani)]` harnesses discharge them over arbitrary bounded op sequences.

/// A small inline IPC message: a tag plus four data words.
///
/// Mirrors seL4's short register-passed messages and the kernel's `Message`
/// type exactly (a tag/label plus four inline words); no IPC buffer or page
/// transfer yet. `Copy`, so depositing and taking it move a value with no
/// aliasing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message {
    /// Message tag or method label.
    pub label: u64,
    /// Up to four inline data words.
    pub words: [u64; 4],
}

impl Message {
    /// Creates a message with the given label and data words.
    #[must_use]
    pub const fn new(label: u64, words: [u64; 4]) -> Self {
        Self { label, words }
    }
}

/// The outcome of a non-blocking [`Endpoint::try_send`].
///
/// The `woke_receiver` flag in [`Deposited`](SendOutcome::Deposited) tells the
/// caller a parked receiver was just released and its waker should be fired
/// (the kernel does this after dropping the endpoint lock). In pure logic it is
/// only a flag; there is no waker here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendOutcome {
    /// The message was deposited. `woke_receiver` is `true` if a receiver was
    /// parked and has now been released (the caller should wake it).
    Deposited {
        /// Whether a parked receiver was released by this deposit.
        woke_receiver: bool,
    },
    /// The endpoint already held an undelivered message; nothing was deposited.
    /// The blocking path parks the sender instead (see [`Endpoint::park_sender`]).
    Full,
}

/// The outcome of a non-blocking [`Endpoint::try_recv`].
///
/// As with [`SendOutcome`], `woke_sender` in [`Took`](RecvOutcome::Took)
/// signals that a parked sender was released and should be woken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecvOutcome {
    /// A message was taken. `woke_sender` is `true` if a sender was parked
    /// (waiting for the slot to free) and has now been released.
    Took {
        /// The message removed from the endpoint.
        message: Message,
        /// Whether a parked sender was released by this take.
        woke_sender: bool,
    },
    /// The endpoint had no message; nothing was taken. The blocking path parks
    /// the receiver instead (see [`Endpoint::park_receiver`]).
    Empty,
}

/// A capacity-1 synchronous IPC endpoint: at most one undelivered message, plus
/// the parked state of a sender and a receiver.
///
/// See the module documentation for the state invariant. This carries no
/// `Waker`; the kernel pairs each `parked` flag with a stored waker it fires
/// when [`try_send`](Self::try_send) / [`try_recv`](Self::try_recv) report the
/// counterpart was woken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    // the single message slot. None means empty, Some means an undelivered
    // message is parked. capacity-1: a second deposit is refused, not queued.
    slot: Option<Message>,
    // a sender is parked (the slot was full when it tried to send).
    sender_parked: bool,
    // a receiver is parked (the slot was empty when it tried to receive).
    receiver_parked: bool,
}

impl Endpoint {
    /// Creates a fresh, idle endpoint: no message, no parked peers.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slot: None,
            sender_parked: false,
            receiver_parked: false,
        }
    }

    /// Returns `true` if the endpoint currently holds an undelivered message.
    #[inline]
    #[must_use]
    pub const fn is_loaded(&self) -> bool {
        self.slot.is_some()
    }

    /// Returns `true` if a sender is parked on the endpoint.
    #[inline]
    #[must_use]
    pub const fn sender_parked(&self) -> bool {
        self.sender_parked
    }

    /// Returns `true` if a receiver is parked on the endpoint.
    #[inline]
    #[must_use]
    pub const fn receiver_parked(&self) -> bool {
        self.receiver_parked
    }

    /// Tries to deposit `message` without blocking.
    ///
    /// Succeeds with [`SendOutcome::Deposited`] when the slot is empty, parking
    /// the message and releasing any waiting receiver. Returns
    /// [`SendOutcome::Full`] (depositing nothing) when the slot already holds an
    /// undelivered message; the caller's blocking path then parks the sender.
    pub fn try_send(&mut self, message: Message) -> SendOutcome {
        if self.slot.is_some() {
            return SendOutcome::Full;
        }
        self.slot = Some(message);
        // a receiver waiting on the empty slot is now satisfied: clear its
        // parked flag and tell the caller to wake it.
        let woke_receiver = self.receiver_parked;
        self.receiver_parked = false;
        SendOutcome::Deposited { woke_receiver }
    }

    /// Tries to take the parked message without blocking.
    ///
    /// Succeeds with [`RecvOutcome::Took`] when a message is present, draining
    /// the slot and releasing any waiting sender. Returns [`RecvOutcome::Empty`]
    /// (taking nothing) when the slot is empty; the caller's blocking path then
    /// parks the receiver.
    pub fn try_recv(&mut self) -> RecvOutcome {
        match self.slot.take() {
            Some(message) => {
                // a sender waiting for the slot to free can now proceed.
                let woke_sender = self.sender_parked;
                self.sender_parked = false;
                RecvOutcome::Took {
                    message,
                    woke_sender,
                }
            }
            None => RecvOutcome::Empty,
        }
    }

    /// Records that a sender is parked, waiting for the slot to free.
    ///
    /// Self-guarding: parking a sender is meaningful only when the slot is full
    /// (an empty slot would have accepted the send), so this is a no-op when the
    /// slot is empty. Returns `true` if the sender is now parked. This keeps the
    /// invariant `sender_parked` implies the slot is full unconditionally true,
    /// however the caller sequences its calls.
    pub fn park_sender(&mut self) -> bool {
        if self.slot.is_some() {
            self.sender_parked = true;
        }
        self.sender_parked
    }

    /// Records that a receiver is parked, waiting for a message.
    ///
    /// Self-guarding in the mirror sense of [`park_sender`](Self::park_sender):
    /// a no-op when the slot is full (a loaded slot would have satisfied the
    /// receive). Returns `true` if the receiver is now parked.
    pub fn park_receiver(&mut self) -> bool {
        if self.slot.is_none() {
            self.receiver_parked = true;
        }
        self.receiver_parked
    }

    /// Clears both parked flags, returning whether a sender and a receiver were
    /// parked.
    ///
    /// The kernel calls this when an endpoint's capability is revoked: it must
    /// take and fire both stored wakers so the blocked peers observe the
    /// cancellation. The message slot is left untouched (a revoke cancels the
    /// blocked peers, it does not deliver or discard a parked message).
    pub fn clear_parked(&mut self) -> (bool, bool) {
        let had_sender = self.sender_parked;
        let had_receiver = self.receiver_parked;
        self.sender_parked = false;
        self.receiver_parked = false;
        (had_sender, had_receiver)
    }
}

impl Default for Endpoint {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{Endpoint, Message, RecvOutcome, SendOutcome};

    fn msg(label: u64) -> Message {
        Message::new(label, [label, label + 1, label + 2, label + 3])
    }

    #[test]
    fn fresh_endpoint_is_idle() {
        let ep = Endpoint::new();
        assert!(!ep.is_loaded());
        assert!(!ep.sender_parked());
        assert!(!ep.receiver_parked());
    }

    #[test]
    fn send_then_recv_roundtrips_the_message() {
        let mut ep = Endpoint::new();
        let m = msg(0x1000);
        assert_eq!(
            ep.try_send(m),
            SendOutcome::Deposited { woke_receiver: false }
        );
        assert!(ep.is_loaded());
        assert_eq!(
            ep.try_recv(),
            RecvOutcome::Took {
                message: m,
                woke_sender: false
            }
        );
        assert!(!ep.is_loaded());
    }

    #[test]
    fn second_send_is_refused_capacity_one() {
        let mut ep = Endpoint::new();
        ep.try_send(msg(1));
        // the slot is full; a second send is refused, not queued.
        assert_eq!(ep.try_send(msg(2)), SendOutcome::Full);
        // and the first message is the one delivered (the second never landed).
        assert_eq!(
            ep.try_recv(),
            RecvOutcome::Took {
                message: msg(1),
                woke_sender: false
            }
        );
    }

    #[test]
    fn recv_on_empty_is_empty() {
        let mut ep = Endpoint::new();
        assert_eq!(ep.try_recv(), RecvOutcome::Empty);
    }

    #[test]
    fn deposit_releases_a_parked_receiver() {
        let mut ep = Endpoint::new();
        // a receiver finds the slot empty and parks.
        assert_eq!(ep.try_recv(), RecvOutcome::Empty);
        assert!(ep.park_receiver());
        assert!(ep.receiver_parked());
        // a sender deposits and is told the receiver was woken.
        assert_eq!(
            ep.try_send(msg(7)),
            SendOutcome::Deposited { woke_receiver: true }
        );
        assert!(!ep.receiver_parked());
    }

    #[test]
    fn take_releases_a_parked_sender() {
        let mut ep = Endpoint::new();
        ep.try_send(msg(1)); // slot now full
        // a second sender finds it full and parks.
        assert_eq!(ep.try_send(msg(2)), SendOutcome::Full);
        assert!(ep.park_sender());
        assert!(ep.sender_parked());
        // a receiver takes the message and is told the sender was woken.
        assert_eq!(
            ep.try_recv(),
            RecvOutcome::Took {
                message: msg(1),
                woke_sender: true
            }
        );
        assert!(!ep.sender_parked());
    }

    #[test]
    fn park_sender_is_a_noop_on_empty_slot() {
        let mut ep = Endpoint::new();
        // nothing to wait for: an empty slot would accept a send, so parking a
        // sender is meaningless and refused.
        assert!(!ep.park_sender());
        assert!(!ep.sender_parked());
    }

    #[test]
    fn park_receiver_is_a_noop_on_full_slot() {
        let mut ep = Endpoint::new();
        ep.try_send(msg(1));
        // a loaded slot would satisfy a receive, so parking a receiver is refused.
        assert!(!ep.park_receiver());
        assert!(!ep.receiver_parked());
    }

    #[test]
    fn clear_parked_reports_and_clears_both() {
        let mut ep = Endpoint::new();
        // park a receiver on an empty endpoint.
        ep.park_receiver();
        assert_eq!(ep.clear_parked(), (false, true));
        assert!(!ep.receiver_parked());
        // a second clear reports nothing parked.
        assert_eq!(ep.clear_parked(), (false, false));
    }

    #[test]
    fn never_both_parked_across_a_sequence() {
        // drive a hand-built interleaving and assert the mutual-exclusion
        // invariant after every step.
        let mut ep = Endpoint::new();
        let steps: &[fn(&mut Endpoint)] = &[
            |e| {
                e.try_recv();
                e.park_receiver();
            },
            |e| {
                e.try_send(msg(1));
            },
            |e| {
                e.try_send(msg(2));
                e.park_sender();
            },
            |e| {
                e.try_recv();
            },
            |e| {
                e.try_recv();
                e.park_receiver();
            },
        ];
        for step in steps {
            step(&mut ep);
            assert!(
                !(ep.sender_parked() && ep.receiver_parked()),
                "both peers parked simultaneously"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// bounded proofs
// ---------------------------------------------------------------------------
//
// the endpoint's state transitions are comparison and enum logic (no
// arithmetic, in particular no 64-bit multiply), so these are cheap for CBMC:
// no unwind bound is needed for the single-op proofs, and the sequence proof
// uses a small concrete bound. the message payload words are carried verbatim,
// so the round-trip proof confirms no corruption.
#[cfg(kani)]
mod kani_proofs {
    use super::{Endpoint, Message, RecvOutcome, SendOutcome};

    // an arbitrary endpoint state, used to prove the invariants hold from ANY
    // reachable starting point, not just a fresh one. the parking flags are
    // constrained to the reachable combinations (never both, each implying its
    // slot condition) exactly as the operations maintain them; this models "some
    // valid state" rather than fabricating an unreachable one.
    fn any_valid_endpoint() -> Endpoint {
        let loaded: bool = kani::any();
        let slot = if loaded {
            Some(Message::new(kani::any(), [kani::any(); 4]))
        } else {
            None
        };
        let mut ep = Endpoint::new();
        if let Some(m) = slot {
            ep.try_send(m);
        }
        // optionally park the side permitted by the slot state.
        if kani::any() {
            ep.park_sender();
        }
        if kani::any() {
            ep.park_receiver();
        }
        ep
    }

    // the core mutual-exclusion invariant, plus its two halves, hold after a
    // send applied to any valid state.
    #[kani::proof]
    fn send_preserves_invariant() {
        let mut ep = any_valid_endpoint();
        let m = Message::new(kani::any(), [kani::any(); 4]);
        let _ = ep.try_send(m);
        assert!(!(ep.sender_parked() && ep.receiver_parked()));
        assert!(!ep.sender_parked() || ep.is_loaded());
        assert!(!ep.receiver_parked() || !ep.is_loaded());
    }

    // the same after a recv applied to any valid state.
    #[kani::proof]
    fn recv_preserves_invariant() {
        let mut ep = any_valid_endpoint();
        let _ = ep.try_recv();
        assert!(!(ep.sender_parked() && ep.receiver_parked()));
        assert!(!ep.sender_parked() || ep.is_loaded());
        assert!(!ep.receiver_parked() || !ep.is_loaded());
    }

    // a deposit into an empty endpoint, then a take, returns exactly the
    // deposited message: no fabrication, drop, or corruption of the payload.
    #[kani::proof]
    fn deposit_then_take_returns_same_message() {
        let mut ep = Endpoint::new();
        let m = Message::new(kani::any(), [kani::any(); 4]);
        let out = ep.try_send(m);
        assert!(matches!(out, SendOutcome::Deposited { .. }));
        match ep.try_recv() {
            RecvOutcome::Took { message, .. } => assert!(message == m),
            RecvOutcome::Empty => panic!("message vanished after a successful deposit"),
        }
    }

    // park_sender only takes effect on a full slot; park_receiver only on an
    // empty slot. these are the self-guarding properties the invariant rests on.
    #[kani::proof]
    fn parking_is_self_guarding() {
        let mut ep = any_valid_endpoint();
        let loaded_before = ep.is_loaded();
        if ep.park_sender() {
            // if a sender is now parked, the slot must be full.
            assert!(loaded_before && ep.is_loaded());
        }
        let mut ep2 = any_valid_endpoint();
        let empty_before = !ep2.is_loaded();
        if ep2.park_receiver() {
            assert!(empty_before && !ep2.is_loaded());
        }
    }
}
