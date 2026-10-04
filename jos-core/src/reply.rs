//! One-shot reply object for `Call`/`Reply` IPC, as pure verifiable logic.
//!
//! A `Call` is a send that also waits for an answer. When the server receives
//! a called message, the kernel binds a `Reply` object to the caller; the
//! server later answers through that object exactly once. This is the seL4 MCS
//! reply-object model: the right to answer is a capability the server holds,
//! not ambient knowledge of who called, and it is consumed by use.
//!
//! As in [`crate::endpoint`], the kernel pairs this model with the parked
//! caller's waker; here a parked caller is a state, and "wake the caller" is an
//! effect the kernel performs after [`Reply::reply`] succeeds.
//!
//! # State and invariant
//!
//! ```text
//! Idle --bind--> Waiting --reply(m)--> Replied(m) --take--> Idle
//!                   |                      |
//!                   +------cancel----------+-----> Idle
//! ```
//!
//! 1. A reply is delivered only to a bound caller: `reply` on `Idle` or
//!    `Replied` is refused and changes nothing.
//! 2. One shot: between two `bind`s at most one reply is accepted.
//! 3. A caller takes exactly the message the server replied with.
//! 4. `cancel` (caller timed out, or the reply cap was revoked) always returns
//!    to `Idle`, so a late reply is refused rather than delivered to a stranger.

use crate::endpoint::Message;

/// Errors from [`Reply`] operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyError {
    /// `bind` was called while a caller is already bound to this object.
    Busy,
    /// `reply` was called with no caller waiting for an answer.
    NotWaiting,
}

/// The state of a reply object. See the module documentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Idle,
    Waiting,
    Replied(Message),
}

/// A one-shot reply object: binds to one caller, accepts one answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    state: State,
}

impl Reply {
    /// Creates an idle reply object with no caller bound.
    #[must_use]
    pub const fn new() -> Self {
        Self { state: State::Idle }
    }

    /// Returns `true` if no caller is bound and no answer is pending.
    #[inline]
    #[must_use]
    pub const fn is_idle(&self) -> bool {
        matches!(self.state, State::Idle)
    }

    /// Returns `true` if a caller is bound and waiting for an answer.
    #[inline]
    #[must_use]
    pub const fn is_waiting(&self) -> bool {
        matches!(self.state, State::Waiting)
    }

    /// Binds a caller: the kernel calls this when it delivers a called message
    /// to the server.
    ///
    /// # Errors
    ///
    /// [`ReplyError::Busy`] if the object is not idle; the state is unchanged.
    pub fn bind(&mut self) -> Result<(), ReplyError> {
        if !self.is_idle() {
            return Err(ReplyError::Busy);
        }
        self.state = State::Waiting;
        Ok(())
    }

    /// Answers the bound caller with `message`. On success the kernel wakes the
    /// caller, which then collects the answer with [`take`](Self::take).
    ///
    /// # Errors
    ///
    /// [`ReplyError::NotWaiting`] if no caller is waiting (never bound, already
    /// answered, or cancelled); the state is unchanged.
    pub fn reply(&mut self, message: Message) -> Result<(), ReplyError> {
        if !self.is_waiting() {
            return Err(ReplyError::NotWaiting);
        }
        self.state = State::Replied(message);
        Ok(())
    }

    /// Collects the answer, returning the object to idle. `None` if no answer
    /// is pending.
    pub fn take(&mut self) -> Option<Message> {
        match self.state {
            State::Replied(message) => {
                self.state = State::Idle;
                Some(message)
            }
            State::Idle | State::Waiting => None,
        }
    }

    /// Abandons the binding (caller timed out or the reply cap was revoked),
    /// discarding any undelivered answer. Returns `true` if a caller was bound.
    pub fn cancel(&mut self) -> bool {
        let was_bound = !self.is_idle();
        self.state = State::Idle;
        was_bound
    }
}

impl Default for Reply {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{Message, Reply, ReplyError};

    fn msg(label: u64) -> Message {
        Message::new(label, [label; 4])
    }

    #[test]
    fn call_reply_roundtrip() {
        let mut r = Reply::new();
        r.bind().unwrap();
        assert!(r.is_waiting());
        r.reply(msg(9)).unwrap();
        assert_eq!(r.take(), Some(msg(9)));
        assert!(r.is_idle());
    }

    #[test]
    fn reply_without_caller_is_refused() {
        let mut r = Reply::new();
        assert_eq!(r.reply(msg(1)), Err(ReplyError::NotWaiting));
        assert!(r.is_idle());
    }

    #[test]
    fn second_reply_is_refused() {
        let mut r = Reply::new();
        r.bind().unwrap();
        r.reply(msg(1)).unwrap();
        assert_eq!(r.reply(msg(2)), Err(ReplyError::NotWaiting));
        // the first answer is the one delivered.
        assert_eq!(r.take(), Some(msg(1)));
    }

    #[test]
    fn bind_while_bound_is_busy() {
        let mut r = Reply::new();
        r.bind().unwrap();
        assert_eq!(r.bind(), Err(ReplyError::Busy));
    }

    #[test]
    fn cancel_makes_late_reply_fail() {
        let mut r = Reply::new();
        r.bind().unwrap();
        assert!(r.cancel());
        assert_eq!(r.reply(msg(1)), Err(ReplyError::NotWaiting));
        assert_eq!(r.take(), None);
        assert!(!r.cancel());
    }

    #[test]
    fn take_before_reply_is_none() {
        let mut r = Reply::new();
        r.bind().unwrap();
        assert_eq!(r.take(), None);
        // the caller is still waiting.
        assert!(r.is_waiting());
    }
}

// bounded proofs: the state space is three states, so a short arbitrary op
// sequence from a fresh object covers every reachable transition.
#[cfg(kani)]
mod kani_proofs {
    use super::{Message, Reply};

    fn any_msg() -> Message {
        Message::new(kani::any(), [kani::any(); 4])
    }

    // one shot: after a bind, at most one reply is accepted, whatever ops follow
    // (short of take/cancel, which end the binding).
    #[kani::proof]
    fn at_most_one_reply_per_bind() {
        let mut r = Reply::new();
        r.bind().unwrap();
        let first = r.reply(any_msg());
        let second = r.reply(any_msg());
        assert!(first.is_ok());
        assert!(second.is_err());
    }

    // the caller takes exactly the answer the server gave.
    #[kani::proof]
    fn take_returns_the_reply() {
        let mut r = Reply::new();
        let m = any_msg();
        r.bind().unwrap();
        r.reply(m).unwrap();
        assert!(r.take() == Some(m));
        assert!(r.is_idle());
    }

    // over an arbitrary 4-op sequence, a message is only ever taken after a
    // reply was accepted while a caller was bound.
    #[kani::proof]
    #[kani::unwind(5)]
    fn no_answer_without_bound_caller() {
        let mut r = Reply::new();
        let mut accepted = 0u8;
        let mut taken = 0u8;
        for _ in 0..4 {
            match kani::any::<u8>() % 4 {
                0 => {
                    let _ = r.bind();
                }
                1 => {
                    let waiting = r.is_waiting();
                    if r.reply(any_msg()).is_ok() {
                        assert!(waiting);
                        accepted += 1;
                    }
                }
                2 => {
                    if r.take().is_some() {
                        taken += 1;
                    }
                }
                _ => {
                    let _ = r.cancel();
                }
            }
            // never more answers delivered than accepted.
            assert!(taken <= accepted);
        }
    }
}
