//! The per-thread IPC buffer: message words that do not fit in a register.
//!
//! A message carries four data words (see [`Message`]). The syscall ABI passes
//! word 0 in a register; words 1 to 3 travel through each thread's IPC buffer,
//! a frame the thread registers with the kernel and also maps into its own
//! address space. The kernel reads the sender's buffer and writes the
//! receiver's through its own mapping of those frames, never through a user
//! virtual address, so there is no user pointer to validate (the seL4 model).
//!
//! A thread with no buffer still works: it sends zeros in words 1 to 3 and
//! receives word 0 only. That keeps register-only programs unchanged.
//!
//! # Layout
//!
//! An [`IpcBuffer`] sits at the start of its frame. `mrs[i]` is message word
//! `i`. On delivery the kernel writes all four words, so a receiver can read
//! word 0 from either the return register or `mrs[0]`; on send only `mrs[1]`
//! to `mrs[3]` are read, since word 0 comes from the register.
//!
//! Three more words carry a capability (byte offsets in the frame):
//!
//! | offset | field | written by |
//! |---|---|---|
//! | `0x20` | `send_cap`: slot of a capability to send, plus one | sender |
//! | `0x28` | `recv_slot`: slot an incoming capability lands in, plus one | receiver |
//! | `0x30` | `caps_received`: 1 if a capability arrived, else 0 | kernel |
//!
//! The plus-one encoding makes a zeroed buffer send and accept nothing.

use crate::endpoint::Message;

/// Number of message words a buffer holds, equal to a [`Message`]'s words.
pub const MSG_WORDS: usize = 4;

/// One thread's IPC buffer, at the start of its frame.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpcBuffer {
    /// Message words; `mrs[i]` is word `i`.
    pub mrs: [u64; MSG_WORDS],
    /// Slot of a capability to send with the next message, plus one; zero
    /// sends none.
    pub send_cap: u64,
    /// Slot where a capability sent with an incoming message lands, plus one;
    /// zero accepts none.
    pub recv_slot: u64,
    /// Set on every delivery: 1 if a capability arrived in `recv_slot`, else 0.
    pub caps_received: u64,
}

impl IpcBuffer {
    /// Returns the slot whose capability the next send carries, if any.
    #[must_use]
    pub fn send_slot(&self) -> Option<usize> {
        plus_one_slot(self.send_cap)
    }

    /// Returns the slot an incoming capability lands in, if the thread accepts
    /// one.
    #[must_use]
    pub fn receive_slot(&self) -> Option<usize> {
        plus_one_slot(self.recv_slot)
    }
}

/// Decodes a plus-one slot field: zero means none.
fn plus_one_slot(field: u64) -> Option<usize> {
    usize::try_from(field.checked_sub(1)?).ok()
}

/// Builds the message a sender passes: `word0` from the register, words 1 to 3
/// from its buffer, or zeros if it has none.
#[must_use]
pub fn compose(word0: u64, buffer: Option<&IpcBuffer>) -> Message {
    let mut data = [word0, 0, 0, 0];
    if let Some(buf) = buffer {
        data[1..].copy_from_slice(&buf.mrs[1..]);
    }
    Message::new(0, data)
}

/// Delivers `message` to a receiver: writes every word into its buffer, if it
/// has one, and returns word 0 for the return register.
///
/// `caps_received` is cleared; the kernel sets it once a capability the
/// message carries has actually landed.
#[must_use]
pub fn deliver(message: &Message, buffer: Option<&mut IpcBuffer>) -> u64 {
    if let Some(buf) = buffer {
        buf.mrs = message.words;
        buf.caps_received = 0;
    }
    message.words[0]
}

#[cfg(test)]
mod tests {
    use super::{IpcBuffer, compose, deliver};

    fn with_words(mrs: [u64; 4]) -> IpcBuffer {
        IpcBuffer { mrs, ..IpcBuffer::default() }
    }

    #[test]
    fn words_round_trip_through_buffers() {
        let sender = with_words([99, 1, 2, 3]);
        let message = compose(7, Some(&sender));
        // word 0 comes from the register, not the sender's mrs[0].
        assert_eq!(message.words, [7, 1, 2, 3]);
        let mut receiver = IpcBuffer::default();
        assert_eq!(deliver(&message, Some(&mut receiver)), 7);
        assert_eq!(receiver.mrs, [7, 1, 2, 3]);
    }

    #[test]
    fn no_sender_buffer_sends_zeros() {
        let message = compose(5, None);
        assert_eq!(message.words, [5, 0, 0, 0]);
    }

    #[test]
    fn no_receiver_buffer_gets_word_zero_only() {
        let message = compose(5, Some(&with_words([0, 1, 2, 3])));
        assert_eq!(deliver(&message, None), 5);
    }

    #[test]
    fn delivery_overwrites_stale_words() {
        let mut receiver = with_words([9, 9, 9, 9]);
        receiver.caps_received = 1;
        let _ = deliver(&compose(1, None), Some(&mut receiver));
        assert_eq!(receiver.mrs, [1, 0, 0, 0]);
        assert_eq!(receiver.caps_received, 0);
    }

    #[test]
    fn slot_fields_are_plus_one() {
        let mut buf = IpcBuffer::default();
        assert_eq!((buf.send_slot(), buf.receive_slot()), (None, None));
        buf.send_cap = 1;
        buf.recv_slot = 6;
        assert_eq!((buf.send_slot(), buf.receive_slot()), (Some(0), Some(5)));
    }

    #[test]
    fn compose_carries_no_capability() {
        let sender = IpcBuffer { send_cap: 3, ..IpcBuffer::default() };
        // the kernel attaches the capability after checking the endpoint's rights.
        assert_eq!(compose(0, Some(&sender)).cap, None);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::{IpcBuffer, compose, deliver};

    fn any_buffer() -> IpcBuffer {
        IpcBuffer {
            mrs: kani::any(),
            send_cap: kani::any(),
            recv_slot: kani::any(),
            caps_received: kani::any(),
        }
    }

    /// Any message composed from a register word and a sender buffer arrives
    /// intact: the receiver sees the register word in the return value and in
    /// `mrs[0]`, and the sender's words 1 to 3 unchanged.
    #[kani::proof]
    fn buffer_round_trip_is_lossless() {
        let word0: u64 = kani::any();
        let sender = any_buffer();
        let mut receiver = any_buffer();
        let returned = deliver(&compose(word0, Some(&sender)), Some(&mut receiver));
        assert!(returned == word0);
        assert!(receiver.mrs[0] == word0);
        assert!(receiver.mrs[1..] == sender.mrs[1..]);
    }

    /// Without a sender buffer, words 1 to 3 arrive as zero, never as stale data
    /// left in the receiver's buffer.
    #[kani::proof]
    fn missing_sender_buffer_sends_zeros() {
        let word0: u64 = kani::any();
        let mut receiver = any_buffer();
        let returned = deliver(&compose(word0, None), Some(&mut receiver));
        assert!(returned == word0);
        assert!(receiver.mrs == [word0, 0, 0, 0]);
    }

    /// Delivery never reports a capability on its own and leaves the receiver's
    /// requests untouched: a stale `caps_received` cannot survive into the next
    /// message.
    #[kani::proof]
    fn delivery_clears_caps_received() {
        let sender = any_buffer();
        let mut receiver = any_buffer();
        let before = receiver;
        let _ = deliver(&compose(kani::any(), Some(&sender)), Some(&mut receiver));
        assert!(receiver.caps_received == 0);
        assert!(receiver.send_cap == before.send_cap);
        assert!(receiver.recv_slot == before.recv_slot);
    }

    /// The plus-one slot fields decode zero as none and anything else as the
    /// slot one below it.
    #[kani::proof]
    fn slot_fields_decode_plus_one() {
        let buf = any_buffer();
        match buf.receive_slot() {
            None => assert!(buf.recv_slot == 0),
            Some(slot) => assert!(slot as u64 + 1 == buf.recv_slot),
        }
        match buf.send_slot() {
            None => assert!(buf.send_cap == 0),
            Some(slot) => assert!(slot as u64 + 1 == buf.send_cap),
        }
    }
}
