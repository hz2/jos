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

use crate::endpoint::Message;

/// Number of message words a buffer holds, equal to a [`Message`]'s words.
pub const MSG_WORDS: usize = 4;

/// The message words of one thread's IPC buffer, at the start of its frame.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpcBuffer {
    /// Message words; `mrs[i]` is word `i`.
    pub mrs: [u64; MSG_WORDS],
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
#[must_use]
pub fn deliver(message: &Message, buffer: Option<&mut IpcBuffer>) -> u64 {
    if let Some(buf) = buffer {
        buf.mrs = message.words;
    }
    message.words[0]
}

#[cfg(test)]
mod tests {
    use super::{IpcBuffer, compose, deliver};

    #[test]
    fn words_round_trip_through_buffers() {
        let sender = IpcBuffer { mrs: [99, 1, 2, 3] };
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
        let message = compose(5, Some(&IpcBuffer { mrs: [0, 1, 2, 3] }));
        assert_eq!(deliver(&message, None), 5);
    }

    #[test]
    fn delivery_overwrites_stale_words() {
        let mut receiver = IpcBuffer { mrs: [9, 9, 9, 9] };
        let _ = deliver(&compose(1, None), Some(&mut receiver));
        assert_eq!(receiver.mrs, [1, 0, 0, 0]);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::{IpcBuffer, compose, deliver};

    /// Any message composed from a register word and a sender buffer arrives
    /// intact: the receiver sees the register word in the return value and in
    /// `mrs[0]`, and the sender's words 1 to 3 unchanged.
    #[kani::proof]
    fn buffer_round_trip_is_lossless() {
        let word0: u64 = kani::any();
        let sender = IpcBuffer { mrs: kani::any() };
        let mut receiver = IpcBuffer { mrs: kani::any() };
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
        let mut receiver = IpcBuffer { mrs: kani::any() };
        let returned = deliver(&compose(word0, None), Some(&mut receiver));
        assert!(returned == word0);
        assert!(receiver.mrs == [word0, 0, 0, 0]);
    }
}
