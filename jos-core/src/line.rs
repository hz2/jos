//! Line editing for a console: what a terminal user types, turned into lines.
//!
//! A program reads console input a byte at a time and feeds each byte to a
//! [`LineEditor`], which keeps the line so far and says what to echo. It reads
//! what a serial terminal sends: printable ASCII is added and echoed,
//! backspace (DEL or BS) takes the last character out, Ctrl-U clears the line,
//! Ctrl-C abandons it, and Enter (CR, LF, or CRLF) ends it. Escape sequences,
//! such as the arrow keys, are swallowed whole. A full line takes no more
//! characters.
//!
//! # Invariant
//!
//! The line holds only printable ASCII, so it is always valid UTF-8, and never
//! more than `N` bytes. Each byte changes it exactly as the [`Edit`] it
//! returns says, which the Kani harness at the bottom of this file checks for
//! every byte sequence.

/// What feeding one byte did to the line, and so what to echo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Edit {
    /// Nothing: the byte was ignored, or was part of an escape sequence.
    Nothing,
    /// The character was added at the end: echo it.
    Typed(u8),
    /// The last character was taken out: echo backspace, space, backspace.
    Erased,
    /// The whole line, this many characters, was taken out.
    Cleared(usize),
    /// The line is full, so the character was dropped.
    Full,
    /// Enter: the line is done, and [`LineEditor::line`] holds it.
    Done,
    /// Ctrl-C: the line was abandoned, and is empty now.
    Interrupted,
}

/// Where the editor is within an escape sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Escape {
    /// Not in one.
    None,
    /// Just after `ESC`.
    Started,
    /// Inside a control sequence (`ESC [`), until its final byte.
    Control,
}

/// The line being typed, of at most `N` bytes.
pub struct LineEditor<const N: usize> {
    /// The line's bytes; the first `len` are live.
    bytes: [u8; N],
    /// How many bytes the line holds.
    len: usize,
    /// The last byte was a carriage return, so a line feed now ends nothing.
    after_cr: bool,
    /// Where the editor is within an escape sequence.
    escape: Escape,
}

/// The byte backspace sends on most terminals (DEL).
const DELETE: u8 = 0x7f;

/// The byte backspace sends on the others (BS).
const BACKSPACE: u8 = 0x08;

/// Ctrl-U.
const CLEAR: u8 = 0x15;

/// Ctrl-C.
const INTERRUPT: u8 = 0x03;

/// The byte an escape sequence starts with.
const ESC: u8 = 0x1b;

impl<const N: usize> LineEditor<N> {
    /// Returns an editor with an empty line.
    #[must_use]
    pub const fn new() -> Self {
        Self { bytes: [0; N], len: 0, after_cr: false, escape: Escape::None }
    }

    /// Feeds one byte of input and returns what it did.
    pub fn feed(&mut self, byte: u8) -> Edit {
        let after_cr = core::mem::replace(&mut self.after_cr, byte == b'\r');
        match self.escape {
            Escape::Started => {
                self.escape = if byte == b'[' { Escape::Control } else { Escape::None };
                return Edit::Nothing;
            }
            Escape::Control => {
                // parameter and intermediate bytes, then one final byte.
                if (0x40..=0x7e).contains(&byte) {
                    self.escape = Escape::None;
                }
                return Edit::Nothing;
            }
            Escape::None => {}
        }
        match byte {
            b'\n' if after_cr => Edit::Nothing,
            b'\r' | b'\n' => Edit::Done,
            DELETE | BACKSPACE if self.len > 0 => {
                self.len -= 1;
                Edit::Erased
            }
            CLEAR => Edit::Cleared(core::mem::take(&mut self.len)),
            INTERRUPT => {
                self.len = 0;
                Edit::Interrupted
            }
            ESC => {
                self.escape = Escape::Started;
                Edit::Nothing
            }
            0x20..=0x7e if self.len < N => {
                self.bytes[self.len] = byte;
                self.len += 1;
                Edit::Typed(byte)
            }
            0x20..=0x7e => Edit::Full,
            _ => Edit::Nothing,
        }
    }

    /// Returns the line so far.
    #[must_use]
    pub fn line(&self) -> &str {
        // only printable ascii is ever stored, so this never falls back.
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }

    /// Empties the line, for the next one.
    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl<const N: usize> Default for LineEditor<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{Edit, LineEditor};

    /// Feeds every byte of `input` and returns the last edit.
    fn feed_all<const N: usize>(editor: &mut LineEditor<N>, input: &[u8]) -> Edit {
        input.iter().fold(Edit::Nothing, |_, &byte| editor.feed(byte))
    }

    #[test]
    fn typing_and_enter_make_a_line() {
        let mut editor: LineEditor<16> = LineEditor::new();
        assert_eq!(editor.feed(b'l'), Edit::Typed(b'l'));
        assert_eq!(feed_all(&mut editor, b"s -a\r"), Edit::Done);
        assert_eq!(editor.line(), "ls -a");
        // the line feed of a crlf ends nothing more.
        assert_eq!(editor.feed(b'\n'), Edit::Nothing);
        editor.clear();
        assert_eq!(feed_all(&mut editor, b"x\n"), Edit::Done);
        assert_eq!(editor.line(), "x");
    }

    #[test]
    fn erasing_takes_characters_out() {
        let mut editor: LineEditor<16> = LineEditor::new();
        feed_all(&mut editor, b"helo");
        assert_eq!(editor.feed(0x7f), Edit::Erased);
        assert_eq!(editor.feed(0x08), Edit::Erased);
        feed_all(&mut editor, b"lo");
        assert_eq!(editor.line(), "helo");
        assert_eq!(editor.feed(0x15), Edit::Cleared(4));
        assert_eq!(editor.feed(0x7f), Edit::Nothing);
        feed_all(&mut editor, b"abc");
        assert_eq!(editor.feed(0x03), Edit::Interrupted);
        assert_eq!(editor.line(), "");
    }

    #[test]
    fn a_full_line_and_escape_sequences_add_nothing() {
        let mut editor: LineEditor<3> = LineEditor::new();
        feed_all(&mut editor, b"abc");
        assert_eq!(editor.feed(b'd'), Edit::Full);
        editor.clear();
        // up arrow, then a function key with parameters.
        assert_eq!(feed_all(&mut editor, b"\x1b[A\x1b[15~"), Edit::Nothing);
        assert_eq!(feed_all(&mut editor, b"\x1bOx"), Edit::Typed(b'x'));
        assert_eq!(editor.line(), "x");
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::{Edit, LineEditor};

    /// The capacity the harness uses: small, so the line fills.
    const N: usize = 3;

    /// For every sequence of six bytes, each byte changes the line exactly as
    /// the edit it returns says, the line never outgrows its capacity, and it
    /// holds only printable ASCII, so [`LineEditor::line`] never falls back.
    #[kani::proof]
    #[kani::unwind(7)] // six bytes, and three line bytes to check, plus one
    fn every_edit_says_what_it_did() {
        let mut editor: LineEditor<N> = LineEditor::new();
        for _ in 0..6 {
            let byte: u8 = kani::any();
            let before = editor.len;
            let last = if before > 0 { editor.bytes[before - 1] } else { 0 };
            match editor.feed(byte) {
                Edit::Typed(b) => assert!(b == byte && editor.len == before + 1 && editor.bytes[before] == byte),
                Edit::Erased => assert!(before > 0 && editor.len == before - 1),
                Edit::Cleared(n) => assert!(n == before && editor.len == 0),
                Edit::Interrupted => assert!(editor.len == 0),
                Edit::Full => assert!(before == N && editor.len == N),
                Edit::Done | Edit::Nothing => assert!(editor.len == before),
            }
            // a character that stays keeps its value.
            if editor.len >= before && before > 0 {
                assert!(editor.bytes[before - 1] == last);
            }
            assert!(editor.len <= N);
            assert!(editor.bytes[..editor.len].iter().all(|b| (0x20..=0x7e).contains(b)));
        }
    }
}
