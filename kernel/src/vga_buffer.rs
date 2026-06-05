use core::fmt;
use spin::Mutex;
use volatile::Volatile;

/// A global `Writer` instance that can be used for printing to the VGA text buffer.
///
/// Used by the `print!` and `println!` macros.
///
/// Constructed at compile time via `Writer::new` (no `lazy_static`): the buffer
/// is held as a raw pointer to the fixed 0xb8000 address, dereferenced only
/// inside `&mut self` methods behind this mutex. A first-access lazy init path
/// hung the boot sequence elsewhere, so the const static is the safer choice.
pub static WRITER: Mutex<Writer> = Mutex::new(Writer::new());

/// The standard color palette in VGA text mode.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Color {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    Pink = 13,
    Yellow = 14,
    White = 15,
}

/// A combination of a foreground and a background color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)] // ensures that ColorCode has the exact same data layout as u8
struct ColorCode(u8);

impl ColorCode {
    /// Create a new `ColorCode` with the given foreground and background colors.
    const fn new(foreground: Color, background: Color) -> ColorCode {
        ColorCode((background as u8) << 4 | (foreground as u8))
    }
}

/// A screen character in the VGA text buffer, consisting of an ASCII character and a `ColorCode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct ScreenChar {
    ascii_character: u8,
    color_code: ColorCode,
}

/// The height of the text buffer (normally 25 lines).
const BUFFER_HEIGHT: usize = 25;
/// The width of the text buffer (normally 80 columns).
const BUFFER_WIDTH: usize = 80;

/// A structure representing the VGA text buffer.
#[repr(transparent)]
struct Buffer {
    chars: [[Volatile<ScreenChar>; BUFFER_WIDTH]; BUFFER_HEIGHT],
}

/// A writer type that allows writing ASCII bytes and strings to an underlying `Buffer`.
///
/// Wraps lines at `BUFFER_WIDTH`. Supports newline characters and implements the
/// `core::fmt::Write` trait.
pub struct Writer {
    column_position: usize,
    color_code: ColorCode,
    // raw pointer to the fixed vga buffer rather than &'static mut, so Writer
    // is const-constructible. it is only dereferenced inside &mut self methods
    // (behind the WRITER mutex), so no aliasing &mut ever exists.
    buffer: *mut Buffer,
}

// SAFETY: the buffer pointer targets the fixed mmio address 0xb8000, which is
// not thread-local and is always valid on this platform. all access goes
// through the WRITER mutex, so Writer can be shared across cores safely.
unsafe impl Send for Writer {}

impl Writer {
    /// Creates a writer for the VGA text buffer at its fixed address.
    const fn new() -> Writer {
        Writer {
            column_position: 0,
            color_code: ColorCode::new(Color::Yellow, Color::Black),
            buffer: 0xb8000 as *mut Buffer,
        }
    }

    // borrows the vga buffer mutably for the duration of a write.
    fn buffer(&mut self) -> &mut Buffer {
        // SAFETY: buffer points at the fixed, identity-mapped vga mmio region,
        // live under the multiboot/grub bios path. &mut self plus the WRITER
        // mutex guarantee this is the only live reference to it.
        unsafe { &mut *self.buffer }
    }

    /// Writes an ASCII byte to the buffer.
    ///
    /// Wraps lines at `BUFFER_WIDTH`. Supports the `\n` newline character.
    pub fn write_byte(&mut self, byte: u8) {
        match byte {
            b'\n' => self.new_line(),
            byte => {
                if self.column_position >= BUFFER_WIDTH {
                    self.new_line();
                }

                let row = BUFFER_HEIGHT - 1;
                let col = self.column_position;

                let color_code = self.color_code;
                self.buffer().chars[row][col].write(ScreenChar {
                    ascii_character: byte,
                    color_code,
                });
                self.column_position += 1;
            }
        }
    }

    /// Writes the given ASCII string to the buffer.
    ///
    /// Wraps lines at `BUFFER_WIDTH`. Supports the `\n` newline character. Does **not**
    /// support strings with non-ASCII characters, since they can't be printed in the VGA text
    /// mode.
    fn write_string(&mut self, s: &str) {
        for byte in s.bytes() {
            match byte {
                // printable ASCII byte or newline
                0x20..=0x7e | b'\n' => self.write_byte(byte),
                // not part of printable ASCII range
                _ => self.write_byte(0xfe),
            }
        }
    }

    /// Shifts all lines one line up and clears the last row.
    fn new_line(&mut self) {
        for row in 1..BUFFER_HEIGHT {
            for col in 0..BUFFER_WIDTH {
                let character = self.buffer().chars[row][col].read();
                self.buffer().chars[row - 1][col].write(character);
            }
        }
        self.clear_row(BUFFER_HEIGHT - 1);
        self.column_position = 0;
    }

    /// Clears a row by overwriting it with blank characters.
    fn clear_row(&mut self, row: usize) {
        let blank = ScreenChar {
            ascii_character: b' ',
            color_code: self.color_code,
        };
        for col in 0..BUFFER_WIDTH {
            self.buffer().chars[row][col].write(blank);
        }
    }
}

impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_string(s);
        Ok(())
    }
}

/// Like the `print!` macro in the standard library, but prints to the VGA text buffer.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::vga_buffer::_print(format_args!($($arg)*)));
}

/// Like the `println!` macro in the standard library, but prints to the VGA text buffer.
#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

/// Prints the given formatted string to the VGA text buffer through the global `WRITER` instance.
#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    use x86_64::instructions::interrupts;
    // hold the WRITER lock with interrupts disabled so an interrupt handler
    // that also prints cannot deadlock against an in-progress print. see the
    // same guard in serial::_print for the full rationale.
    interrupts::without_interrupts(|| {
        WRITER.lock().write_fmt(args).unwrap();
    });
}

// pub fn print_something() {
//     // before implementing the above macros
//     let mut writer = Writer {
//         column_position: 0,
//         color_code: ColorCode::new(Color::Yellow, Color::Black),
//         buffer: unsafe { &mut *(0xb8000 as *mut Buffer) },
//     };
//     writer.write_byte(b'H');
//     writer.write_string("ello, world!");
//     writer.write_string("Wörld!"); // non-ASCII character

//     // after implementing the above macros
//     println!("Hello, world!");
// }

// tests

// printing far more lines than the buffer is tall must scroll without panicking
// AND leave the most recent line readable at the bottom. the bare "call println!
// 200 times and assert nothing" version could not catch a scroll that corrupted
// or blanked the visible line, so read the last written line back and check it.
#[test_case]
fn test_println_scrolls_and_keeps_last_line() {
    use core::fmt::Write;
    use x86_64::instructions::interrupts;

    // more than BUFFER_HEIGHT lines, so the buffer scrolls many times over.
    let last = "final line after scrolling";
    interrupts::without_interrupts(|| {
        let mut writer = WRITER.lock();
        for i in 0..BUFFER_HEIGHT * 3 {
            writeln!(writer, "filler line {i}").expect("writeln failed");
        }
        // the last line printed lands on the row above the (blank) cursor row.
        writeln!(writer, "{last}").expect("writeln failed");
        for (i, c) in last.chars().enumerate() {
            let screen_char = writer.buffer().chars[BUFFER_HEIGHT - 2][i].read();
            assert_eq!(char::from(screen_char.ascii_character), c);
        }
    });
}

#[test_case]
fn test_println_output() {
    use core::fmt::Write;
    use x86_64::instructions::interrupts;

    let s = "Some test string that fits on a single line";
    // hold the lock across the whole write-then-read so a timer interrupt
    // cannot print between writing the line and checking the buffer (which
    // would scroll our line away). write via the locked writer directly rather
    // than println! (which would try to lock again and deadlock).
    interrupts::without_interrupts(|| {
        let mut writer = WRITER.lock();
        writeln!(writer, "\n{s}").expect("writeln failed");
        for (i, c) in s.chars().enumerate() {
            let screen_char = writer.buffer().chars[BUFFER_HEIGHT - 2][i].read();
            assert_eq!(char::from(screen_char.ascii_character), c);
        }
    });
}
