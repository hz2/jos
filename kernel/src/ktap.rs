//! KTAP output for kernel tests: the line format the host harness parses.
//!
//! A test binary prints a header and a plan, then for each test a `# run`
//! line (so a harness can name the test that was running if the guest dies)
//! and one `ok N name` or `not ok N name` line; diagnostics are lines that
//! start with `#`. Framework tests (`#[test_case]`) report through
//! [`crate::test_runner`]. A binary that checks one thing calls [`single`]
//! once, and [`crate::exit_qemu`] reports its result when the run ends,
//! whichever path ends it: the ring-3 `exit` probe, a fault handler, or a
//! panic.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use spin::Mutex;

/// The name of the test running now: the registered single test, or the
/// framework test [`begin`] last announced.
static CURRENT: Mutex<Option<&'static str>> = Mutex::new(None);

/// The number of the test running now, counting from 1.
static INDEX: AtomicUsize = AtomicUsize::new(0);

/// Set when the binary checks one thing, so the exit reports it.
static SINGLE: AtomicBool = AtomicBool::new(false);

/// Prints the KTAP header and the plan for `count` tests.
pub fn plan(count: usize) {
    crate::serial_println!("KTAP version 1");
    crate::serial_println!("1..{}", count);
}

/// Announces test `index` (counting from 1), named `name`, about to run.
pub fn begin(index: usize, name: &'static str) {
    INDEX.store(index, Ordering::Relaxed);
    *CURRENT.lock() = Some(name);
    crate::serial_println!("# run {}", name);
}

/// Reports the test [`begin`] last announced as passed.
pub fn pass() {
    // released before printing, so a panic while printing cannot spin in fail().
    let name = CURRENT.lock().take();
    if let Some(name) = name {
        crate::serial_println!("ok {} {}", INDEX.load(Ordering::Relaxed), name);
    }
}

/// Reports the test running now, if any, as failed. It reports each test once.
pub fn fail() {
    let name = CURRENT.lock().take();
    if let Some(name) = name {
        crate::serial_println!("not ok {} {}", INDEX.load(Ordering::Relaxed), name);
    }
}

/// Starts a binary that checks one thing, named `name`: prints the header,
/// the plan of one test, and its run line. The exit reports the result.
pub fn single(name: &'static str) {
    SINGLE.store(true, Ordering::Relaxed);
    plan(1);
    begin(1, name);
}

/// Reports the result a run ends with, for a binary that checks one thing;
/// called by [`crate::exit_qemu`]. A second call reports nothing.
pub fn finish_single(passed: bool) {
    if SINGLE.load(Ordering::Relaxed) {
        if passed { pass() } else { fail() }
    }
}

/// Prints `args` as KTAP diagnostics: every line starts with `# `.
pub fn diag(args: core::fmt::Arguments) {
    use core::fmt::Write;

    /// Writes through to the serial port, starting each line with `# `.
    struct Diag {
        /// Whether the next byte starts a line.
        at_line_start: bool,
    }

    impl Write for Diag {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            for line in s.split_inclusive('\n') {
                if self.at_line_start {
                    crate::serial_print!("# ");
                }
                crate::serial_print!("{}", line);
                self.at_line_start = line.ends_with('\n');
            }
            Ok(())
        }
    }

    let mut out = Diag { at_line_start: true };
    let _ = out.write_fmt(args);
    if !out.at_line_start {
        crate::serial_println!();
    }
}
