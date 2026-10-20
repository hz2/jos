//! Scripted console sessions: `jig expect SCRIPT`.
//!
//! A script drives the root task's shell over the serial console, the way a
//! person would, and checks what it prints:
//!
//! ```text
//! # a comment
//! < jos>          wait until the output, from where the last wait matched, holds "jos>"
//! > echo hi       type "echo hi" and press Enter
//! > ab\bc         keys too: \b backspace, \u Ctrl-U, \c Ctrl-C, \e escape, \\ a backslash
//! < hi
//! > halt 0
//! ```
//!
//! A run passes when every wait matched before its deadline and the machine
//! then stopped with success, so a script ends by halting it.

use std::io::{Read as _, Write as _};
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::run::{Image, Machine};

/// One line of a script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Type this text, then Enter.
    Send(String),
    /// Wait until the output holds this text.
    Expect(String),
}

/// Reads a script: `> text` and `< text` lines, with `#` comments and blank
/// lines skipped. Returns each step with its line number.
///
/// # Errors
///
/// The line number and text of the first line that is neither.
pub fn parse(script: &str) -> Result<Vec<(usize, Step)>, String> {
    let mut steps = Vec::new();
    for (index, raw) in script.lines().enumerate() {
        let line = raw.trim_end();
        let number = index + 1;
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let step = if let Some(text) = line.strip_prefix("> ") {
            Step::Send(unescape(text))
        } else if let Some(text) = line.strip_prefix("< ") {
            Step::Expect(text.to_string())
        } else {
            return Err(format!("line {number}: expected `> text` or `< text`, got {line:?}"));
        };
        steps.push((number, step));
    }
    Ok(steps)
}

/// Turns the escapes a `>` line may use into the keys they stand for: `\b`
/// backspace (DEL), `\u` Ctrl-U, `\c` Ctrl-C, `\e` escape, `\\` a backslash.
/// Any other backslash is kept as it is.
fn unescape(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('b') => out.push('\x7f'),
            Some('u') => out.push('\x15'),
            Some('c') => out.push('\x03'),
            Some('e') => out.push('\x1b'),
            // an escaped backslash, or one that ends the line.
            Some('\\') | None => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    out
}

/// What the guest has printed so far, shared with the thread that reads it.
#[derive(Default)]
struct Output {
    /// Every byte so far.
    bytes: Vec<u8>,
    /// The guest's output has ended: qemu exited.
    ended: bool,
}

/// How a session ended.
pub struct Session {
    /// The first step that failed, with its line number and why, or `None`.
    pub failure: Option<(usize, String)>,
    /// Everything the guest printed.
    pub transcript: String,
    /// The runner's exit code, if it exited.
    pub code: Option<i32>,
    /// How long it took.
    pub duration: Duration,
}

impl Session {
    /// Whether every step passed and the machine stopped with success.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.failure.is_none() && self.code == Some(0)
    }
}

/// Returns where `needle` starts in `haystack`, if it occurs.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// Boots `image` on `machine` with the console on a pipe and runs `steps`,
/// giving each wait `step_timeout`.
#[must_use]
pub fn run(repo: &std::path::Path, image: &Image, machine: &Machine, steps: &[(usize, Step)], step_timeout: Duration) -> Session {
    let start = Instant::now();
    let mut command = Command::new("bash");
    // stderr joins stdout, so the transcript keeps the runner's messages in order.
    command
        .args(["-c", "exec \"$0\" \"$1\" 2>&1"])
        .arg(repo.join("scripts/run-qemu.sh"))
        .arg(&image.kernel)
        .current_dir(repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // a group of its own, so stopping a failed session stops qemu too.
        .process_group(0);
    if let Some(modules) = &image.modules {
        command.env("JOS_MODULES", modules);
    }
    for (name, value) in machine.env() {
        command.env(name, value);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            return Session {
                failure: Some((0, format!("cannot run the qemu runner: {e}"))),
                transcript: String::new(),
                code: None,
                duration: start.elapsed(),
            };
        }
    };
    let output = Arc::new((Mutex::new(Output::default()), Condvar::new()));
    let reader = child.stdout.take().map(|mut stdout| {
        let output = Arc::clone(&output);
        std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            loop {
                let read = stdout.read(&mut chunk).unwrap_or(0);
                let (lock, changed) = &*output;
                let Ok(mut state) = lock.lock() else { return };
                if read == 0 {
                    state.ended = true;
                    changed.notify_all();
                    return;
                }
                state.bytes.extend_from_slice(&chunk[..read]);
                changed.notify_all();
            }
        })
    });
    let failure = drive(&mut child, &output, steps, step_timeout);
    let code = finish(&mut child, failure.is_none(), step_timeout);
    if let Some(reader) = reader {
        let _ = reader.join();
    }
    let transcript = output.0.lock().map(|state| String::from_utf8_lossy(&state.bytes).into_owned()).unwrap_or_default();
    Session { failure, transcript, code, duration: start.elapsed() }
}

/// Runs the steps against the live guest; returns the first failure.
fn drive(
    child: &mut Child,
    output: &(Mutex<Output>, Condvar),
    steps: &[(usize, Step)],
    step_timeout: Duration,
) -> Option<(usize, String)> {
    let mut stdin = child.stdin.take()?;
    let mut cursor = 0;
    for (number, step) in steps {
        match step {
            Step::Send(text) => {
                let typed = format!("{text}\r");
                if stdin.write_all(typed.as_bytes()).and_then(|()| stdin.flush()).is_err() {
                    return Some((*number, format!("could not type {text:?}: the guest is gone")));
                }
            }
            Step::Expect(text) => {
                let (lock, changed) = output;
                let deadline = Instant::now() + step_timeout;
                let Ok(mut state) = lock.lock() else {
                    return Some((*number, "the output lock was poisoned".into()));
                };
                loop {
                    if let Some(at) = find(&state.bytes[cursor..], text.as_bytes()) {
                        cursor += at + text.len();
                        break;
                    }
                    let now = Instant::now();
                    if state.ended || now >= deadline {
                        let why = if state.ended { "the guest stopped" } else { "timed out" };
                        return Some((*number, format!("{why} waiting for {text:?}")));
                    }
                    let Ok((next, _)) = changed.wait_timeout(state, deadline - now) else {
                        return Some((*number, "the output lock was poisoned".into()));
                    };
                    state = next;
                }
            }
        }
    }
    // stdin closes here; a script that halted the machine has nothing more to say.
    None
}

/// Waits for the runner to exit, up to `timeout` if the script passed, and
/// stops its whole process group otherwise; returns its exit code.
fn finish(child: &mut Child, passed: bool, timeout: Duration) -> Option<i32> {
    let deadline = Instant::now() + if passed { timeout } else { Duration::ZERO };
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return status.code();
        }
        if Instant::now() >= deadline {
            // the group's id is the runner's pid; qemu is in it, as its child.
            let group = format!("-{}", child.id());
            let _ = Command::new("kill").args(["-KILL", "--", &group]).status();
            return child.wait().ok().and_then(|status| status.code());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use super::{Step, find, parse};

    #[test]
    fn scripts_read_sends_waits_and_comments() {
        let steps = parse("# boot\n< jos>\n\n> echo hi\n< hi\n").unwrap();
        assert_eq!(steps, [(2, Step::Expect("jos>".into())), (4, Step::Send("echo hi".into())), (5, Step::Expect("hi".into()))]);
        assert!(parse("echo hi\n").unwrap_err().starts_with("line 1"));
    }

    #[test]
    fn sends_turn_escapes_into_keys() {
        let steps = parse("> ab\\b\\u\\c\\e[A\\\\\\q\n").unwrap();
        assert_eq!(steps, [(1, Step::Send("ab\x7f\x15\x03\x1b[A\\\\q".into()))]);
    }

    #[test]
    fn find_locates_text_in_bytes() {
        assert_eq!(find(b"jos> help", b"help"), Some(5));
        assert_eq!(find(b"jos>", b"nope"), None);
        assert_eq!(find(b"", b""), Some(0));
    }
}
