//! Finding the images to boot, and booting them.
//!
//! An image is a kernel binary plus the boot modules it gets. Each boot goes
//! through `scripts/run-qemu.sh`, the one place that knows how to build an ISO
//! and start qemu, with its environment variables picking the machine. The
//! runner builds a fresh ISO directory per run, so boots can run in parallel.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::ktap::{self, Report};

/// A kernel binary to boot, with its boot modules.
#[derive(Clone, Debug)]
pub struct Image {
    /// The name reports use: a test binary's name, or `boot`.
    pub name: String,
    /// The kernel ELF.
    pub kernel: PathBuf,
    /// The `JOS_MODULES` value: `None` boots without modules.
    pub modules: Option<String>,
    /// A command that reproduces this boot by itself.
    pub reproduce: String,
}

/// The machine qemu emulates: the runner's variables, `None` for its default.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Machine {
    /// `JOS_QEMU_ACCEL`: `tcg` or `kvm`.
    pub accel: Option<String>,
    /// `JOS_QEMU_CPU`.
    pub cpu: Option<String>,
    /// `JOS_QEMU_MEM`.
    pub mem: Option<String>,
    /// `JOS_QEMU_SMP`.
    pub smp: Option<String>,
    /// `JOS_QEMU_MACHINE`.
    pub kind: Option<String>,
    /// `JOS_QEMU_TIMEOUT`, in seconds.
    pub timeout: Option<u64>,
}

impl Machine {
    /// The runner variables this machine sets.
    pub(crate) fn env(&self) -> Vec<(&'static str, String)> {
        let mut env = Vec::new();
        let fields = [
            ("JOS_QEMU_ACCEL", &self.accel),
            ("JOS_QEMU_CPU", &self.cpu),
            ("JOS_QEMU_MEM", &self.mem),
            ("JOS_QEMU_SMP", &self.smp),
            ("JOS_QEMU_MACHINE", &self.kind),
        ];
        for (name, value) in fields {
            if let Some(value) = value {
                env.push((name, value.clone()));
            }
        }
        if let Some(timeout) = self.timeout {
            env.push(("JOS_QEMU_TIMEOUT", timeout.to_string()));
        }
        env
    }

    /// The machine in a few words, for reports: only what differs from the
    /// runner's defaults.
    #[must_use]
    pub fn describe(&self) -> String {
        let parts: Vec<&str> = [&self.accel, &self.cpu, &self.mem, &self.smp, &self.kind]
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect();
        if parts.is_empty() { "default".into() } else { parts.join(" ") }
    }

    /// The variables to put before a reproduce command.
    #[must_use]
    pub fn env_prefix(&self) -> String {
        let mut prefix = String::new();
        for (name, value) in self.env() {
            let _ = write!(prefix, "{name}={value} ");
        }
        prefix
    }
}

/// How a boot ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// The guest reported success and its KTAP agrees.
    Passed,
    /// The guest reported failure, with the runner's exit code.
    Failed(i32),
    /// The guest ran out of time.
    TimedOut,
    /// The exit code and the KTAP disagree (or there was no KTAP).
    Inconsistent(String),
}

/// One finished boot.
#[derive(Debug)]
pub struct Outcome {
    /// What was booted.
    pub image: Image,
    /// On what machine.
    pub machine: Machine,
    /// How it ended.
    pub status: Status,
    /// Its parsed KTAP.
    pub report: Report,
    /// Its whole serial log.
    pub output: String,
    /// Where the log was saved.
    pub log: PathBuf,
    /// How long it took.
    pub duration: Duration,
}

impl Outcome {
    /// Whether the boot passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.status == Status::Passed
    }
}

/// Builds the kernel test binaries and returns one image per binary, in
/// cargo's order.
///
/// # Errors
///
/// The cargo error output, if the build fails.
pub fn discover_tests(repo: &Path, target: &Path) -> Result<Vec<Image>, String> {
    let output = Command::new("cargo")
        .args(["test", "--no-run", "--all-targets"])
        .current_dir(repo.join("kernel"))
        .env("CARGO_TARGET_DIR", target)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run cargo: {e}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(stderr.into_owned());
    }
    Ok(stderr.lines().filter_map(executable).collect())
}

/// Reads a cargo `Executable what (path)` line into an image.
fn executable(line: &str) -> Option<Image> {
    let rest = line.trim().strip_prefix("Executable ")?;
    let (what, path) = rest.rsplit_once(" (")?;
    let path = path.strip_suffix(')')?;
    let (name, reproduce) = if what.ends_with("src/lib.rs") {
        ("lib".to_string(), "(cd kernel && cargo test --lib)".to_string())
    } else if what.ends_with("src/main.rs") {
        ("bin".to_string(), "(cd kernel && cargo test --bin jos)".to_string())
    } else {
        let file = what.strip_prefix("tests/")?.strip_suffix(".rs")?;
        (file.to_string(), format!("scripts/check.sh qemu {file}"))
    };
    Some(Image { name, kernel: PathBuf::from(path), modules: Some(String::new()), reproduce })
}

/// Builds the kernel binary and the user workspace, and returns the image
/// that boots the root task with `args` after its name, and the programs it
/// starts as processes as modules beside it.
///
/// # Errors
///
/// The cargo error output, if a build fails.
pub fn root_image(repo: &Path, target: &Path, args: &str) -> Result<Image, String> {
    let user_target = target.join("user");
    for (dir, target_dir) in [("kernel", target), ("user", user_target.as_path())] {
        let output = Command::new("cargo")
            .arg("build")
            .current_dir(repo.join(dir))
            .env("CARGO_TARGET_DIR", target_dir)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("cannot run cargo: {e}"))?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned());
        }
    }
    let bin = user_target.join("x86_64-unknown-none/debug");
    Ok(Image {
        name: "boot".into(),
        kernel: target.join("x86_64-jos/debug/jos"),
        modules: Some(format!("{} root {args};{} hello", bin.join("root").display(), bin.join("hello").display())),
        reproduce: format!("JOS_ROOT_ARGS='{args}' scripts/check.sh boot"),
    })
}

/// Boots `image` on `machine` and waits for it, saving the serial log under
/// `log_dir`; `round` tells repeated boots of one image apart.
#[must_use]
pub fn boot(repo: &Path, image: Image, machine: Machine, round: usize, log_dir: &Path) -> Outcome {
    let start = Instant::now();
    let mut command = Command::new("bash");
    // stderr joins stdout, so the log keeps the runner's messages in order.
    command
        .args(["-c", "exec \"$0\" \"$1\" 2>&1"])
        .arg(repo.join("scripts/run-qemu.sh"))
        .arg(&image.kernel)
        .current_dir(repo)
        .stdin(Stdio::null());
    if let Some(modules) = &image.modules {
        command.env("JOS_MODULES", modules);
    }
    for (name, value) in machine.env() {
        command.env(name, value);
    }
    let (code, output) = match command.output() {
        Ok(out) => (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned()),
        Err(e) => (-1, format!("jig: cannot run the qemu runner: {e}\n")),
    };
    let report = ktap::parse(&output);
    let status = match code {
        0 => match report.problem() {
            None => Status::Passed,
            Some(problem) => Status::Inconsistent(problem),
        },
        124 | 137 => Status::TimedOut,
        code => Status::Failed(code),
    };
    let mut label = format!("{}-{}", image.name, machine.describe().replace(' ', "-"));
    if round > 0 {
        let _ = write!(label, "-{round}");
    }
    let log = log_dir.join(format!("{label}.log"));
    let _ = std::fs::write(&log, &output);
    Outcome { image, machine, status, report, output, log, duration: start.elapsed() }
}

#[cfg(test)]
mod tests {
    use super::{Machine, executable};

    #[test]
    fn cargo_executable_lines_become_images() {
        let test = executable("  Executable tests/badged_ipc.rs (/t/x86_64-jos/debug/deps/badged_ipc-0a1b)").unwrap();
        assert_eq!(test.name, "badged_ipc");
        assert_eq!(test.kernel.to_str(), Some("/t/x86_64-jos/debug/deps/badged_ipc-0a1b"));
        assert_eq!(test.reproduce, "scripts/check.sh qemu badged_ipc");
        let lib = executable("  Executable unittests src/lib.rs (/t/deps/jos-1)").unwrap();
        assert_eq!(lib.name, "lib");
        assert_eq!(executable("   Compiling jos v0.1.0").map(|i| i.name), None);
    }

    #[test]
    fn machines_describe_only_what_they_set() {
        assert_eq!(Machine::default().describe(), "default");
        let kvm = Machine { accel: Some("kvm".into()), mem: Some("4G".into()), ..Machine::default() };
        assert_eq!(kvm.describe(), "kvm 4G");
        assert_eq!(kvm.env_prefix(), "JOS_QEMU_ACCEL=kvm JOS_QEMU_MEM=4G ");
    }
}
