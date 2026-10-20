//! jig: the host side of jos testing.
//!
//! ```text
//! jig test [FILTER...] [--exact] [--jobs N] [--repeat N] [--junit FILE] [machine flags]
//! jig boot [--args "test"] [--matrix | --matrix-small] [--jobs N] [--junit FILE] [machine flags]
//! jig ktap FILE
//! machine flags: --accel tcg|kvm --cpu MODEL --mem SIZE --smp N --machine TYPE --timeout SECS
//! ```
//!
//! `test` boots every kernel test image (or the ones whose name contains a
//! filter) in parallel, `boot` the real kernel with the root task (across a
//! machine matrix if asked), and both parse each guest's KTAP and print a line
//! per boot, then a summary; a failure gets the end of its log and a command
//! that reproduces it. Logs are kept under `<target>/jig/`. `ktap` parses a
//! saved log. The exit code is 0 only if every boot passed.
#![warn(clippy::pedantic)]

mod ktap;
mod run;

use std::fmt::Write as _;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use run::{Image, Machine, Outcome, Status};

/// The options every command shares.
#[derive(Default)]
struct Options {
    /// Name filters (`test`).
    filters: Vec<String>,
    /// Match filters exactly instead of as substrings.
    exact: bool,
    /// Boots at once.
    jobs: Option<usize>,
    /// Runs of each image (`test`), to hunt flaky tests.
    repeat: usize,
    /// Where to write `JUnit` XML.
    junit: Option<PathBuf>,
    /// The machine for every boot.
    machine: Machine,
    /// The root task's arguments (`boot`).
    args: String,
    /// Boot across the full machine matrix (`boot`).
    matrix: bool,
    /// Boot across the small machine matrix (`boot`).
    matrix_small: bool,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("test") => parse_options(&args[1..]).map_or_else(|e| usage(&e), |o| test(&o)),
        Some("boot") => parse_options(&args[1..]).map_or_else(|e| usage(&e), |o| boot(&o)),
        Some("ktap") if args.len() == 2 => ktap_file(Path::new(&args[1])),
        _ => usage(""),
    };
    std::process::exit(code);
}

/// Prints the usage, after `problem` if there is one, and returns exit code 2.
fn usage(problem: &str) -> i32 {
    if !problem.is_empty() {
        eprintln!("jig: {problem}");
    }
    eprintln!("usage: jig test [FILTER...] [--exact] [--jobs N] [--repeat N] [--junit FILE] [machine flags]");
    eprintln!("       jig boot [--args ARGS] [--matrix | --matrix-small] [--jobs N] [--junit FILE] [machine flags]");
    eprintln!("       jig ktap FILE");
    eprintln!("machine flags: --accel tcg|kvm --cpu MODEL --mem SIZE --smp N --machine TYPE --timeout SECS");
    2
}

/// Reads the flags after a command.
fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut options = Options { repeat: 1, args: "test".into(), ..Options::default() };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let mut value = || iter.next().cloned().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--exact" => options.exact = true,
            "--matrix" => options.matrix = true,
            "--matrix-small" => options.matrix_small = true,
            "--jobs" => options.jobs = Some(value()?.parse().map_err(|_| "--jobs takes a number")?),
            "--repeat" => options.repeat = value()?.parse().map_err(|_| "--repeat takes a number")?,
            "--junit" => options.junit = Some(PathBuf::from(value()?)),
            "--args" => options.args = value()?,
            "--accel" => options.machine.accel = Some(value()?),
            "--cpu" => options.machine.cpu = Some(value()?),
            "--mem" => options.machine.mem = Some(value()?),
            "--smp" => options.machine.smp = Some(value()?),
            "--machine" => options.machine.kind = Some(value()?),
            "--timeout" => options.machine.timeout = Some(value()?.parse().map_err(|_| "--timeout takes seconds")?),
            flag if flag.starts_with("--") => return Err(format!("unknown flag {flag}")),
            filter => options.filters.push(filter.to_string()),
        }
    }
    Ok(options)
}

/// The repository root: jig lives in `tools/jig`.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The cargo target directory the kernel builds into.
fn target_dir(repo: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| repo.join("target"), PathBuf::from)
}

/// A fresh directory for this run's logs.
fn log_dir(target: &Path) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let dir = target.join("jig").join(format!("run-{stamp}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Returns false, after saying which, if a tool the runner needs is not on
/// `PATH`: they come with the dev shell.
fn tools_present() -> bool {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let missing = ["qemu-system-x86_64", "grub-mkrescue", "xorriso"]
        .into_iter()
        .find(|tool| !std::env::split_paths(&path).any(|dir| dir.join(tool).is_file()));
    if let Some(tool) = missing {
        eprintln!("jig: {tool} not found: run jig inside the dev shell (nix develop), or through scripts/check.sh");
    }
    missing.is_none()
}

/// `jig test`: every kernel test image, or the ones the filters pick.
fn test(options: &Options) -> i32 {
    if !tools_present() {
        return 1;
    }
    let repo = repo_root();
    let target = target_dir(&repo);
    eprintln!("jig: building the kernel tests");
    let images = match run::discover_tests(&repo, &target) {
        Ok(images) => images,
        Err(e) => {
            eprintln!("{e}\njig: the build failed");
            return 1;
        }
    };
    let picked: Vec<Image> = images
        .into_iter()
        .filter(|image| {
            options.filters.is_empty()
                || options.filters.iter().any(|f| if options.exact { &image.name == f } else { image.name.contains(f.as_str()) })
        })
        .collect();
    if picked.is_empty() {
        eprintln!("jig: no test matches {:?}", options.filters);
        return 1;
    }
    let mut jobs = Vec::new();
    for round in 0..options.repeat.max(1) {
        jobs.extend(picked.iter().map(|image| (image.clone(), options.machine.clone(), round)));
    }
    run_all(&repo, &target, jobs, options)
}

/// `jig boot`: the real kernel with the root task, on one machine or a matrix.
fn boot(options: &Options) -> i32 {
    if !tools_present() {
        return 1;
    }
    let repo = repo_root();
    let target = target_dir(&repo);
    eprintln!("jig: building the kernel and the root task");
    let image = match run::root_image(&repo, &target, &options.args) {
        Ok(image) => image,
        Err(e) => {
            eprintln!("{e}\njig: the build failed");
            return 1;
        }
    };
    let machines = if options.matrix || options.matrix_small {
        matrix(options.matrix_small, &options.machine)
    } else {
        vec![options.machine.clone()]
    };
    let jobs = machines.into_iter().map(|machine| (image.clone(), machine, 0)).collect();
    run_all(&repo, &target, jobs, options)
}

/// The machines `boot --matrix` covers: cpu models with and without SMEP and
/// SMAP, memory from small to past the identity map, one and several cpus,
/// both machine types; plus the host cpu under KVM when it is usable. The
/// small matrix is a handful of the most different ones.
fn matrix(small: bool, base: &Machine) -> Vec<Machine> {
    let make = |accel: &str, cpu: &str, mem: &str, smp: &str, machine: &str| Machine {
        accel: Some(accel.into()),
        cpu: Some(cpu.into()),
        mem: Some(mem.into()),
        smp: Some(smp.into()),
        kind: Some(machine.into()),
        timeout: base.timeout,
    };
    let kvm = std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").is_ok();
    let mut machines = Vec::new();
    if small {
        machines.push(make("tcg", "max", "128M", "1", "q35"));
        machines.push(make("tcg", "qemu64", "64M", "1", "pc"));
        machines.push(make("tcg", "max", "4G", "4", "q35"));
        if kvm {
            machines.push(make("kvm", "host", "1G", "2", "q35"));
        }
        return machines;
    }
    for cpu in ["max", "qemu64"] {
        for mem in ["64M", "128M", "1G", "4G"] {
            for smp in ["1", "4"] {
                for machine in ["q35", "pc"] {
                    machines.push(make("tcg", cpu, mem, smp, machine));
                }
            }
        }
    }
    if kvm {
        for mem in ["128M", "4G"] {
            for smp in ["1", "4"] {
                machines.push(make("kvm", "host", mem, smp, "q35"));
            }
        }
    }
    machines
}

/// Boots every job (an image, a machine, and which round of `--repeat` it
/// is) on a pool of workers, prints a line as each finishes, then the
/// summary; writes `JUnit` XML if asked. Returns the exit code.
fn run_all(repo: &Path, target: &Path, jobs: Vec<(Image, Machine, usize)>, options: &Options) -> i32 {
    let total = jobs.len();
    let workers = options.jobs.unwrap_or_else(default_jobs).clamp(1, total.max(1));
    let logs = log_dir(target);
    let start = Instant::now();
    eprintln!("jig: {total} boots on {workers} workers, logs in {}", logs.display());
    let queue = Arc::new(Mutex::new(jobs));
    let (done, finished) = mpsc::channel();
    let mut handles = Vec::new();
    for _ in 0..workers {
        let (queue, done, repo, logs) = (Arc::clone(&queue), done.clone(), repo.to_path_buf(), logs.clone());
        handles.push(std::thread::spawn(move || {
            while let Some((image, machine, round)) = queue.lock().ok().and_then(|mut q| q.pop()) {
                if done.send(run::boot(&repo, image, machine, round, &logs)).is_err() {
                    break;
                }
            }
        }));
    }
    drop(done);
    let color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let mut outcomes = Vec::new();
    for outcome in finished {
        println!("{}", line(&outcome, color));
        outcomes.push(outcome);
    }
    for handle in handles {
        let _ = handle.join();
    }
    outcomes.sort_by(|a, b| a.image.name.cmp(&b.image.name).then(a.machine.describe().cmp(&b.machine.describe())));
    let failed: Vec<&Outcome> = outcomes.iter().filter(|o| !o.passed()).collect();
    for outcome in &failed {
        print!("{}", failure_detail(outcome));
    }
    let checks: usize = outcomes.iter().map(|o| o.report.top().count()).sum();
    println!(
        "jig: {} of {} boots passed ({} checks) in {:.1}s",
        total - failed.len(),
        total,
        checks,
        start.elapsed().as_secs_f64()
    );
    if let Some(path) = &options.junit {
        match std::fs::write(path, junit(&outcomes)) {
            Ok(()) => println!("jig: JUnit report in {}", path.display()),
            Err(e) => eprintln!("jig: cannot write {}: {e}", path.display()),
        }
    }
    i32::from(!failed.is_empty())
}

/// Half the cores, so tcg guests do not starve each other, at least one and
/// at most eight.
fn default_jobs() -> usize {
    std::thread::available_parallelism().map_or(1, |n| (n.get() / 2).clamp(1, 8))
}

/// The one-line report of a finished boot.
fn line(outcome: &Outcome, color: bool) -> String {
    let (word, paint) = match &outcome.status {
        Status::Passed => ("PASS", "32"),
        Status::Failed(_) | Status::Inconsistent(_) => ("FAIL", "31"),
        Status::TimedOut => ("TIME", "33"),
    };
    let word = if color { format!("\x1b[{paint}m{word}\x1b[0m") } else { word.to_string() };
    let planned = outcome.report.plan.unwrap_or_else(|| outcome.report.top().count());
    let detail = match &outcome.status {
        Status::Passed => String::new(),
        Status::Failed(code) => format!("  exit {code}"),
        Status::TimedOut => "  timed out".into(),
        Status::Inconsistent(why) => format!("  {why}"),
    };
    format!(
        "{word} {:<36} {:>3}/{:<3} {:>6.1}s  {}{detail}",
        outcome.image.name,
        outcome.report.passed(),
        planned,
        outcome.duration.as_secs_f64(),
        outcome.machine.describe()
    )
}

/// What a failed boot reported, the end of its log, and how to rerun it.
fn failure_detail(outcome: &Outcome) -> String {
    let mut text = String::new();
    let _ = writeln!(text, "\n--- {} ({}) ---", outcome.image.name, outcome.machine.describe());
    if let Some(problem) = outcome.report.problem() {
        let _ = writeln!(text, "ktap: {problem}");
    }
    for result in outcome.report.top().filter(|r| !r.ok) {
        let _ = writeln!(text, "not ok {} {}", result.index, result.name);
        for diagnostic in &result.diagnostics {
            let _ = writeln!(text, "    # {diagnostic}");
        }
    }
    if let Some(running) = &outcome.report.running {
        let _ = writeln!(text, "running when it stopped: {running}");
    }
    let tail = tail(&outcome.output);
    let _ = writeln!(text, "last {} log lines:", tail.len());
    for line in tail {
        let _ = writeln!(text, "    {line}");
    }
    let _ = writeln!(text, "log: {}", outcome.log.display());
    let _ = writeln!(text, "reproduce: {}{}", outcome.machine.env_prefix(), outcome.image.reproduce);
    text
}

/// The last lines of a guest's log, in order.
fn tail(output: &str) -> Vec<&str> {
    let lines: Vec<&str> = output.lines().collect();
    lines[lines.len().saturating_sub(25)..].to_vec()
}

/// Escapes `text` for XML.
fn xml(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// The `JUnit` XML report: a suite per boot, a case per KTAP test, and one
/// more when the boot failed without a `not ok` to show for it (no KTAP, or
/// cut short), named after the test running when it stopped.
fn junit(outcomes: &[Outcome]) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites>\n");
    for outcome in outcomes {
        let suite = xml(&format!("{} ({})", outcome.image.name, outcome.machine.describe()));
        let cases: Vec<&ktap::TestResult> = outcome.report.top().collect();
        let boot_problem = match &outcome.status {
            Status::Passed => None,
            Status::TimedOut => Some("timed out".to_string()),
            Status::Failed(code) => outcome.report.problem().or(Some(format!("exit {code}"))),
            Status::Inconsistent(why) => Some(why.clone()),
        };
        let boot_problem = boot_problem.filter(|_| cases.iter().all(|c| c.ok));
        let extra = usize::from(boot_problem.is_some());
        let _ = writeln!(
            out,
            "  <testsuite name=\"{suite}\" tests=\"{}\" failures=\"{}\" time=\"{:.3}\">",
            cases.len() + extra,
            cases.iter().filter(|c| !c.ok).count() + extra,
            outcome.duration.as_secs_f64()
        );
        for case in &cases {
            let _ = write!(out, "    <testcase classname=\"{suite}\" name=\"{}\"", xml(&case.name));
            if case.ok {
                out.push_str("/>\n");
            } else {
                let _ = writeln!(out, "><failure message=\"not ok\">{}</failure></testcase>", xml(&case.diagnostics.join("\n")));
            }
        }
        if let Some(problem) = boot_problem {
            let _ = writeln!(
                out,
                "    <testcase classname=\"{suite}\" name=\"{}\"><failure message=\"{}\">{}</failure></testcase>",
                xml(outcome.report.running.as_deref().unwrap_or("boot")),
                xml(&problem),
                xml(&tail(&outcome.output).join("\n"))
            );
        }
        out.push_str("  </testsuite>\n");
    }
    out.push_str("</testsuites>\n");
    out
}

/// `jig ktap FILE`: parses a saved log and prints what it says.
fn ktap_file(path: &Path) -> i32 {
    let Ok(text) = std::fs::read_to_string(path) else {
        eprintln!("jig: cannot read {}", path.display());
        return 2;
    };
    let report = ktap::parse(&text);
    for result in &report.results {
        let indent = "    ".repeat(result.depth);
        let word = if result.skipped { "skip" } else if result.ok { "ok" } else { "not ok" };
        println!("{indent}{word} {} {}", result.index, result.name);
    }
    match report.problem() {
        None => {
            println!("jig: {} of {} passed", report.passed(), report.top().count());
            0
        }
        Some(problem) => {
            println!("jig: {problem}");
            1
        }
    }
}

/// Keeps `Duration` in the imports for the report helpers' signatures.
#[allow(dead_code)]
fn _duration(d: Duration) -> f64 {
    d.as_secs_f64()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{junit, tail};
    use crate::ktap;
    use crate::run::{Image, Machine, Outcome, Status};

    /// A finished boot that printed `output` and ended as `status`.
    fn outcome(output: &str, status: Status) -> Outcome {
        Outcome {
            image: Image { name: "t".into(), kernel: PathBuf::new(), modules: None, reproduce: String::new() },
            machine: Machine::default(),
            status,
            report: ktap::parse(output),
            output: output.into(),
            log: PathBuf::new(),
            duration: Duration::ZERO,
        }
    }

    #[test]
    fn a_timeout_fails_the_test_that_was_running() {
        let xml = junit(&[outcome("KTAP version 1\n1..2\n# run a\nok 1 a\n# run b <x>\n", Status::TimedOut)]);
        assert!(xml.contains("tests=\"2\" failures=\"1\""));
        assert!(xml.contains("<testcase classname=\"t (default)\" name=\"a\"/>"));
        assert!(xml.contains("name=\"b &lt;x&gt;\"><failure message=\"timed out\">"));
    }

    #[test]
    fn a_not_ok_carries_its_diagnostics() {
        let xml = junit(&[outcome("KTAP version 1\n1..1\n# run a\n# a: why\nnot ok 1 a\n", Status::Failed(35))]);
        assert!(xml.contains("tests=\"1\" failures=\"1\""));
        assert!(xml.contains("<failure message=\"not ok\">a: why</failure>"));
    }

    #[test]
    fn the_tail_keeps_the_last_lines_in_order() {
        let log = (0..30).map(|i| i.to_string()).collect::<Vec<_>>().join("\n");
        let last = tail(&log);
        assert_eq!(last.len(), 25);
        assert_eq!((last[0], last[24]), ("5", "29"));
        assert_eq!(tail("a\nb"), ["a", "b"]);
    }
}
