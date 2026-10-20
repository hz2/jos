//! A KTAP parser for the serial output of a jos guest.
//!
//! A guest prints KTAP (the format Linux's `KUnit` uses) mixed in with its own
//! log lines:
//!
//! ```text
//! KTAP version 1
//! 1..2
//! # run first_test
//! ok 1 first_test
//! # run second_test
//! # second_test: why it failed
//! not ok 2 second_test
//! ```
//!
//! The parser keeps what a report needs: the plan, every result with the
//! diagnostics printed since the test started, and which test was running
//! when the output stopped. Lines it does not understand (kernel log lines)
//! are skipped. Indented KTAP (a nested suite) is read too, one level per four
//! spaces, and kept apart from the top level.

/// The result of one test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestResult {
    /// The test's number in its plan, counting from 1.
    pub index: usize,
    /// Its name.
    pub name: String,
    /// Whether it passed (`ok`), or was skipped with `# SKIP`.
    pub ok: bool,
    /// Whether it was skipped.
    pub skipped: bool,
    /// The `#` lines printed between its `# run` line and its result.
    pub diagnostics: Vec<String>,
    /// How deeply its suite is nested: 0 for the top level.
    pub depth: usize,
}

/// Everything parsed from one guest's output.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Whether a `KTAP version` (or `TAP version`) header appeared.
    pub saw_header: bool,
    /// The top-level plan (`1..N`), if one appeared.
    pub plan: Option<usize>,
    /// Every result, in order, at every depth.
    pub results: Vec<TestResult>,
    /// The test a `# run` line announced that has no result yet: the one
    /// running when the output stopped, if the guest died.
    pub running: Option<String>,
}

impl Report {
    /// The top-level results.
    pub fn top(&self) -> impl Iterator<Item = &TestResult> {
        self.results.iter().filter(|r| r.depth == 0)
    }

    /// How many top-level tests passed.
    #[must_use]
    pub fn passed(&self) -> usize {
        self.top().filter(|r| r.ok).count()
    }

    /// Why the KTAP does not show a clean pass, or `None` if it does.
    #[must_use]
    pub fn problem(&self) -> Option<String> {
        if !self.saw_header {
            return Some("no KTAP output".into());
        }
        let count = self.top().count();
        if let Some(failed) = self.top().find(|r| !r.ok) {
            return Some(format!("not ok {} {}", failed.index, failed.name));
        }
        match self.plan {
            None => Some("no KTAP plan".into()),
            Some(plan) if plan != count => match &self.running {
                Some(name) => Some(format!("stopped in {name} after {count} of {plan} tests")),
                None => Some(format!("{count} of {plan} planned tests reported")),
            },
            Some(_) => None,
        }
    }
}

/// Parses `output`, the serial log of one guest.
#[must_use]
pub fn parse(output: &str) -> Report {
    let mut report = Report::default();
    let mut diagnostics: Vec<String> = Vec::new();
    for raw in output.lines() {
        let line = raw.trim_end_matches('\r');
        let indent = line.len() - line.trim_start_matches(' ').len();
        let depth = indent / 4;
        let line = line.trim_start_matches(' ');
        if line.starts_with("KTAP version") || line.starts_with("TAP version") {
            if depth == 0 {
                report.saw_header = true;
            }
        } else if let Some(count) = plan_count(line) {
            if depth == 0 {
                report.plan = Some(count);
            }
        } else if let Some(name) = line.strip_prefix("# run ") {
            if depth == 0 {
                report.running = Some(name.trim().to_string());
            }
            diagnostics.clear();
        } else if let Some(text) = line.strip_prefix('#') {
            diagnostics.push(text.trim().to_string());
        } else if let Some(mut result) = result_line(line, depth) {
            result.diagnostics = std::mem::take(&mut diagnostics);
            if depth == 0 && report.running.as_deref() == Some(result.name.as_str()) {
                report.running = None;
            }
            report.results.push(result);
        }
    }
    report
}

/// Reads a plan line, `1..N`.
fn plan_count(line: &str) -> Option<usize> {
    let rest = line.strip_prefix("1..")?;
    let digits = rest.split_whitespace().next()?;
    digits.parse().ok()
}

/// Reads a result line: `ok N name`, `not ok N name`, optionally followed by
/// `# SKIP reason` or another directive.
fn result_line(line: &str, depth: usize) -> Option<TestResult> {
    let (ok, rest) = if let Some(rest) = line.strip_prefix("not ok ") {
        (false, rest)
    } else {
        (true, line.strip_prefix("ok ")?)
    };
    let (number, rest) = rest.split_once(' ').unwrap_or((rest, ""));
    let index = number.parse().ok()?;
    let (name, directive) = match rest.split_once(" # ") {
        Some((name, directive)) => (name, directive),
        None => (rest, ""),
    };
    let name = name.strip_prefix("- ").unwrap_or(name).trim().to_string();
    let skipped = directive.trim_start().to_ascii_uppercase().starts_with("SKIP");
    Some(TestResult { index, name, ok: ok || skipped, skipped, diagnostics: Vec::new(), depth })
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn a_clean_run_passes() {
        let report = parse("KTAP version 1\n1..2\n# run a\nok 1 a\n# run b\nok 2 b\n");
        assert_eq!(report.problem(), None);
        assert_eq!(report.passed(), 2);
        assert_eq!(report.running, None);
    }

    #[test]
    fn a_failure_keeps_its_diagnostics() {
        let report = parse("KTAP version 1\n1..1\n# run a\n# a: wrong word\nnot ok 1 a\n");
        assert_eq!(report.results[0].diagnostics, ["a: wrong word"]);
        assert_eq!(report.problem().as_deref(), Some("not ok 1 a"));
    }

    #[test]
    fn a_dead_guest_names_the_running_test() {
        let report = parse("KTAP version 1\n1..3\n# run a\nok 1 a\n# run b\nEXCEPTION: oops\n");
        assert_eq!(report.running.as_deref(), Some("b"));
        assert_eq!(report.problem().as_deref(), Some("stopped in b after 1 of 3 tests"));
    }

    #[test]
    fn log_noise_and_crlf_are_ignored() {
        let out = "jos: booting\r\nKTAP version 1\r\n1..1\r\nheap ok: sum = 120\r\n# run a\r\nok 1 a\r\njos: halted\r\n";
        let report = parse(out);
        assert_eq!(report.problem(), None);
        assert_eq!(report.results[0].name, "a");
    }

    #[test]
    fn no_output_is_a_problem() {
        assert_eq!(parse("jos: booting\n").problem().as_deref(), Some("no KTAP output"));
        assert_eq!(parse("KTAP version 1\nok 1 a\n").problem().as_deref(), Some("no KTAP plan"));
    }

    #[test]
    fn skips_count_as_passes_and_nested_suites_stay_apart() {
        let out = "KTAP version 1\n1..2\nok 1 a # SKIP no kvm\n    KTAP version 1\n    1..1\n    not ok 1 inner\nok 2 outer\n";
        let report = parse(out);
        assert!(report.results[0].skipped && report.results[0].ok);
        assert_eq!(report.top().count(), 2);
        assert_eq!(report.problem(), None);
        assert_eq!(report.results.iter().filter(|r| r.depth == 1).count(), 1);
    }

    #[test]
    fn the_tap_dash_form_is_read() {
        let report = parse("TAP version 14\n1..1\nok 1 - a name\n");
        assert_eq!(report.results[0].name, "a name");
        assert_eq!(report.problem(), None);
    }
}
