//! Test results in KTAP, the line format the host harness parses.
//!
//! A suite prints a header and a plan, then for each test a `# run` line (so
//! a harness can tell which test was running if the machine dies) and one
//! `ok` or `not ok` line. Diagnostics are lines starting with `#`.

/// Prints the KTAP header and the plan for `count` tests.
pub fn header(count: usize) {
    crate::println!("KTAP version 1");
    crate::println!("1..{}", count);
}

/// Announces that test `name` is about to run.
pub fn run(name: &str) {
    crate::println!("# run {}", name);
}

/// Reports the result of test number `index` (counting from 1).
pub fn report(index: usize, name: &str, passed: bool) {
    if passed {
        crate::println!("ok {} {}", index, name);
    } else {
        crate::println!("not ok {} {}", index, name);
    }
}
