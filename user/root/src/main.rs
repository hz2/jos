//! The root task: the first userspace program.
//!
//! The kernel loads it from the `root` boot module and starts it with every
//! initial capability: its own thread, `CNode`, and address space, its IPC
//! buffer and boot information, the console, the machine, and untyped memory
//! covering the free RAM. From here on the kernel only enforces; this program
//! decides.
//!
//! Its command line picks a mode. `hello` (the default) and `test [filter]`
//! run the first-light checks below, or those whose name contains `filter`,
//! which exercise the capability model end to end from ring 3, report them in
//! KTAP, and halt the machine with the result; `list` names them; `shell`
//! reads commands from the console (type `help`).
//!
//! Each check runs in a fresh thread whose faults go to the runner, under a
//! deadline: a check that faults, panics (a spawned thread's panic is a
//! fault), or hangs is reported `not ok` with what happened, and the rest of
//! the suite still runs.
#![no_std]
#![no_main]
#![warn(clippy::pedantic)]

use core::sync::atomic::{AtomicPtr, Ordering};

use libjos::abi::{BootInfo, FaultKind, IpcSyscallError, layout, map_flags, root_slot};
use libjos::jos_core::cap_rights::Rights;
use libjos::jos_core::line::LineEditor;
use libjos::jos_core::untyped::ObjectType;
use libjos::mem::{self, Error};
use libjos::sys::{self, Slot};
use libjos::thread::Thread;
use libjos::{console, ktap, println, rt};

libjos::root_entry!(main);

/// A first-light check: `Err` carries why it failed.
type Check = fn(&BootInfo) -> Result<(), &'static str>;

/// Every first-light check, in order.
const CHECKS: [(&str, Check); 22] = [
    ("boot_info_is_consistent", boot_info_is_consistent),
    ("add_probe_round_trips", add_probe_round_trips),
    ("endpoint_carries_a_word", endpoint_carries_a_word),
    ("badge_arrives_with_the_message", badge_arrives_with_the_message),
    ("revoke_reaches_every_copy", revoke_reaches_every_copy),
    ("fresh_page_maps_and_holds_data", fresh_page_maps_and_holds_data),
    ("writable_and_executable_is_refused", writable_and_executable_is_refused),
    ("console_without_write_is_refused", console_without_write_is_refused),
    ("machine_without_write_is_refused", machine_without_write_is_refused),
    ("threads_run_and_report_back", threads_run_and_report_back),
    ("thread_ids_are_reused", thread_ids_are_reused),
    ("stale_reply_reaches_no_new_thread", stale_reply_reaches_no_new_thread),
    ("nonblocking_send_reaches_a_parked_receiver", nonblocking_send_reaches_a_parked_receiver),
    ("nonblocking_recv_takes_a_parked_sender", nonblocking_recv_takes_a_parked_sender),
    ("page_fault_reaches_its_handler", page_fault_reaches_its_handler),
    ("invalid_opcode_reaches_its_handler", invalid_opcode_reaches_its_handler),
    ("fault_without_a_handler_stops_only_that_thread", fault_without_a_handler_stops_only_that_thread),
    ("handled_page_fault_resumes_the_thread", handled_page_fault_resumes_the_thread),
    ("a_timed_receive_runs_out", a_timed_receive_runs_out),
    ("a_timed_receive_takes_what_arrives_in_time", a_timed_receive_takes_what_arrives_in_time),
    ("revoking_an_endpoint_ends_its_waits", revoking_an_endpoint_ends_its_waits),
    ("calls_reach_the_longest_waiting_receiver", calls_reach_the_longest_waiting_receiver),
];

/// What a thread sends to say it is about to block.
const READY: u64 = 0x5EAD;

/// What a thread sends when its work is done.
const DONE: u64 = 0xD0E;

/// What a check thread sends when its check passed.
const PASSED: u64 = 0x9A55;

/// What a check thread sends when its check failed, once it has said why.
const FAILED: u64 = 0xFA11;

/// The badge of the runner's endpoint as check threads report on it.
const REPORT_BADGE: u64 = 0xC4EC;

/// The badge of the runner's endpoint as check threads' faults reach it.
const FAULT_BADGE: u64 = 0xF417;

/// How long a check may run before the runner stops it.
const CHECK_TIMEOUT_MS: u64 = 30_000;

/// Pages of stack a check thread gets.
const CHECK_STACK_PAGES: u64 = 8;

/// The boot information, for the check threads: `main` stores it before it
/// starts any.
static BOOT: AtomicPtr<BootInfo> = AtomicPtr::new(core::ptr::null_mut());

/// Runs the mode the command line names.
fn main(boot: &'static BootInfo) -> ! {
    BOOT.store(core::ptr::from_ref(boot).cast_mut(), Ordering::Release);
    describe(boot);
    let mut words = boot.cmdline().split(|&b| b == b' ').filter(|w| !w.is_empty());
    let mode = words.next().unwrap_or(b"");
    let filter = words.next().unwrap_or(b"");
    match mode {
        b"" | b"hello" | b"test" => {
            let failed = run_checks(filter);
            rt::halt(u64::from(failed != 0))
        }
        b"shell" => shell(boot),
        b"list" => {
            // as KTAP with every check skipped, so a harness reads the list too.
            ktap::header(CHECKS.len());
            for (index, (name, _)) in CHECKS.iter().enumerate() {
                println!("ok {} {} # SKIP listed", index + 1, name);
            }
            rt::halt(0)
        }
        _ => {
            println!("# root: unknown mode; expected hello, test [filter], list, or shell");
            rt::halt(2)
        }
    }
}

/// What `help` prints.
const HELP: &str = "\
commands:
  help             this list
  info             what the kernel handed the root task
  mem              untyped memory and free capability slots
  list             the first-light checks
  test [filter]    run the checks, or those whose name contains filter
  bench [rounds]   time call and reply round trips to another thread
  echo text        print text
  halt [code]      stop the machine; code 0 reports success";

/// Reads commands from the console and runs them, until `halt`.
fn shell(boot: &BootInfo) -> ! {
    println!("jos shell; type help for the commands");
    let mut editor: LineEditor<128> = LineEditor::new();
    loop {
        libjos::print!("jos> ");
        match console::read_line(&mut editor) {
            Ok(true) => run_command(boot, editor.line()),
            Ok(false) => {}
            Err(e) => {
                println!("shell: the console refused a read: {:?}", e);
                rt::halt(1)
            }
        }
    }
}

/// Runs one shell command line.
fn run_command(boot: &BootInfo, line: &str) {
    let line = line.trim();
    let (command, rest) = line.split_once(' ').unwrap_or((line, ""));
    let rest = rest.trim();
    match command {
        "" => {}
        "help" => println!("{}", HELP),
        "info" => describe(boot),
        "mem" => {
            for u in boot.untyped() {
                println!("untyped slot {}: {} KiB at {:#x}", u.slot, u.size / 1024, u.phys);
            }
            println!("{} capability slots free", mem::free_slots());
        }
        "list" => {
            for (name, _) in CHECKS {
                println!("  {}", name);
            }
        }
        "test" => {
            let failed = run_checks(rest.as_bytes());
            println!("{}", if failed == 0 { "all passed" } else { "some failed" });
        }
        "bench" => {
            let rounds = rest.parse().unwrap_or(10_000);
            match bench_ipc(rounds) {
                Ok(cycles) => println!("{} call/reply round trips, {} cycles each", rounds, cycles),
                Err(why) => println!("bench: {}", why),
            }
        }
        "echo" => println!("{}", rest),
        "halt" => rt::halt(rest.parse().unwrap_or(0)),
        _ => println!("unknown command {}; try help", command),
    }
}

/// Answers every call on the endpoint in field 0 with the word it carried,
/// through the reply object in field 1, until a receive fails.
extern "C" fn echo_server(arg: u64) {
    let (ep, reply) = (field(arg, 0), field(arg, 1));
    let Ok((mut word, _)) = sys::recv_reply(ep, reply) else { return };
    while let Ok((next, _)) = sys::reply_recv(ep, reply, word) {
        word = next;
    }
}

/// Times `rounds` call and reply round trips to a thread that echoes them,
/// and returns the time stamp cycles each took.
fn bench_ipc(rounds: u64) -> Result<u64, &'static str> {
    let ep = object(ObjectType::Endpoint)?;
    let reply = object(ObjectType::Reply)?;
    let server = Thread::spawn(echo_server, pack(ep, reply, 0), 1).map_err(|_| "spawn")?;
    let start = rdtsc();
    let echoed = (0..rounds).all(|round| sys::call(ep, round) == Ok(round));
    let cycles = rdtsc().wrapping_sub(start);
    server.reap();
    release(&[ep, reply])?;
    ensure(echoed, "a round trip came back wrong")?;
    Ok(cycles / rounds.max(1))
}

/// Returns the boot information `main` stored.
fn boot_info() -> &'static BootInfo {
    let boot = BOOT.load(Ordering::Acquire);
    // SAFETY: main stored a `&'static BootInfo` here before starting any
    // thread that calls this, and it is never written again.
    unsafe { &*boot }
}

/// Prints what the kernel handed over, as KTAP diagnostics.
fn describe(boot: &BootInfo) {
    println!("# jos root task, running in ring 3");
    println!(
        "# image {:#x}..{:#x}, stack {:#x}..{:#x}, ipc buffer {:#x}",
        boot.image_start, boot.image_end, boot.stack_bottom, boot.stack_top, boot.ipc_buffer
    );
    let mut free = 0;
    for u in boot.untyped() {
        println!("#   untyped slot {}: {:#x}, {} KiB, {} KiB used", u.slot, u.phys, u.size / 1024, u.used / 1024);
        free += u.size - u.used;
    }
    println!(
        "# {} untyped regions, {} MiB free; slots {}..{} empty; {} MiB above the identity map ignored",
        boot.untyped().len(),
        free >> 20,
        boot.empty.start,
        boot.empty.end,
        boot.memory_ignored >> 20
    );
    if let Ok(cmdline) = core::str::from_utf8(boot.cmdline()) {
        println!("# cmdline: \"{}\"", cmdline);
    }
}

/// Runs every check whose name contains `filter`, each in a thread of its own,
/// reports each in KTAP, and returns how many failed.
fn run_checks(filter: &[u8]) -> usize {
    let picked = || CHECKS.iter().enumerate().filter(|(_, (name, _))| contains(name.as_bytes(), filter));
    let count = picked().count();
    ktap::header(count);
    let runner = match Runner::new() {
        Ok(runner) => runner,
        Err(why) => {
            println!("# root: cannot set up the runner: {}", why);
            return count.max(1);
        }
    };
    let mut failed = 0;
    for (n, (index, (name, _))) in picked().enumerate() {
        ktap::run(name);
        let passed = runner.run(index, name);
        failed += usize::from(!passed);
        ktap::report(n + 1, name, passed);
    }
    runner.free();
    println!("# root: {} of {} checks passed", count - failed, count);
    failed
}

/// Returns whether `needle` occurs in `haystack`; the empty needle always does.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|window| window == needle)
}

/// Runs check field 0 (an index into [`CHECKS`]) and reports on field 1:
/// [`PASSED`], or [`FAILED`] once it has printed why.
extern "C" fn run_check(arg: u64) {
    let (index, report) = (field(arg, 0), field(arg, 1));
    let Some((name, check)) = usize::try_from(index).ok().and_then(|i| CHECKS.get(i)) else {
        return;
    };
    let word = match check(boot_info()) {
        Ok(()) => PASSED,
        Err(why) => {
            println!("# {}: {}", name, why);
            FAILED
        }
    };
    let _ = sys::send_blocking(report, word);
}

/// The endpoint check threads report and fault on, and what receiving from it
/// needs.
struct Runner {
    /// The endpoint the runner receives on.
    inbox: Slot,
    /// A copy of it, badged [`REPORT_BADGE`], that check threads report on.
    reports: Slot,
    /// A copy of it, badged [`FAULT_BADGE`], that check threads' faults go to.
    faults: Slot,
    /// The reply object a fault binds to the thread that faulted.
    reply: Slot,
}

impl Runner {
    /// Retypes the endpoint and reply object and mints the two copies.
    fn new() -> Result<Self, &'static str> {
        let inbox = object(ObjectType::Endpoint)?;
        let reports = mem::mint(inbox, Rights::ALL, REPORT_BADGE).map_err(|_| "mint")?;
        let faults = mem::mint(inbox, Rights::ALL, FAULT_BADGE).map_err(|_| "mint")?;
        let reply = object(ObjectType::Reply)?;
        Ok(Self { inbox, reports, faults, reply })
    }

    /// Runs check `index` in a fresh thread and waits for it to report, fault,
    /// or run out of time; says why unless it passed.
    fn run(&self, index: usize, name: &str) -> bool {
        let arg = pack(index as u64, self.reports, 0);
        let Ok(thread) = Thread::spawn_with(run_check, arg, CHECK_STACK_PAGES, Some(self.faults)) else {
            println!("# {}: the runner could not start a thread for it", name);
            return false;
        };
        let outcome = sys::recv_timeout(self.inbox, Some(self.reply), CHECK_TIMEOUT_MS);
        let passed = match outcome {
            Ok((PASSED, REPORT_BADGE)) => true,
            Ok((FAILED, REPORT_BADGE)) => false,
            Ok((vector, FAULT_BADGE)) => {
                let [_, address, rip, error] = sys::received_words();
                match FaultKind::from_vector(vector) {
                    Some(kind) => println!(
                        "# {}: faulted: {:?} at rip {:#x}, address {:#x}, error {:#x}",
                        name, kind, rip, address, error
                    ),
                    None => println!("# {}: faulted: vector {} at rip {:#x}", name, vector, rip),
                }
                false
            }
            Ok((word, badge)) => {
                println!("# {}: unexpected message {:#x} with badge {:#x}", name, word, badge);
                false
            }
            Err(IpcSyscallError::TimedOut) => {
                println!("# {}: no result after {} ms", name, CHECK_TIMEOUT_MS);
                false
            }
            Err(e) => {
                println!("# {}: the runner's receive failed: {:?}", name, e);
                false
            }
        };
        thread.reap();
        // a fault leaves the reply bound to the thread just stopped, and
        // answering it frees it; a report that raced the deadline is dropped.
        if matches!(outcome, Ok((_, FAULT_BADGE))) {
            let _ = sys::reply(self.reply, 0);
        }
        while sys::recv(self.inbox).is_ok() {}
        passed
    }

    /// Frees the runner's objects, the copies before the endpoint, so their
    /// slots are freed too.
    fn free(self) {
        let _ = release(&[self.reports, self.faults, self.inbox, self.reply]);
    }
}

/// Turns a condition into a check result.
fn ensure(condition: bool, why: &'static str) -> Result<(), &'static str> {
    if condition { Ok(()) } else { Err(why) }
}

/// Retypes an object for a check, naming the failure.
fn object(ty: ObjectType) -> Result<Slot, &'static str> {
    mem::retype(ty).map_err(|e| match e {
        Error::NoSlot => "out of slots",
        Error::NoMemory => "out of untyped memory",
        Error::Retype(_) | Error::Ipc(_) | Error::Mint(_) => "retype refused",
    })
}

/// Frees the objects a check made.
fn release(slots: &[Slot]) -> Result<(), &'static str> {
    for &slot in slots {
        mem::release(slot).map_err(|_| "release refused")?;
    }
    Ok(())
}

/// Packs three 16-bit fields (slots, or small values) into a thread argument.
fn pack(a: u64, b: u64, c: u64) -> u64 {
    a | b << 16 | c << 32
}

/// Returns field `i` of a [`pack`]ed argument.
fn field(arg: u64, i: u32) -> u64 {
    (arg >> (16 * i)) & 0xFFFF
}

/// The boot information agrees with the fixed layout and with itself.
fn boot_info_is_consistent(boot: &BootInfo) -> Result<(), &'static str> {
    ensure(boot.ipc_buffer == layout::ROOT_IPC_BUFFER, "ipc buffer not at its fixed address")?;
    ensure(boot.stack_top == layout::ROOT_STACK_TOP, "stack top not at its fixed address")?;
    ensure(boot.image_start >= layout::ROOT_IMAGE_BASE, "image below its base")?;
    ensure(boot.image_end <= layout::ROOT_IMAGE_LIMIT, "image past its limit")?;
    ensure(!boot.untyped().is_empty(), "no untyped memory")?;
    let first_free = root_slot::FIRST_UNTYPED + boot.untyped_count;
    ensure(boot.empty.start == first_free, "empty slots do not follow the untyped")?;
    ensure(boot.empty.end == boot.cnode_slots, "empty slots do not run to the end")?;
    // the check runs in a thread of its own, which finds its own buffer, in its
    // thread block, from its stack.
    let buffer = libjos::console::ipc_buffer();
    ensure(libjos::thread::is_spawned(), "the check is not running in a spawned thread")?;
    ensure(buffer % layout::THREAD_BLOCK == layout::THREAD_IPC_BUFFER, "the stack does not find the ipc buffer")
}

/// The arithmetic probe crosses the boundary both ways.
fn add_probe_round_trips(_: &BootInfo) -> Result<(), &'static str> {
    ensure(sys::add(40, 2) == 42, "add(40, 2) != 42")
}

/// A retyped endpoint carries a word from a send to a receive.
fn endpoint_carries_a_word(_: &BootInfo) -> Result<(), &'static str> {
    let ep = object(ObjectType::Endpoint)?;
    sys::send(ep, 0x1234).map_err(|_| "send")?;
    let received = sys::recv(ep).map_err(|_| "recv")?;
    let empty = sys::recv(ep);
    release(&[ep])?;
    ensure(received == (0x1234, 0), "wrong word or badge")?;
    ensure(empty == Err(IpcSyscallError::WouldBlock), "empty endpoint did not refuse")
}

/// A badged copy stamps its badge on what is sent through it.
fn badge_arrives_with_the_message(_: &BootInfo) -> Result<(), &'static str> {
    let ep = object(ObjectType::Endpoint)?;
    let badged = sys::mint(ep, Rights::ALL, 7).map_err(|_| "mint")?;
    sys::send(badged, 99).map_err(|_| "send")?;
    let received = sys::recv(ep).map_err(|_| "recv")?;
    // revoking the original takes the badged copy with it.
    release(&[ep])?;
    ensure(received == (99, 7), "badge did not arrive")
}

/// Revoking an endpoint removes it and the copy derived from it.
fn revoke_reaches_every_copy(_: &BootInfo) -> Result<(), &'static str> {
    let ep = object(ObjectType::Endpoint)?;
    let copy = sys::mint(ep, Rights::READ, 0).map_err(|_| "mint")?;
    ensure(sys::revoke(ep) == Ok(2), "revoke did not remove both")?;
    mem::free_slot(ep);
    ensure(sys::recv(copy) == Err(IpcSyscallError::BadCap), "copy survived")?;
    ensure(sys::recv(ep) == Err(IpcSyscallError::BadCap), "original survived")
}

/// A page built from untyped maps into the root's own address space and
/// holds data.
fn fresh_page_maps_and_holds_data(_: &BootInfo) -> Result<(), &'static str> {
    // a 2 MiB region of the first GiB that the image and the window leave alone.
    const VADDR: u64 = layout::USER_START + 0x1000_0000;
    let table = object(ObjectType::PageTable)?;
    let frame = object(ObjectType::Frame)?;
    sys::map_page_table(root_slot::VSPACE, table, VADDR).map_err(|_| "map table")?;
    sys::map_frame(root_slot::VSPACE, frame, VADDR, map_flags::WRITE).map_err(|_| "map frame")?;
    let word = VADDR as *mut u64;
    // SAFETY: the frame was just mapped writable at VADDR and nothing else
    // refers to that page.
    let seen = unsafe {
        word.write_volatile(0xFEED_F00D);
        word.read_volatile()
    };
    sys::unmap(frame).map_err(|_| "unmap")?;
    release(&[frame, table])?;
    ensure(seen == 0xFEED_F00D, "page did not hold the word")
}

/// The kernel never maps a page both writable and executable.
fn writable_and_executable_is_refused(_: &BootInfo) -> Result<(), &'static str> {
    const VADDR: u64 = layout::USER_START + 0x1000_0000;
    let table = object(ObjectType::PageTable)?;
    let frame = object(ObjectType::Frame)?;
    sys::map_page_table(root_slot::VSPACE, table, VADDR).map_err(|_| "map table")?;
    let wx = sys::map_frame(root_slot::VSPACE, frame, VADDR, map_flags::WRITE | map_flags::EXECUTE);
    release(&[frame, table])?;
    ensure(wx == Err(IpcSyscallError::WritableExecutable), "w+x mapping was not refused")
}

/// A console capability without `WRITE` cannot print.
fn console_without_write_is_refused(_: &BootInfo) -> Result<(), &'static str> {
    let read_only = sys::mint(root_slot::CONSOLE, Rights::READ, 0).map_err(|_| "mint")?;
    let refused = sys::console_write(read_only, 0);
    sys::revoke(read_only).map_err(|_| "revoke")?;
    ensure(refused == Err(IpcSyscallError::Denied), "read-only console printed")
}

/// A machine capability without `WRITE` cannot halt the machine.
fn machine_without_write_is_refused(_: &BootInfo) -> Result<(), &'static str> {
    let read_only = sys::mint(root_slot::MACHINE, Rights::READ, 0).map_err(|_| "mint")?;
    let refused = sys::machine_halt(read_only, 0);
    sys::revoke(read_only).map_err(|_| "revoke")?;
    ensure(refused == IpcSyscallError::Denied, "read-only machine halted")
}

/// Sends twice the value in field 2 on the endpoint in field 0.
extern "C" fn double_and_report(arg: u64) {
    let _ = sys::send_blocking(field(arg, 0), field(arg, 2) * 2);
}

/// Calls the endpoint in field 0 and waits for an answer that never comes.
extern "C" fn call_and_wait(arg: u64) {
    let _ = sys::call(field(arg, 0), 5);
}

/// Takes the call that starts a thread on `start` and, in one syscall,
/// answers it with [`READY`] and parks in a receive on `inbox` with `reply`:
/// the starter's call ([`spawn_parked`]) returns only once this thread is
/// parked, whatever the timer does in between.
fn park_after_answering(inbox: Slot, start: Slot, reply: Slot) -> Result<(u64, u64), IpcSyscallError> {
    sys::recv_reply(start, reply)?;
    sys::reply_recv(inbox, reply, READY)
}

/// Starts `entry`, which must begin with [`park_after_answering`] on `start`,
/// and returns once it is parked.
fn spawn_parked(entry: libjos::thread::Entry, arg: u64, start: Slot) -> Result<Thread, &'static str> {
    let thread = Thread::spawn(entry, arg, 1).map_err(|_| "spawn")?;
    if sys::call(start, 0) == Ok(READY) {
        Ok(thread)
    } else {
        thread.reap();
        Err("the thread did not reach its receive")
    }
}

/// Parks in a receive on field 0 ([`park_after_answering`], started on field
/// 1, reply object in field 2) and reports the word it got on field 1.
extern "C" fn receive_and_report(arg: u64) {
    let (inbox, report, reply) = (field(arg, 0), field(arg, 1), field(arg, 2));
    let word = park_after_answering(inbox, report, reply).map_or(u64::MAX, |(w, _)| w);
    let _ = sys::send_blocking(report, word);
}

/// Fills the endpoint in field 0 with 1 (a non-blocking send, which leaves it
/// in the endpoint's slot), reports [`READY`] on field 1, sends 55 on field 0
/// (blocking, so it parks behind the full slot), and reports [`DONE`].
extern "C" fn send_and_report(arg: u64) {
    let (outbox, report) = (field(arg, 0), field(arg, 1));
    let _ = sys::send(outbox, 1);
    let _ = sys::send_blocking(report, READY);
    let _ = sys::send_blocking(outbox, 55);
    let _ = sys::send_blocking(report, DONE);
}

/// Reads the time stamp counter.
fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: rdtsc only reads the counter into eax and edx; ring 3 may use it
    // because the kernel leaves CR4.TSD clear.
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
    u64::from(hi) << 32 | u64::from(lo)
}

/// Spins for 2^29 time stamp cycles, a sixth of a second or more, so a timer
/// tick (every 55 ms) lands and any thread that is ready gets to run.
fn spin_past_a_tick() {
    let start = rdtsc();
    while rdtsc().wrapping_sub(start) < 1 << 29 {
        core::hint::spin_loop();
    }
}

/// A thread started from ring 3 runs in the root's spaces and reports back.
fn threads_run_and_report_back(_: &BootInfo) -> Result<(), &'static str> {
    let ep = object(ObjectType::Endpoint)?;
    let thread = Thread::spawn(double_and_report, pack(ep, 0, 21), 2).map_err(|_| "spawn")?;
    let got = sys::recv_blocking(ep);
    thread.reap();
    release(&[ep])?;
    ensure(got == Ok((42, 0)), "the thread did not report 42")
}

/// Starting and exiting more threads than the scheduler holds at once works,
/// because a retired thread's id is reused.
fn thread_ids_are_reused(_: &BootInfo) -> Result<(), &'static str> {
    let ep = object(ObjectType::Endpoint)?;
    let mut result = Ok(());
    for round in 0..80 {
        let Ok(thread) = Thread::spawn(double_and_report, pack(ep, 0, round), 1) else {
            result = Err("spawn failed: are thread ids reused?");
            break;
        };
        let got = sys::recv_blocking(ep);
        thread.reap();
        if got != Ok((round * 2, 0)) {
            result = Err("a thread reported the wrong word");
            break;
        }
    }
    release(&[ep])?;
    result
}

/// An answer to a caller that has since retired reaches nothing, even when a
/// new thread now holds the retired one's scheduler id.
fn stale_reply_reaches_no_new_thread(_: &BootInfo) -> Result<(), &'static str> {
    let call_ep = object(ObjectType::Endpoint)?;
    let reply = object(ObjectType::Reply)?;
    let inbox = object(ObjectType::Endpoint)?;
    let report = object(ObjectType::Endpoint)?;
    let waiter_reply = object(ObjectType::Reply)?;
    let caller = Thread::spawn(call_and_wait, pack(call_ep, 0, 0), 1).map_err(|_| "spawn caller")?;
    let request = sys::recv_reply(call_ep, reply);
    // the reply object stays bound to the caller as it retires.
    caller.reap();
    let waiter = spawn_parked(receive_and_report, pack(inbox, report, waiter_reply), report)?;
    // the waiter is parked in its receive now; the stale answer must not wake
    // it, which it would get to show while this thread spins.
    let _ = sys::reply(reply, 99);
    spin_past_a_tick();
    let sent = sys::send_blocking(inbox, 42);
    let got = sys::recv_blocking(report);
    waiter.reap();
    release(&[call_ep, reply, inbox, report, waiter_reply])?;
    ensure(request.map(|(word, _)| word) == Ok(5), "the call did not arrive")?;
    ensure(sent.is_ok(), "the waiter did not take the message")?;
    ensure(got == Ok((42, 0)), "the stale answer woke the thread that reused the slot")
}

/// A non-blocking send hands its message to a receiver parked in a blocking
/// receive, instead of leaving it in the endpoint where the receiver never
/// looks.
fn nonblocking_send_reaches_a_parked_receiver(_: &BootInfo) -> Result<(), &'static str> {
    let inbox = object(ObjectType::Endpoint)?;
    let report = object(ObjectType::Endpoint)?;
    let reply = object(ObjectType::Reply)?;
    let waiter = spawn_parked(receive_and_report, pack(inbox, report, reply), report)?;
    let sent = sys::send(inbox, 77);
    // with the message handed over, nothing is left in the endpoint.
    let stranded = sys::recv(inbox);
    let got = if stranded.is_err() { sys::recv_blocking(report) } else { Ok((0, 0)) };
    waiter.reap();
    release(&[inbox, report, reply])?;
    ensure(sent.is_ok(), "the send was refused")?;
    ensure(stranded == Err(IpcSyscallError::WouldBlock), "the message stayed in the endpoint")?;
    ensure(got == Ok((77, 0)), "the parked receiver did not get the message")
}

/// A non-blocking receive takes the message in the endpoint's slot first (it
/// is the older one), then the message of a sender parked behind the full
/// slot, and that completes the parked send.
fn nonblocking_recv_takes_a_parked_sender(_: &BootInfo) -> Result<(), &'static str> {
    let outbox = object(ObjectType::Endpoint)?;
    let report = object(ObjectType::Endpoint)?;
    let sender = Thread::spawn(send_and_report, pack(outbox, report, 0), 1).map_err(|_| "spawn")?;
    let ready = sys::recv_blocking(report);
    // let the sender reach its blocking send and park behind the full slot.
    spin_past_a_tick();
    let first = sys::recv(outbox);
    let second = sys::recv(outbox);
    let done = if second.is_ok() { sys::recv_blocking(report) } else { Ok((0, 0)) };
    sender.reap();
    release(&[outbox, report])?;
    ensure(ready == Ok((READY, 0)), "the sender did not start")?;
    ensure(first == Ok((1, 0)), "the deposited message did not come first")?;
    ensure(second == Ok((55, 0)), "the parked sender's message was not taken")?;
    ensure(done == Ok((DONE, 0)), "the parked sender's send did not complete")
}

/// A page nothing maps, unless a fault handler maps it: 512 MiB into the
/// first GiB of user space, clear of the image and the window.
const FAULT_PAGE: u64 = layout::USER_START + 0x2000_0000;

/// The vector of a page fault, the first word of its fault message.
const PAGE_FAULT: u64 = 14;

/// The vector of an invalid opcode.
const INVALID_OPCODE: u64 = 6;

/// Reads the first word of [`FAULT_PAGE`] and reports it on field 0.
extern "C" fn read_fault_page(arg: u64) {
    // SAFETY: the read is meant to fault (or, once a handler mapped the page,
    // to read what it put there); volatile, so it is not optimized away.
    let word = unsafe { core::ptr::read_volatile(FAULT_PAGE as *const u64) };
    let _ = sys::send_blocking(field(arg, 0), word);
}

/// Loads the first word of [`FAULT_PAGE`] with live values in `rax` and
/// `rdx` across the load, and reports the word on field 0 only if both
/// survived (a resumed fault must not touch them); otherwise `0xBAD`.
extern "C" fn load_with_live_registers(arg: u64) {
    let (rax, rdx, word): (u64, u64, u64);
    // SAFETY: the load is meant to fault until a handler maps the page; the
    // block only sets and reads registers and reads that page.
    unsafe {
        core::arch::asm!(
            "mov rax, 0x1111",
            "mov rdx, 0x2222",
            "mov rcx, [{page}]",
            page = in(reg) FAULT_PAGE,
            out("rax") rax,
            out("rdx") rdx,
            out("rcx") word,
            options(nostack, readonly),
        );
    }
    let report = if rax == 0x1111 && rdx == 0x2222 { word } else { 0xBAD };
    let _ = sys::send_blocking(field(arg, 0), report);
}

/// Executes `ud2`, then reports on field 0 (which it should never reach).
extern "C" fn execute_ud2(arg: u64) {
    // SAFETY: ud2 raises an invalid-opcode fault and touches nothing else.
    unsafe { core::arch::asm!("ud2") };
    let _ = sys::send_blocking(field(arg, 0), 1);
}

/// A fault a check caught, and what to clean up once it is done.
struct Caught {
    /// The fault message's words: vector, address, instruction, error code.
    words: [u64; 4],
    /// The badge the fault arrived with.
    badge: u64,
    /// The fault endpoint.
    faults: Slot,
    /// The badged copy of it the thread's faults went to.
    badged: Slot,
    /// The reply object bound to the faulting thread.
    reply: Slot,
    /// The thread that faulted.
    thread: Thread,
}

impl Caught {
    /// Starts `entry` with its faults sent to a badged copy of a fresh
    /// endpoint, and receives the fault with a reply object.
    fn fault_of(entry: libjos::thread::Entry, report: Slot) -> Result<Self, &'static str> {
        let faults = object(ObjectType::Endpoint)?;
        let reply = object(ObjectType::Reply)?;
        let badged = mem::mint(faults, Rights::ALL, 0xF00).map_err(|_| "mint")?;
        let thread = Thread::spawn_with(entry, pack(report, 0, 0), 1, Some(badged)).map_err(|_| "spawn")?;
        let (word, badge) = sys::recv_reply(faults, reply).map_err(|_| "no fault arrived")?;
        let mut words = sys::received_words();
        words[0] = word;
        Ok(Self { words, badge, faults, badged, reply, thread })
    }

    /// Stops the thread and frees the fault endpoint, its copy, the reply
    /// object, and `more`.
    fn clean_up(self, more: &[Slot]) -> Result<(), &'static str> {
        self.thread.reap();
        release(&[self.badged, self.faults, self.reply])?;
        release(more)
    }
}

/// A page fault in a thread arrives at its fault endpoint as a call, with the
/// fault's vector, address, instruction, and error code.
fn page_fault_reaches_its_handler(_: &BootInfo) -> Result<(), &'static str> {
    let report = object(ObjectType::Endpoint)?;
    let caught = Caught::fault_of(read_fault_page, report)?;
    let (words, badge) = (caught.words, caught.badge);
    caught.clean_up(&[report])?;
    ensure(badge == 0xF00, "the fault did not carry the handler's badge")?;
    ensure(words[0] == PAGE_FAULT, "not a page fault")?;
    ensure(words[1] == FAULT_PAGE, "wrong fault address")?;
    ensure(words[2] >= layout::ROOT_IMAGE_BASE && words[2] < layout::ROOT_IMAGE_LIMIT, "the faulting instruction is not in the image")?;
    // a user-mode read of a page that is not present.
    ensure(words[3] & 0b111 == 0b100, "wrong error code")
}

/// An invalid opcode arrives the same way, with no address.
fn invalid_opcode_reaches_its_handler(_: &BootInfo) -> Result<(), &'static str> {
    let report = object(ObjectType::Endpoint)?;
    let caught = Caught::fault_of(execute_ud2, report)?;
    let words = caught.words;
    caught.clean_up(&[report])?;
    ensure(words[0] == INVALID_OPCODE && words[1] == 0, "not an invalid opcode")
}

/// A thread with no fault handler is stopped by its fault, and nothing else
/// is: this check keeps running, and the thread never reports.
fn fault_without_a_handler_stops_only_that_thread(_: &BootInfo) -> Result<(), &'static str> {
    let report = object(ObjectType::Endpoint)?;
    let thread = Thread::spawn(read_fault_page, pack(report, 0, 0), 1).map_err(|_| "spawn")?;
    spin_past_a_tick();
    let reported = sys::recv(report);
    thread.reap();
    release(&[report])?;
    ensure(reported == Err(IpcSyscallError::WouldBlock), "the faulting thread went on")
}

/// A handler that maps the missing page and answers resumes the thread at the
/// faulting instruction, with its registers as they were, and the load now
/// reads what the handler put there: demand paging from userspace.
fn handled_page_fault_resumes_the_thread(_: &BootInfo) -> Result<(), &'static str> {
    let report = object(ObjectType::Endpoint)?;
    let caught = Caught::fault_of(load_with_live_registers, report)?;
    let page = mem::map_new_page(FAULT_PAGE).map_err(|_| "map the page")?;
    // SAFETY: the page was just mapped writable here, and the thread that will
    // read it is parked until the reply below.
    unsafe { core::ptr::write_volatile(FAULT_PAGE as *mut u64, 0x77) };
    let answered = sys::reply(caught.reply, 0);
    let got = sys::recv_blocking(report);
    let words = caught.words;
    sys::unmap(page).map_err(|_| "unmap")?;
    caught.clean_up(&[page, report])?;
    ensure(words[0] == PAGE_FAULT, "not a page fault")?;
    ensure(answered.is_ok(), "the reply was refused")?;
    ensure(got == Ok((0x77, 0)), "the resumed thread did not read the mapped page")
}

/// Parks in a receive on field 0 ([`park_after_answering`], started on field
/// 1, reply object in field 2) and reports on field 1 the error code it ended
/// with, or 0 if a message came.
extern "C" fn receive_and_report_error(arg: u64) {
    let (inbox, report, reply) = (field(arg, 0), field(arg, 1), field(arg, 2));
    let code = park_after_answering(inbox, report, reply).err().map_or(0, |e| e as u64);
    let _ = sys::send_blocking(report, code);
}

/// Parks to receive a call on field 0 ([`park_after_answering`], started on
/// field 1, reply object in field 2) and answers it with the reply object's
/// slot, which tells the threads apart.
extern "C" fn answer_with_reply_slot(arg: u64) {
    let (ep, start, reply) = (field(arg, 0), field(arg, 1), field(arg, 2));
    if park_after_answering(ep, start, reply).is_ok() {
        let _ = sys::reply(reply, reply);
    }
}

/// A timed receive on an endpoint nothing sends to gives up, and leaves no
/// trace behind: a later send is not handed to the receiver that gave up, but
/// waits in the endpoint for the next receive.
fn a_timed_receive_runs_out(_: &BootInfo) -> Result<(), &'static str> {
    let ep = object(ObjectType::Endpoint)?;
    let waited = sys::recv_timeout(ep, None, 100);
    let sent = sys::send(ep, 9);
    let later = sys::recv(ep);
    release(&[ep])?;
    ensure(waited == Err(IpcSyscallError::TimedOut), "the receive did not time out")?;
    ensure(sent.is_ok() && later == Ok((9, 0)), "the receiver that timed out still took a message")
}

/// A timed receive takes a message that comes before its time is up.
fn a_timed_receive_takes_what_arrives_in_time(_: &BootInfo) -> Result<(), &'static str> {
    let ep = object(ObjectType::Endpoint)?;
    let thread = Thread::spawn(double_and_report, pack(ep, 0, 4), 1).map_err(|_| "spawn")?;
    let got = sys::recv_timeout(ep, None, 5000);
    thread.reap();
    release(&[ep])?;
    ensure(got == Ok((8, 0)), "the message did not arrive in time")
}

/// Revoking the last capability to an endpoint ends the wait of a thread
/// parked in a blocking receive on it, with `BadCap`, instead of leaving it
/// parked on an endpoint nothing names (seL4's cancel-all-IPC).
fn revoking_an_endpoint_ends_its_waits(_: &BootInfo) -> Result<(), &'static str> {
    let inbox = object(ObjectType::Endpoint)?;
    let report = object(ObjectType::Endpoint)?;
    let reply = object(ObjectType::Reply)?;
    let waiter = spawn_parked(receive_and_report_error, pack(inbox, report, reply), report)?;
    release(&[inbox])?;
    let ended = sys::recv_timeout(report, None, 2000);
    waiter.reap();
    release(&[report, reply])?;
    ensure(ended != Err(IpcSyscallError::TimedOut), "the revoke left the waiter parked")?;
    ensure(ended == Ok((IpcSyscallError::BadCap as u64, 0)), "the waiter did not end with BadCap")
}

/// A call goes to the receiver that has waited longest, even when a newer
/// receiver parked in a table entry that a third thread freed before it.
fn calls_reach_the_longest_waiting_receiver(_: &BootInfo) -> Result<(), &'static str> {
    let ep = object(ObjectType::Endpoint)?;
    let (inbox, report) = (object(ObjectType::Endpoint)?, object(ObjectType::Endpoint)?);
    let bystander_reply = object(ObjectType::Reply)?;
    let (first_reply, second_reply) = (object(ObjectType::Reply)?, object(ObjectType::Reply)?);
    // a bystander parks first, then the oldest receiver behind it.
    let bystander = spawn_parked(receive_and_report, pack(inbox, report, bystander_reply), report)?;
    let first = spawn_parked(answer_with_reply_slot, pack(ep, report, first_reply), report)?;
    // waking the bystander frees its entry, which the newer receiver takes.
    let woke = sys::send_blocking(inbox, 3).and_then(|()| sys::recv_blocking(report));
    let second = spawn_parked(answer_with_reply_slot, pack(ep, report, second_reply), report)?;
    let answers = (sys::call(ep, 0), sys::call(ep, 0));
    for thread in [bystander, first, second] {
        thread.reap();
    }
    release(&[ep, inbox, report, bystander_reply, first_reply, second_reply])?;
    ensure(woke == Ok((3, 0)), "the bystander did not take its message")?;
    ensure(answers.0 == Ok(first_reply), "the call skipped the receiver that waited longest")?;
    ensure(answers.1 == Ok(second_reply), "the second call did not reach the newer receiver")
}
