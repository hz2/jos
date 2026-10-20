//! The root task: the first userspace program.
//!
//! The kernel loads it from the `root` boot module and starts it with every
//! initial capability: its own thread, `CNode`, and address space, its IPC
//! buffer and boot information, the console, the machine, and untyped memory
//! covering the free RAM. From here on the kernel only enforces; this program
//! decides.
//!
//! Its command line picks a mode. `hello` (the default) and `test` run the
//! first-light checks below, which exercise the capability model end to end
//! from ring 3, report them in KTAP, and halt the machine with the result.
#![no_std]
#![no_main]
#![warn(clippy::pedantic)]

use libjos::abi::{BootInfo, IpcSyscallError, layout, map_flags, root_slot};
use libjos::jos_core::cap_rights::Rights;
use libjos::jos_core::untyped::ObjectType;
use libjos::sys::{self, Slot};
use libjos::{ktap, println, rt};

libjos::root_entry!(main);

/// A first-light check: `Err` carries why it failed.
type Check = fn(&BootInfo) -> Result<(), &'static str>;

/// Every first-light check, in order.
const CHECKS: [(&str, Check); 9] = [
    ("boot_info_is_consistent", boot_info_is_consistent),
    ("add_probe_round_trips", add_probe_round_trips),
    ("endpoint_carries_a_word", endpoint_carries_a_word),
    ("badge_arrives_with_the_message", badge_arrives_with_the_message),
    ("revoke_reaches_every_copy", revoke_reaches_every_copy),
    ("fresh_page_maps_and_holds_data", fresh_page_maps_and_holds_data),
    ("writable_and_executable_is_refused", writable_and_executable_is_refused),
    ("console_without_write_is_refused", console_without_write_is_refused),
    ("machine_without_write_is_refused", machine_without_write_is_refused),
];

/// Runs the mode the command line names.
fn main(boot: &'static BootInfo) -> ! {
    describe(boot);
    let mode = boot.cmdline().split(|&b| b == b' ').next().unwrap_or(b"");
    match mode {
        b"" | b"hello" | b"test" => {
            let failed = first_light(boot);
            rt::halt(u64::from(failed != 0))
        }
        _ => {
            println!("# root: unknown mode; expected hello or test");
            rt::halt(2)
        }
    }
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

/// Runs every check, reports each in KTAP, and returns how many failed.
fn first_light(boot: &BootInfo) -> usize {
    ktap::header(CHECKS.len());
    let mut failed = 0;
    for (index, (name, check)) in CHECKS.iter().enumerate() {
        ktap::run(name);
        let result = check(boot);
        if let Err(why) = result {
            println!("# {}: {}", name, why);
            failed += 1;
        }
        ktap::report(index + 1, name, result.is_ok());
    }
    println!("# root: {} of {} checks passed", CHECKS.len() - failed, CHECKS.len());
    failed
}

/// Turns a condition into a check result.
fn ensure(condition: bool, why: &'static str) -> Result<(), &'static str> {
    if condition { Ok(()) } else { Err(why) }
}

/// The first untyped capability the kernel handed over.
fn untyped(boot: &BootInfo) -> Result<Slot, &'static str> {
    boot.untyped().first().map(|u| u.slot).ok_or("no untyped memory")
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
    ensure(boot.empty.end == boot.cnode_slots, "empty slots do not run to the end")
}

/// The arithmetic probe crosses the boundary both ways.
fn add_probe_round_trips(_: &BootInfo) -> Result<(), &'static str> {
    ensure(sys::add(40, 2) == 42, "add(40, 2) != 42")
}

/// A retyped endpoint carries a word from a send to a receive.
fn endpoint_carries_a_word(boot: &BootInfo) -> Result<(), &'static str> {
    let ep = boot.empty.start;
    sys::retype(untyped(boot)?, ObjectType::Endpoint, ep).map_err(|_| "retype endpoint")?;
    sys::send(ep, 0x1234).map_err(|_| "send")?;
    let received = sys::recv(ep).map_err(|_| "recv")?;
    ensure(received == (0x1234, 0), "wrong word or badge")?;
    ensure(sys::recv(ep) == Err(IpcSyscallError::WouldBlock), "empty endpoint did not refuse")?;
    sys::revoke(ep).map(|_| ()).map_err(|_| "revoke")
}

/// A badged copy stamps its badge on what is sent through it.
fn badge_arrives_with_the_message(boot: &BootInfo) -> Result<(), &'static str> {
    let ep = boot.empty.start;
    sys::retype(untyped(boot)?, ObjectType::Endpoint, ep).map_err(|_| "retype endpoint")?;
    let badged = sys::mint(ep, Rights::ALL, 7).map_err(|_| "mint")?;
    sys::send(badged, 99).map_err(|_| "send")?;
    let received = sys::recv(ep).map_err(|_| "recv")?;
    ensure(received == (99, 7), "badge did not arrive")?;
    sys::revoke(ep).map(|_| ()).map_err(|_| "revoke")
}

/// Revoking an endpoint removes it and the copy derived from it.
fn revoke_reaches_every_copy(boot: &BootInfo) -> Result<(), &'static str> {
    let ep = boot.empty.start;
    sys::retype(untyped(boot)?, ObjectType::Endpoint, ep).map_err(|_| "retype endpoint")?;
    let copy = sys::mint(ep, Rights::READ, 0).map_err(|_| "mint")?;
    ensure(sys::revoke(ep) == Ok(2), "revoke did not remove both")?;
    ensure(sys::recv(copy) == Err(IpcSyscallError::BadCap), "copy survived")?;
    ensure(sys::recv(ep) == Err(IpcSyscallError::BadCap), "original survived")
}

/// A page built from untyped maps into the root's own address space and
/// holds data.
fn fresh_page_maps_and_holds_data(boot: &BootInfo) -> Result<(), &'static str> {
    // a 2 MiB region of the first GiB that the image and the window leave alone.
    const VADDR: u64 = layout::USER_START + 0x1000_0000;
    let (table, frame) = (boot.empty.start, boot.empty.start + 1);
    let mem = untyped(boot)?;
    sys::retype(mem, ObjectType::PageTable, table).map_err(|_| "retype table")?;
    sys::retype(mem, ObjectType::Frame, frame).map_err(|_| "retype frame")?;
    sys::map_page_table(root_slot::VSPACE, table, VADDR).map_err(|_| "map table")?;
    sys::map_frame(root_slot::VSPACE, frame, VADDR, map_flags::WRITE).map_err(|_| "map frame")?;
    let word = VADDR as *mut u64;
    // SAFETY: the frame was just mapped writable at VADDR and nothing else
    // refers to that page.
    let seen = unsafe {
        word.write_volatile(0xFEED_F00D);
        word.read_volatile()
    };
    ensure(seen == 0xFEED_F00D, "page did not hold the word")?;
    sys::unmap(frame).map_err(|_| "unmap")?;
    sys::revoke(frame).map_err(|_| "revoke frame")?;
    sys::revoke(table).map(|_| ()).map_err(|_| "revoke table")
}

/// The kernel never maps a page both writable and executable.
fn writable_and_executable_is_refused(boot: &BootInfo) -> Result<(), &'static str> {
    const VADDR: u64 = layout::USER_START + 0x1000_0000;
    let (table, frame) = (boot.empty.start, boot.empty.start + 1);
    let mem = untyped(boot)?;
    sys::retype(mem, ObjectType::PageTable, table).map_err(|_| "retype table")?;
    sys::retype(mem, ObjectType::Frame, frame).map_err(|_| "retype frame")?;
    sys::map_page_table(root_slot::VSPACE, table, VADDR).map_err(|_| "map table")?;
    let wx = sys::map_frame(root_slot::VSPACE, frame, VADDR, map_flags::WRITE | map_flags::EXECUTE);
    ensure(wx == Err(IpcSyscallError::WritableExecutable), "w+x mapping was not refused")?;
    sys::revoke(frame).map_err(|_| "revoke frame")?;
    sys::revoke(table).map(|_| ()).map_err(|_| "revoke table")
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
