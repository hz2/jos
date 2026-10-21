//! Throws seeded random syscalls at the kernel and checks every answer.
//!
//! The root task starts this from the `fuzz` boot module as a process that
//! holds almost nothing: its console, its parent, its fault endpoint, and an
//! untyped region at [`UNTYPED`] to retype objects from, so whatever it does
//! can only reach what it made itself. Its argument is the seed. Each step
//! picks a syscall by a swarm mix (per-seed weights, so some seeds hammer a
//! few calls and leave others out) and arguments biased toward the values
//! that reach deep paths: small slot numbers, page-aligned user addresses,
//! and the edges of the range.
//!
//! Two oracles: the kernel must survive every call, and every answer must be
//! one the ABI documents for that call. It exits with the number of answers
//! that were not, after printing each as a KTAP diagnostic.
//!
//! With [`DIFFERENTIAL`] set in the argument it runs a differential storm
//! instead: only the calls `jos_core::spec` answers, each made on the kernel
//! and on the spec, and it exits with 1 at the first answer that differs,
//! after printing both.
#![no_std]
#![no_main]
#![warn(clippy::pedantic)]

use libjos::abi::{
    CNODE_SIZE_BITS, ENOSYS, IPC_ERR_FLAG, InvokeError, IpcSyscallError, MintSyscallError, ProcessStart,
    RetypeSyscallError, Syscall, encode_object_type, layout, pack_cnode_copy,
};
use libjos::jos_core::untyped::ObjectType;
use libjos::jos_core::cap_rights::Rights;
use libjos::jos_core::rng::{KernelRng, OpMix, SimRng};
use libjos::jos_core::spec::{self, Kind, Spec};
use libjos::println;
use libjos::syscall::syscall3;

libjos::process_entry!(main);

/// Syscalls per run.
pub const STEPS: u64 = 2000;

/// The slot the parent puts an untyped region in.
pub const UNTYPED: u64 = 4;

/// The number of syscalls the mix picks among, and one past the last.
const SYSCALLS: usize = Syscall::ALL.len() + 1;

/// The longest a waiting call may wait, in milliseconds.
const MAX_WAIT_MS: u64 = 20;

/// What a call's answer may be, by the ABI.
#[derive(Clone, Copy, Debug)]
enum Answer {
    /// Any value.
    Any,
    /// 0, or an [`IpcSyscallError`] code.
    Status,
    /// A value below [`IPC_ERR_FLAG`], or a flagged [`IpcSyscallError`] code.
    Flagged,
    /// 0, or a [`RetypeSyscallError`] code.
    Retype,
    /// A slot, or a flagged [`MintSyscallError`] code.
    Mint,
    /// A value, or a flagged [`InvokeError`] code.
    Invoke,
    /// [`ENOSYS`]: there is no such call.
    Unknown,
}

/// Returns what `nr`'s answer may be, or `None` for a call this program does
/// not make: one that ends this process, blocks with no way to be woken, or
/// moves its own IPC buffer out from under it. (The ambient `exit`, which
/// would end the machine, is gone once a root task runs, so it is made.)
fn answer(nr: u64) -> Option<Answer> {
    let Some(call) = Syscall::from_u64(nr) else { return Some(Answer::Unknown) };
    Some(match call {
        Syscall::IpcSendBlocking
        | Syscall::IpcRecvBlocking
        | Syscall::Call
        | Syscall::RecvReply
        | Syscall::ReplyRecv
        | Syscall::SetIpcBuffer
        | Syscall::ThreadExit => return None,
        Syscall::Add => Answer::Any,
        // a process under a root task has no ambient way to stop the machine.
        Syscall::Exit => Answer::Unknown,
        Syscall::Retype => Answer::Retype,
        Syscall::Mint => Answer::Mint,
        Syscall::Invoke => Answer::Invoke,
        Syscall::IpcRecv
        | Syscall::Revoke
        | Syscall::RecvTimeout
        | Syscall::ConsoleRead
        | Syscall::Wait
        | Syscall::SelfCheck => Answer::Flagged,
        _ => Answer::Status,
    })
}

/// Returns whether `rax` is an answer of kind `answer`.
fn documented(answer: Answer, rax: u64) -> bool {
    let flagged = rax & IPC_ERR_FLAG != 0;
    let code = rax & !IPC_ERR_FLAG;
    match answer {
        Answer::Any => true,
        Answer::Status => rax == 0 || IpcSyscallError::from_code(rax).is_some(),
        Answer::Flagged => !flagged || IpcSyscallError::from_code(code).is_some(),
        Answer::Retype => rax == 0 || RetypeSyscallError::from_code(rax).is_some(),
        Answer::Mint => !flagged || MintSyscallError::from_code(code).is_some(),
        Answer::Invoke => !flagged || InvokeError::from_code(code).is_some(),
        Answer::Unknown => rax == ENOSYS,
    }
}

/// What an argument is, so the fuzzer can mostly pick values that get past
/// the first checks and reach the deeper paths.
#[derive(Clone, Copy)]
enum Arg {
    /// A slot that should hold a capability.
    Live,
    /// A slot that should be empty, for a new capability.
    Free,
    /// An object type word, as `retype` takes it.
    Type,
    /// A user address, page aligned, perhaps with flag bits.
    Address,
    /// A wait, in milliseconds.
    Wait,
    /// A `cnode_copy` target: a slot and a rights mask, packed.
    Target,
    /// Any word.
    Word,
}

/// The arguments `call` takes.
fn schema(call: Syscall) -> [Arg; 3] {
    use Arg::{Address, Free, Live, Target, Type, Wait, Word};
    match call {
        Syscall::Retype => [Live, Type, Free],
        Syscall::CNodeCopy => [Live, Live, Target],
        Syscall::MapPageTable | Syscall::MapFrame => [Live, Live, Address],
        Syscall::TcbConfigure => [Live, Live, Live],
        Syscall::TcbSetIpcBuffer | Syscall::TcbSetFaultHandler => [Live, Live, Word],
        Syscall::TcbStart => [Live, Address, Address],
        Syscall::RecvTimeout => [Live, Live, Wait],
        Syscall::Wait => [Live, Wait, Word],
        Syscall::ConsoleRead => [Live, Word, Wait],
        _ => [Live, Word, Word],
    }
}

/// The object types `retype` can make.
const TYPES: [ObjectType; 8] = [
    ObjectType::Endpoint,
    ObjectType::CNode { size_bits: CNODE_SIZE_BITS },
    ObjectType::PageTable,
    ObjectType::Tcb,
    ObjectType::Frame,
    ObjectType::Notification,
    ObjectType::Reply,
    ObjectType::VSpace,
];

/// The most objects one run retypes: untyped memory is not reclaimed, so a
/// sweep of many seeds must not exhaust it.
const MAX_OBJECTS: usize = 24;

/// What the fuzzer knows of its own capability space: the slots it believes
/// hold capabilities.
struct Slots {
    /// The slots believed live.
    live: [u64; 64],
    /// How many of `live` are set.
    count: usize,
    /// How many objects this run retyped.
    retyped: usize,
}

impl Slots {
    /// Returns a slot believed live, or `None` if none is.
    fn pick(&self, rng: &mut SimRng) -> Option<u64> {
        (self.count > 0).then(|| self.live[index(rng.below(self.count as u64))])
    }

    /// Records that `slot` now holds a capability.
    fn add(&mut self, slot: u64) {
        if self.count < self.live.len() && !self.live[..self.count].contains(&slot) {
            self.live[self.count] = slot;
            self.count += 1;
        }
    }

    /// Records that `slot` no longer holds a capability.
    fn remove(&mut self, slot: u64) {
        if let Some(i) = self.live[..self.count].iter().position(|&s| s == slot) {
            self.count -= 1;
            self.live[i] = self.live[self.count];
        }
    }
}

/// Converts a value below a small bound into an index.
fn index(value: u64) -> usize {
    usize::try_from(value).unwrap_or(0)
}

/// Picks a hostile word: any value at all, biased to the edges.
fn hostile(rng: &mut SimRng) -> u64 {
    match rng.below(6) {
        0 => 0,
        1 => rng.below(70),
        2 => rng.below(0x1000),
        3 => u64::MAX - rng.below(4),
        4 => layout::USER_START + (rng.below(1 << 32) & !0xfff) + rng.below(4),
        _ => rng.next_u64(),
    }
}

/// Picks a value for an argument of kind `arg`: mostly a plausible one, and
/// one time in eight a hostile one.
fn argument(arg: Arg, rng: &mut SimRng, slots: &Slots) -> u64 {
    if rng.below(8) == 0 {
        return hostile(rng);
    }
    match arg {
        Arg::Live => slots.pick(rng).unwrap_or_else(|| rng.below(70)),
        Arg::Free => 4 + rng.below(60),
        Arg::Type => encode_object_type(TYPES[index(rng.below(TYPES.len() as u64))]),
        Arg::Address => layout::USER_START + (rng.below(1 << 20) << 12) + rng.below(4),
        Arg::Wait => rng.below(MAX_WAIT_MS + 1),
        Arg::Target => pack_cnode_copy(u16::try_from(4 + rng.below(60)).unwrap_or(4), u8::try_from(rng.below(16)).unwrap_or(0)),
        Arg::Word => hostile(rng),
    }
}

/// Runs the storm the argument asks for: the differential one when it has
/// [`DIFFERENTIAL`] set, the robustness one otherwise.
fn main(start: &ProcessStart) -> u64 {
    if start.arg & DIFFERENTIAL != 0 {
        differential(start.arg & !DIFFERENTIAL)
    } else {
        robustness(start.arg)
    }
}

/// The bit of the argument that picks the differential storm; the rest is
/// the seed.
pub const DIFFERENTIAL: u64 = 1 << 62;

/// The calls the differential storm makes: the ones the spec answers.
const SPEC_CALLS: [Syscall; 9] = [
    Syscall::Add,
    Syscall::Retype,
    Syscall::Mint,
    Syscall::Revoke,
    Syscall::IpcSend,
    Syscall::IpcRecv,
    Syscall::Invoke,
    Syscall::Signal,
    Syscall::Wait,
];

/// Picks a slot for the differential storm: mostly one the spec says is
/// live, sometimes any slot, sometimes one past the end.
fn spec_slot(rng: &mut SimRng, spec: &Spec) -> u64 {
    let live = (0..spec::SLOTS as u64).filter(|&s| spec.is_live(s) && !(1..=3).contains(&s));
    let count = live.clone().count() as u64;
    let slot = match rng.below(8) {
        0 => spec::SLOTS as u64 + rng.below(8),
        1 | 2 => rng.below(spec::SLOTS as u64),
        _ if count > 0 => live.clone().nth(index(rng.below(count))).unwrap_or(0),
        _ => rng.below(spec::SLOTS as u64),
    };
    // never the three capabilities this process lives on.
    if (1..=3).contains(&slot) { 0 } else { slot }
}

/// Picks a word to send: almost always a valid one, sometimes one with bit
/// 63 set, which every send must refuse.
fn spec_word(rng: &mut SimRng) -> u64 {
    match rng.below(16) {
        0 => IPC_ERR_FLAG | rng.next_u64(),
        1 => 0,
        _ => rng.next_u64() & !IPC_ERR_FLAG,
    }
}

/// Picks the arguments of `call` for the differential storm.
fn spec_args(call: Syscall, rng: &mut SimRng, spec: &Spec) -> [u64; 3] {
    let slot = spec_slot(rng, spec);
    match call {
        Syscall::Add => [rng.next_u64(), rng.next_u64(), 0],
        Syscall::Retype => {
            let type_word = match rng.below(10) {
                0 => rng.next_u64(),
                1 => encode_object_type(ObjectType::CNode { size_bits: u8::try_from(rng.below(32)).unwrap_or(0) }),
                _ => encode_object_type(TYPES[index(rng.below(TYPES.len() as u64))]),
            };
            let untyped = if rng.below(4) == 0 { slot } else { UNTYPED };
            [untyped, type_word, spec_slot(rng, spec)]
        }
        Syscall::Mint => {
            let badge = match rng.below(8) {
                0..=3 => 0,
                4 => IPC_ERR_FLAG | rng.next_u64(),
                _ => rng.below(1 << 16),
            };
            [slot, rng.below(256), badge]
        }
        Syscall::IpcSend => [slot, spec_word(rng), 0],
        Syscall::Invoke => [slot, rng.below(3), spec_word(rng)],
        // a slot alone: revoke, recv, signal, and wait, whose 0 ms make it a poll.
        _ => [slot, 0, 0],
    }
}

/// Runs the same calls on the kernel and on the spec, and returns 1 at the
/// first answer that differs, after printing it, or 0 if none did.
fn differential(seed: u64) -> u64 {
    let mut rng = SimRng::new(seed);
    let mix: OpMix<{ SPEC_CALLS.len() }> = OpMix::swarm(&mut rng);
    // the space as the parent built it: three capabilities never named, then
    // the untyped region.
    let mut spec = Spec::new();
    for slot in 1..=3 {
        spec.give(slot, Kind::Other, Rights::WRITE);
    }
    spec.give(index(UNTYPED), Kind::Untyped, Rights::ALL);
    let mut retyped = 0;
    for step in 0..STEPS {
        let call = SPEC_CALLS[mix.pick(&mut rng)];
        let args = spec_args(call, &mut rng, &spec);
        if (call == Syscall::Retype && retyped == MAX_OBJECTS) || (call == Syscall::Revoke && args[0] == UNTYPED) {
            continue;
        }
        let (rax, rdx) = syscall3(call as u64, args[0], args[1], args[2]);
        let expected = match call {
            Syscall::Add => Spec::add(args[0], args[1]),
            Syscall::Retype => spec.retype(args[0], args[1], args[2], rax == RetypeSyscallError::NoRoom as u64),
            Syscall::Mint => spec.mint(args[0], args[1], args[2]),
            Syscall::Revoke => spec.revoke(args[0]),
            Syscall::IpcSend => spec.send(args[0], args[1]),
            Syscall::IpcRecv => spec.recv(args[0]),
            Syscall::Invoke => spec.invoke(args[0], args[1], args[2]),
            Syscall::Signal => spec.signal(args[0]),
            _ => spec.poll(args[0]),
        };
        if call == Syscall::Retype && rax == 0 {
            retyped += 1;
        }
        if expected.rax != rax || expected.rdx.is_some_and(|want| want != rdx) {
            println!(
                "# spec: step {} {:?} {:x?}: the kernel answered {:#x} (rdx {:#x}), the spec {:#x} (rdx {:x?})",
                step, call, args, rax, rdx, expected.rax, expected.rdx
            );
            return 1;
        }
    }
    println!("# spec: seed {} made {} calls, retyped {} objects, every answer as the spec says", seed, STEPS, retyped);
    0
}

/// Runs the robustness storm and returns how many answers were undocumented.
fn robustness(seed: u64) -> u64 {
    let mut rng = SimRng::new(seed);
    let mix: OpMix<SYSCALLS> = OpMix::swarm(&mut rng);
    let mut slots = Slots { live: [0; 64], count: 0, retyped: 0 };
    slots.add(UNTYPED);
    let mut undocumented = 0;
    for step in 0..STEPS {
        // the last pick stands for a number past every call.
        let pick = mix.pick(&mut rng) as u64;
        let nr = if pick < Syscall::ALL.len() as u64 { pick } else { pick + rng.below(1 << 16) };
        let Some(answer) = answer(nr) else { continue };
        let call = Syscall::from_u64(nr);
        let mut args = match call {
            Some(call) => schema(call).map(|arg| argument(arg, &mut rng, &slots)),
            None => [hostile(&mut rng), hostile(&mut rng), hostile(&mut rng)],
        };
        // never name the three capabilities this process lives on, and keep a
        // run's retypes to its budget.
        for arg in &mut args {
            if (1..=3).contains(arg) {
                *arg = 0;
            }
        }
        // a wait waits briefly at most, hostile argument or not, so a step
        // never stalls the run.
        match call {
            Some(Syscall::RecvTimeout | Syscall::ConsoleRead) => args[2] %= MAX_WAIT_MS + 1,
            Some(Syscall::Wait) => args[1] %= MAX_WAIT_MS + 1,
            _ => {}
        }
        if call == Some(Syscall::Retype) && slots.retyped == MAX_OBJECTS {
            continue;
        }
        // revoking the untyped region would take every later retype with it.
        if call == Some(Syscall::Revoke) && args[0] == UNTYPED {
            continue;
        }
        let (rax, _) = syscall3(nr, args[0], args[1], args[2]);
        if !documented(answer, rax) {
            undocumented += 1;
            println!("# fuzz: step {} syscall {} {:x?} answered {:#x}, not a documented {:?}", step, nr, args, rax, answer);
        }
        // what the answer says about the capability space.
        match call {
            Some(Syscall::Retype) if rax == 0 => {
                slots.retyped += 1;
                slots.add(args[2]);
            }
            Some(Syscall::Mint) if rax & IPC_ERR_FLAG == 0 => slots.add(rax),
            Some(Syscall::Revoke) if rax & IPC_ERR_FLAG == 0 => slots.remove(args[0]),
            _ => {}
        }
    }
    println!(
        "# fuzz: seed {} made {} calls, retyped {} objects, {} undocumented answers",
        seed, STEPS, slots.retyped, undocumented
    );
    undocumented
}
