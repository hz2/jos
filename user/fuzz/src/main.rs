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
#![no_std]
#![no_main]
#![warn(clippy::pedantic)]

use libjos::abi::{
    CNODE_SIZE_BITS, ENOSYS, IPC_ERR_FLAG, InvokeError, IpcSyscallError, MintSyscallError, ProcessStart,
    RetypeSyscallError, Syscall, encode_object_type, layout, pack_cnode_copy,
};
use libjos::jos_core::untyped::ObjectType;
use libjos::jos_core::rng::{KernelRng, OpMix, SimRng};
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
/// not make: one that ends the machine or this process, blocks with no way
/// to be woken, or moves its own IPC buffer out from under it.
fn answer(nr: u64) -> Option<Answer> {
    let Some(call) = Syscall::from_u64(nr) else { return Some(Answer::Unknown) };
    Some(match call {
        Syscall::Exit
        | Syscall::IpcSendBlocking
        | Syscall::IpcRecvBlocking
        | Syscall::Call
        | Syscall::RecvReply
        | Syscall::ReplyRecv
        | Syscall::SetIpcBuffer
        | Syscall::ThreadExit => return None,
        Syscall::Add => Answer::Any,
        Syscall::Retype => Answer::Retype,
        Syscall::Mint => Answer::Mint,
        Syscall::Invoke => Answer::Invoke,
        Syscall::IpcRecv | Syscall::Revoke | Syscall::RecvTimeout | Syscall::ConsoleRead | Syscall::Wait => {
            Answer::Flagged
        }
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

/// Runs the storm and returns how many answers were undocumented.
fn main(start: &ProcessStart) -> u64 {
    let mut rng = SimRng::new(start.arg);
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
        start.arg, STEPS, slots.retyped, undocumented
    );
    undocumented
}
