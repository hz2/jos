//! Starting a program from its ELF image as a process of its own.
//!
//! The kernel loads only the root task. Every other program is started by a
//! program already running, out of that program's untyped memory, the seL4
//! way. [`Process::spawn`] does for a program what the kernel did for the root
//! task: it plans the load with the same `jos_core::elf` planner, then builds a
//! fresh address space holding the image, a stack, and an IPC buffer in the
//! root task's layout, a capability space with the three capabilities a process
//! is given ([`process_slot`]), and a thread, and starts it.
//!
//! Each frame is filled through a brief mapping at [`SCRATCH`] in the
//! spawner's own address space before it is mapped into the process, so the
//! process's memory is never mapped beside the spawner's. Spawn from one
//! thread at a time, since they would share that page. The spawner keeps a
//! capability to every object it made, and [`Process::reap`] revokes them all.

use jos_core::cap_rights::Rights;
use jos_core::elf::{ElfError, LoadPlan, LoadSegment, Relocation};
use jos_core::untyped::ObjectType;

use crate::abi::layout::{ROOT_IMAGE_BASE, ROOT_IMAGE_LIMIT, ROOT_IPC_BUFFER, ROOT_STACK_TOP, SCRATCH};
use crate::abi::{CNODE_SIZE_BITS, IpcSyscallError, PROCESS_START, PROCESS_START_MAGIC, map_flags, process_slot};
use crate::mem::{self, Error};
use crate::sys::{self, Slot};

/// Pages of stack a process gets.
pub const STACK_PAGES: u64 = 4;

/// The most frames and page tables one process can be built from.
const MAX_OBJECTS: usize = 48;

/// Bytes in a page.
const PAGE: u64 = 0x1000;

/// Bytes in a page, as an array length.
const PAGE_BYTES: usize = 0x1000;

/// Why a process could not be started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpawnError {
    /// The image is not a program the loader takes.
    Image(ElfError),
    /// The image needs more frames and tables than a process is built from.
    TooBig,
    /// A slot, a retype, or a syscall was refused while building it.
    Build(Error),
}

impl From<Error> for SpawnError {
    fn from(e: Error) -> Self {
        Self::Build(e)
    }
}

impl From<IpcSyscallError> for SpawnError {
    fn from(e: IpcSyscallError) -> Self {
        Self::Build(Error::Ipc(e))
    }
}

/// A capability [`Process::spawn_with`] copies into the new process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    /// Its slot in this program's capability space.
    pub from: Slot,
    /// The slot it lands in, in the process's.
    pub to: Slot,
    /// The rights the copy keeps.
    pub rights: Rights,
}

/// A process this program started, and the capabilities it is built from.
pub struct Process {
    /// Its thread, once retyped.
    tcb: Option<Slot>,
    /// Its capability space.
    cnode: Option<Slot>,
    /// Its address space.
    vspace: Option<Slot>,
    /// Every frame and page table made for it.
    objects: [Slot; MAX_OBJECTS],
    /// How many of `objects` are live.
    count: usize,
}

impl Process {
    /// Starts the ELF `image` as a process, with `arg` in its start record.
    /// It gets this program's console, attenuated to `WRITE`; `parent`, an
    /// endpoint, also with `WRITE` only, to report on and to receive its exit
    /// code from (badge it to tell processes apart); and `faults`, as its
    /// fault handler.
    ///
    /// # Errors
    ///
    /// Why the image cannot be loaded or a step of building the process was
    /// refused; whatever was built by then is revoked again.
    pub fn spawn(image: &[u8], parent: Slot, faults: Slot, arg: u64) -> Result<Self, SpawnError> {
        Self::spawn_with(image, parent, faults, arg, &[])
    }

    /// Like [`spawn`](Self::spawn), and copies each of `grants` into the
    /// process's capability space too, attenuated to its rights, at a slot
    /// past the three every process gets.
    ///
    /// # Errors
    ///
    /// As [`spawn`](Self::spawn), and [`IpcSyscallError::SlotOccupied`] for a
    /// grant aimed at a slot already filled.
    pub fn spawn_with(image: &[u8], parent: Slot, faults: Slot, arg: u64, grants: &[Grant]) -> Result<Self, SpawnError> {
        let plan = LoadPlan::parse(image, ROOT_IMAGE_BASE, (ROOT_IMAGE_BASE, ROOT_IMAGE_LIMIT)).map_err(SpawnError::Image)?;
        let mut process = Self { tcb: None, cnode: None, vspace: None, objects: [0; MAX_OBJECTS], count: 0 };
        match process.build(&plan, image, parent, faults, arg, grants) {
            Ok(()) => Ok(process),
            Err(e) => {
                process.release();
                Err(e)
            }
        }
    }

    /// Stops the process for good and revokes everything it was built from.
    pub fn reap(mut self) {
        self.release();
    }

    /// Builds the address space, the capability space, and the thread, and
    /// starts it.
    fn build(
        &mut self,
        plan: &LoadPlan,
        image: &[u8],
        parent: Slot,
        faults: Slot,
        arg: u64,
        grants: &[Grant],
    ) -> Result<(), SpawnError> {
        let vspace = mem::retype(ObjectType::VSpace)?;
        self.vspace = Some(vspace);
        let cnode = mem::retype(ObjectType::CNode { size_bits: CNODE_SIZE_BITS })?;
        self.cnode = Some(cnode);
        for segment in plan.segments() {
            let flags = if segment.flags.write {
                map_flags::WRITE
            } else if segment.flags.execute {
                map_flags::EXECUTE
            } else {
                0
            };
            let mut page = segment.page_start();
            while page < segment.page_end() {
                let frame = self.frame(|bytes| {
                    copy_file_bytes(bytes, page, segment, image);
                    for relocation in plan.relocations(image) {
                        patch(bytes, page, &relocation);
                    }
                })?;
                self.map(vspace, frame, page, flags)?;
                page += PAGE;
            }
        }
        for n in 1..=STACK_PAGES {
            let page = ROOT_STACK_TOP - n * PAGE;
            let frame = self.frame(|bytes| {
                if n == 1 {
                    // the start record, at the process's initial stack pointer.
                    let at = index(PROCESS_START - page);
                    bytes[at..at + 8].copy_from_slice(&PROCESS_START_MAGIC.to_le_bytes());
                    bytes[at + 8..at + 16].copy_from_slice(&arg.to_le_bytes());
                }
            })?;
            self.map(vspace, frame, page, map_flags::WRITE)?;
        }
        let ipc_buffer = self.frame(|_| {})?;
        self.map(vspace, ipc_buffer, ROOT_IPC_BUFFER, map_flags::WRITE)?;
        let console = crate::console::slot().ok_or(SpawnError::Build(Error::Ipc(IpcSyscallError::BadCap)))?;
        sys::cnode_copy(cnode, console, process_slot::CONSOLE, Rights::WRITE)?;
        sys::cnode_copy(cnode, parent, process_slot::PARENT, Rights::WRITE)?;
        sys::cnode_copy(cnode, faults, process_slot::FAULTS, Rights::WRITE)?;
        for grant in grants {
            sys::cnode_copy(cnode, grant.from, grant.to, grant.rights)?;
        }
        let tcb = mem::retype(ObjectType::Tcb)?;
        self.tcb = Some(tcb);
        sys::tcb_configure(tcb, cnode, vspace)?;
        sys::tcb_set_ipc_buffer(tcb, ipc_buffer)?;
        sys::tcb_set_fault_handler(tcb, process_slot::FAULTS)?;
        sys::tcb_start(tcb, plan.entry(), PROCESS_START)?;
        Ok(())
    }

    /// Retypes a frame for the process and fills it through the scratch page:
    /// `fill` gets the frame's bytes, zeroed.
    fn frame(&mut self, fill: impl FnOnce(&mut [u8; PAGE_BYTES])) -> Result<Slot, SpawnError> {
        let frame = self.keep(mem::retype(ObjectType::Frame)?)?;
        mem::map(frame, SCRATCH, map_flags::WRITE)?;
        // SAFETY: the frame was just mapped writable at SCRATCH, a page nothing
        // else in this program uses, and no other reference to it is live.
        fill(unsafe { &mut *(SCRATCH as *mut [u8; PAGE_BYTES]) });
        sys::unmap(frame)?;
        Ok(frame)
    }

    /// Maps `frame` at `vaddr` in the process's address space, keeping any
    /// page table made for the path.
    fn map(&mut self, vspace: Slot, frame: Slot, vaddr: u64, flags: u64) -> Result<(), SpawnError> {
        let mut tables = [0; 4];
        let mut made = 0;
        let mapped = mem::map_in(vspace, frame, vaddr, flags, |table| {
            tables[made] = table;
            made += 1;
        });
        for &table in &tables[..made] {
            self.keep(table)?;
        }
        mapped.map_err(SpawnError::from)
    }

    /// Records `object` among the process's objects, or revokes it again if
    /// there is no room.
    fn keep(&mut self, object: Slot) -> Result<Slot, SpawnError> {
        if self.count == MAX_OBJECTS {
            let _ = mem::release(object);
            return Err(SpawnError::TooBig);
        }
        self.objects[self.count] = object;
        self.count += 1;
        Ok(object)
    }

    /// Revokes the thread first, so it stops before its memory goes, then
    /// every frame and table, then the capability and address spaces.
    fn release(&mut self) {
        if let Some(tcb) = self.tcb.take() {
            let _ = mem::release(tcb);
        }
        for &object in self.objects[..self.count].iter().rev() {
            let _ = mem::release(object);
        }
        self.count = 0;
        for space in [self.cnode.take(), self.vspace.take()].into_iter().flatten() {
            let _ = mem::release(space);
        }
    }
}

/// Converts an offset the load plan bounds into an index.
fn index(offset: u64) -> usize {
    usize::try_from(offset).unwrap_or(usize::MAX)
}

/// Copies the part of `segment`'s file bytes that falls in the page at `page`
/// into `bytes`, that page's contents.
fn copy_file_bytes(bytes: &mut [u8], page: u64, segment: &LoadSegment, image: &[u8]) {
    let from = page.max(segment.vaddr);
    let to = (page + PAGE).min(segment.vaddr + segment.file_size);
    if from < to {
        let src = index(segment.file_offset + (from - segment.vaddr));
        let (dst, len) = (index(from - page), index(to - from));
        // the plan keeps the file bytes inside the image.
        bytes[dst..dst + len].copy_from_slice(&image[src..src + len]);
    }
}

/// Writes the bytes of `relocation` that fall in the page at `page` into
/// `bytes`, that page's contents.
fn patch(bytes: &mut [u8], page: u64, relocation: &Relocation) {
    for (at, byte) in (relocation.target..).zip(relocation.value.to_le_bytes()) {
        if (page..page + PAGE).contains(&at) {
            bytes[index(at - page)] = byte;
        }
    }
}
