//! The root task: building and starting the first userspace thread.
//!
//! This is the seL4 root-server model. At boot the kernel creates exactly one
//! thread, from the boot module named `root`, and hands it every resource as a
//! capability: its own TCB, CNode, and address space, its IPC buffer and boot
//! information pages, the console and the machine, and untyped memory covering
//! all free RAM. After that the kernel only enforces; the root task decides.
//!
//! The kernel loads the image the way any later loader will: `jos_core::elf`
//! validates it and plans the load, every object comes out of untyped memory,
//! and every page is mapped through the registry-aware [`crate::mapping`]
//! paths, so the root task's pages obey the same W^X rule as any mapping
//! userspace asks for.

use core::mem::MaybeUninit;

use jos_core::abi::{
    BOOT_INFO_MAGIC, BOOT_INFO_VERSION, BootInfo, MAX_BOOT_MODULES, MAX_BOOT_UNTYPED,
    MODULE_CMDLINE_LEN, SlotRange, UntypedDesc, layout, map_flags, root_slot,
};
use jos_core::boot_regions::PhysRange;
use jos_core::cap_rights::Rights;
use jos_core::elf::{ElfError, LoadPlan, PAGE_SIZE};
use jos_core::multiboot2::BootInformation;

use crate::arch::x86_64::multiboot2;
use crate::cap::{self, CSPACE_SLOTS, ObjectId, SavedContext, TcbState, UntypedRegion};
use crate::mapping::{self, MapError};

/// Why the root task could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootError {
    /// There is no free memory to build it from.
    NoMemory,
    /// Its untyped memory ran out while building it.
    NoRoom,
    /// The image is not a loadable ELF file.
    Image(ElfError),
    /// A mapping was refused.
    Map(MapError),
    /// A capability could not be installed.
    Cap,
}

/// The `root` boot module: the image and the arguments after its name.
pub struct RootModule {
    /// The ELF image.
    pub image: &'static [u8],
    /// The command line words after the module name.
    pub args: &'static [u8],
}

/// Finds the boot module whose command line names it `root`.
///
/// Grub passes a module's arguments as its command line; this also accepts a
/// leading path word, in case a loader includes the file name.
#[must_use]
pub fn find_root(info: BootInformation<'static>) -> Option<RootModule> {
    info.modules().find_map(|module| {
        let (name, args) = split_name(module.cmdline);
        if name != b"root" {
            return None;
        }
        // SAFETY: the module comes from grub's info structure, and the memory
        // plan reserves every module range, so its bytes are still the image.
        let image = unsafe { multiboot2::module_bytes(&module) }?;
        Some(RootModule { image, args })
    })
}

/// Splits a module command line into its name and the arguments after it,
/// skipping a leading path word (one that starts with `/`).
fn split_name(cmdline: &[u8]) -> (&[u8], &[u8]) {
    let mut rest = cmdline;
    loop {
        rest = rest.trim_ascii_start();
        let end = rest.iter().position(|&b| b == b' ').unwrap_or(rest.len());
        let (word, after) = rest.split_at(end);
        if word.first() == Some(&b'/') && !after.trim_ascii().is_empty() {
            rest = after;
            continue;
        }
        return (word, after.trim_ascii());
    }
}

/// The untyped regions handed to the root task. Each capability names the
/// `UntypedRegion` struct itself, so the structs must live forever.
static mut UNTYPED: [MaybeUninit<UntypedRegion>; MAX_BOOT_UNTYPED] =
    [const { MaybeUninit::uninit() }; MAX_BOOT_UNTYPED];

/// Builds the root task from `root` and starts it in ring 3. Never returns.
///
/// `free` is the memory the boot frame allocator has not handed out; all of it
/// becomes the root task's untyped memory. `ignored` is the usable memory
/// above the identity map, reported in the boot information.
///
/// # Panics
///
/// If the root task cannot be built: without it there is nothing to run.
///
/// # Safety
///
/// Call once, during boot, after `syscall::init_syscall`, with interrupts
/// enabled or not; `free` must be memory nothing else uses or will use.
pub unsafe fn start(
    root: &RootModule,
    info: BootInformation<'static>,
    free: impl Iterator<Item = PhysRange>,
    ignored: u64,
) -> ! {
    x86_64::instructions::interrupts::disable();
    // SAFETY: forwarded to this function's contract; interrupts are now off.
    match unsafe { build(root, info, free, ignored) } {
        // SAFETY: build returns a fully configured, registered thread.
        Ok(tcb) => unsafe { enter(tcb) },
        Err(e) => panic!("jos: cannot build the root task: {e:?}"),
    }
}

/// Builds the root task and registers it with the scheduler, returning its
/// TCB.
///
/// # Safety
///
/// As [`start`], with interrupts disabled.
unsafe fn build(
    root: &RootModule,
    info: BootInformation<'static>,
    free: impl Iterator<Item = PhysRange>,
    ignored: u64,
) -> Result<ObjectId, RootError> {
    // SAFETY: per the contract the free ranges are unused memory inside the
    // identity map, and this runs once, so UNTYPED is written by nobody else.
    let count = unsafe { make_untyped(free) };
    if count == 0 {
        return Err(RootError::NoMemory);
    }
    // the root task's own objects come out of the largest region.
    // SAFETY: the first `count` entries were just initialized.
    let regions = unsafe { &mut *core::ptr::addr_of_mut!(UNTYPED) };
    let boot = (0..count)
        // SAFETY: the first `count` entries are initialized.
        .max_by_key(|&i| unsafe { regions[i].assume_init_ref() }.free())
        .unwrap_or(0);
    // SAFETY: entry `boot` is initialized and no other reference to it is live.
    let memory = unsafe { regions[boot].assume_init_mut() };

    let cnode = memory.retype_cnode().ok_or(RootError::NoRoom)?;
    let vspace = memory.retype_vspace().ok_or(RootError::NoRoom)?;
    let tcb = memory.retype_tcb().ok_or(RootError::NoRoom)?;
    let ipc_buffer = memory.retype_frame().ok_or(RootError::NoRoom)?;
    let boot_info = memory.retype_frame().ok_or(RootError::NoRoom)?;

    let plan = load_image(memory, vspace, root.image)?;
    for page in 0..layout::ROOT_STACK_PAGES {
        let frame = memory.retype_frame().ok_or(RootError::NoRoom)?;
        map(memory, vspace, frame, layout::ROOT_STACK_BOTTOM + page * PAGE_SIZE, map_flags::WRITE)?;
    }
    map(memory, vspace, ipc_buffer, layout::ROOT_IPC_BUFFER, map_flags::WRITE)?;
    map(memory, vspace, boot_info, layout::ROOT_BOOT_INFO, 0)?;

    // SAFETY: cnode was just carved and nothing else refers to it.
    let space = unsafe { cnode.as_cnode_mut() };
    let mut install = |slot: u64, object: ObjectId| {
        let slot = usize::try_from(slot).map_err(|_| RootError::Cap)?;
        space.insert_at(slot, object, Rights::all()).map(|_| ()).map_err(|_| RootError::Cap)
    };
    install(root_slot::TCB, tcb)?;
    install(root_slot::CNODE, cnode)?;
    install(root_slot::VSPACE, vspace)?;
    install(root_slot::IPC_BUFFER, ipc_buffer)?;
    install(root_slot::BOOT_INFO, boot_info)?;
    install(root_slot::CONSOLE, cap::console_object())?;
    install(root_slot::MACHINE, cap::machine_object())?;
    for (i, slot) in (root_slot::FIRST_UNTYPED..).take(count).enumerate() {
        // SAFETY: entry i is initialized; the reference ends with this call.
        install(slot, unsafe { regions[i].assume_init_mut() }.as_object_id())?;
    }

    // SAFETY: the BootInfo frame was just carved (zeroed, which is a valid
    // BootInfo) and is reached through the identity map; nothing else holds it.
    let page = unsafe { &mut *core::ptr::with_exposed_provenance_mut::<BootInfo>(boot_info.phys_addr() as usize) };
    // SAFETY: the first `count` entries of UNTYPED are initialized.
    unsafe { describe(page, &plan, info, root.args, count, ignored) };

    // SAFETY: tcb was just carved and nothing else refers to it.
    let thread = unsafe { tcb.as_tcb_mut() };
    thread.cspace_ptr = core::ptr::from_mut(space);
    thread.cspace_root = Some(cnode);
    thread.vspace_root = vspace.phys_addr();
    thread.ipc_buffer = ipc_buffer.phys_addr();
    let selectors = crate::gdt::selectors();
    thread.context = SavedContext {
        rip: plan.entry(),
        rsp: layout::ROOT_STACK_TOP,
        rdi: layout::ROOT_BOOT_INFO,
        // IF=1 so the timer can preempt it, plus the always-one bit 1.
        rflags: 0x0000_0202,
        cs: u64::from(selectors.user_code.0),
        ss: u64::from(selectors.user_data.0),
        ..SavedContext::default()
    };
    thread.state = TcbState::Running;
    Ok(tcb)
}

/// Turns every free range into an untyped region in [`UNTYPED`], up to its
/// capacity, and returns how many there are.
///
/// # Safety
///
/// The ranges must be page-aligned, unused memory inside the identity map,
/// and nothing else may touch [`UNTYPED`] meanwhile.
unsafe fn make_untyped(free: impl Iterator<Item = PhysRange>) -> usize {
    let mut count = 0;
    for range in free.filter(|r| !r.is_empty()) {
        if count == MAX_BOOT_UNTYPED {
            crate::serial_println!("jos: more free ranges than untyped slots; {:#x} bytes left out", range.len());
            continue;
        }
        let Ok(len) = usize::try_from(range.len()) else { continue };
        let base = core::ptr::with_exposed_provenance_mut::<u8>(range.start as usize);
        // SAFETY: per the contract the range is unused, identity-mapped memory,
        // so it can back a 'static region; ranges never overlap.
        let bytes = unsafe { core::slice::from_raw_parts_mut(base, len) };
        // SAFETY: entry `count` is not initialized yet and nobody else uses UNTYPED.
        unsafe { (*core::ptr::addr_of_mut!(UNTYPED))[count].write(UntypedRegion::new(bytes)) };
        count += 1;
    }
    count
}

/// Maps `frame` at `vaddr` in `vspace`, carving and installing whatever page
/// tables the path is missing from `memory`.
fn map(memory: &mut UntypedRegion, vspace: ObjectId, frame: ObjectId, vaddr: u64, flags: u64) -> Result<(), RootError> {
    // at most one table per level is missing: a PDPT, a PD, and a PT.
    for _ in 0..4 {
        match mapping::map_frame(vspace, frame, vaddr | flags) {
            Err(MapError::MissingTable) => {
                let table = memory.retype_page_table().ok_or(RootError::NoRoom)?;
                mapping::map_table(vspace, table, vaddr).map_err(RootError::Map)?;
            }
            done => return done.map_err(RootError::Map),
        }
    }
    Err(RootError::Map(MapError::MissingTable))
}

/// Loads `image` into `vspace`: one fresh frame per page of every segment,
/// filled through the identity map and mapped with the segment's own access,
/// then the relocations applied in place.
fn load_image(memory: &mut UntypedRegion, vspace: ObjectId, image: &[u8]) -> Result<LoadPlan, RootError> {
    let window = (layout::ROOT_IMAGE_BASE, layout::ROOT_IMAGE_LIMIT);
    let plan = LoadPlan::parse(image, layout::ROOT_IMAGE_BASE, window).map_err(RootError::Image)?;
    for segment in plan.segments() {
        let flags = if segment.flags.write {
            map_flags::WRITE
        } else if segment.flags.execute {
            map_flags::EXECUTE
        } else {
            0
        };
        let file_end = segment.vaddr + segment.file_size;
        let mut page = segment.page_start();
        while page < segment.page_end() {
            let frame = memory.retype_frame().ok_or(RootError::NoRoom)?;
            // the part of the segment's file bytes that falls in this page.
            let from = page.max(segment.vaddr);
            let to = (page + PAGE_SIZE).min(file_end);
            if from < to {
                let src = (segment.file_offset + (from - segment.vaddr)) as usize;
                let len = (to - from) as usize;
                let dst = core::ptr::with_exposed_provenance_mut::<u8>((frame.phys_addr() + (from - page)) as usize);
                // SAFETY: the plan keeps the source inside the image and the
                // copy inside this page; the frame was just carved, zeroed, and
                // is reached through the identity map with nothing else on it.
                unsafe { core::ptr::copy_nonoverlapping(image[src..src + len].as_ptr(), dst, len) };
            }
            map(memory, vspace, frame, page, flags)?;
            page += PAGE_SIZE;
        }
    }
    for relocation in plan.relocations(image) {
        for (offset, byte) in (0..).zip(relocation.value.to_le_bytes()) {
            let vaddr = relocation.target + offset;
            let page = mapping::translate(vspace, vaddr & !(PAGE_SIZE - 1)).ok_or(RootError::Map(MapError::MissingTable))?;
            let dst = core::ptr::with_exposed_provenance_mut::<u8>((page + (vaddr & (PAGE_SIZE - 1))) as usize);
            // SAFETY: the plan puts every relocation inside a loaded segment, so
            // the page is one of the frames just carved and mapped; the kernel
            // writes it through the identity map whatever its user access.
            unsafe { dst.write(byte) };
        }
    }
    Ok(plan)
}

/// Fills the root task's boot information page.
///
/// # Safety
///
/// The first `count` entries of [`UNTYPED`] must be initialized, and nothing
/// may hold a mutable reference to them.
unsafe fn describe(
    page: &mut BootInfo,
    plan: &LoadPlan,
    info: BootInformation<'static>,
    args: &[u8],
    count: usize,
    ignored: u64,
) {
    page.magic = BOOT_INFO_MAGIC;
    page.version = BOOT_INFO_VERSION;
    page.ipc_buffer = layout::ROOT_IPC_BUFFER;
    page.stack_bottom = layout::ROOT_STACK_BOTTOM;
    page.stack_top = layout::ROOT_STACK_TOP;
    page.image_start = plan.segments().iter().map(|s| s.page_start()).min().unwrap_or(0);
    page.image_end = plan.segments().iter().map(|s| s.page_end()).max().unwrap_or(0);
    page.cnode_slots = CSPACE_SLOTS as u64;
    page.empty = SlotRange { start: root_slot::FIRST_UNTYPED + count as u64, end: CSPACE_SLOTS as u64 };
    page.memory_ignored = ignored;
    page.untyped_count = count as u64;
    for i in 0..count {
        // SAFETY: entry i is initialized, per the contract; the reference is
        // shared and short.
        let region = unsafe { (*core::ptr::addr_of!(UNTYPED))[i].assume_init_ref() };
        page.untyped[i] = UntypedDesc {
            slot: root_slot::FIRST_UNTYPED + i as u64,
            phys: region.base() as u64,
            size: region.size() as u64,
            used: region.used() as u64,
        };
    }
    let mut modules = 0;
    for module in info.modules().take(MAX_BOOT_MODULES) {
        let desc = &mut page.modules[modules];
        desc.phys = u64::from(module.start);
        desc.size = u64::from(module.end.saturating_sub(module.start));
        let len = module.cmdline.len().min(MODULE_CMDLINE_LEN);
        desc.cmdline[..len].copy_from_slice(&module.cmdline[..len]);
        modules += 1;
    }
    page.module_count = modules as u64;
    let len = args.len().min(page.cmdline.len());
    page.cmdline[..len].copy_from_slice(&args[..len]);
}

/// Makes `tcb` the running thread and enters it in ring 3.
///
/// # Safety
///
/// `tcb` must be a fully configured TCB (CNode, VSpace, kernel stack, ring-3
/// context), and interrupts must be disabled.
unsafe fn enter(tcb: ObjectId) -> ! {
    // SAFETY: per the contract tcb is live and configured.
    let thread = unsafe { tcb.as_tcb_mut() };
    let ptr = core::ptr::from_mut(thread);
    // SAFETY: the TCB lives in untyped memory for the kernel's lifetime, and
    // interrupts are off, as registration and switching require.
    unsafe {
        let id = crate::sched::register_thread(ptr);
        crate::sched::set_current(id);
        crate::cpu_local::switch_to(ptr);
        crate::usermode::enter_context(&(*ptr).context)
    }
}
