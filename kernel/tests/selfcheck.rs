// tests/selfcheck.rs
//
// the kernel's selfcheck reports each broken invariant by its own bit. every
// test starts from a kernel that holds all of them, breaks exactly one the way
// a kernel bug would (a space under the wrong id, a link to a capability that
// went alone, a capability to a CNode out of the registry, a thread never
// started, the running thread in the ready set, a parked thread the scheduler
// does not know, a recorded mapping missing from its page tables), checks that
// selfcheck names that one, and puts it back.
#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::panic::PanicInfo;

use jos::cap::{self, KernelCapSpace, ObjectId, Tcb, TcbState, UntypedRegion};
use jos::{mapping, sched, selfcheck};
use jos_core::abi::{fault_message, invariant, map_flags};
use jos_core::cap_rights::Rights;
use jos_core::cap_space::SpaceId;
use jos_core::page_table::pt_index;
use x86_64::instructions::interrupts::without_interrupts;

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, _info_ptr: u32) -> ! {
    jos::init();
    test_main();
    jos::hlt_loop()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}

const UNTYPED_SIZE: usize = 32 * 4096;

/// A page-aligned static untyped region the tests carve from.
#[repr(align(4096))]
struct UntypedBacking {
    bytes: UnsafeCell<[u8; UNTYPED_SIZE]>,
}
// SAFETY: single-threaded ring-0 kernel; handed out exactly once below.
unsafe impl Sync for UntypedBacking {}
static UNTYPED: UntypedBacking = UntypedBacking { bytes: UnsafeCell::new([0; UNTYPED_SIZE]) };

static mut REGION: Option<UntypedRegion> = None;
/// Two of the kernel's own registered spaces, built in place on first use.
static mut SPACES: MaybeUninit<[KernelCapSpace; 2]> = MaybeUninit::uninit();
static mut SPACES_READY: bool = false;
/// A thread the tests register with the scheduler and take back.
static mut TCB: Tcb = Tcb::new();

fn region() -> &'static mut UntypedRegion {
    // SAFETY: tests run single-threaded and sequentially; REGION is built on
    // first use and the &mut handed out is not held across calls.
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(REGION);
        if slot.is_none() {
            // SAFETY: UNTYPED is handed out exactly once here; 4096-aligned.
            *slot = Some(UntypedRegion::new(&mut *UNTYPED.bytes.get()));
        }
        slot.as_mut().unwrap()
    }
}

/// Registered space `i` (0 or 1).
fn space(i: usize) -> &'static mut KernelCapSpace {
    // SAFETY: as region(); both spaces are built in place and registered while
    // empty, once, before anything holds a reference to them.
    unsafe {
        let spaces = (*core::ptr::addr_of_mut!(SPACES)).as_mut_ptr().cast::<KernelCapSpace>();
        if !SPACES_READY {
            for j in 0..2 {
                KernelCapSpace::init_in_place(spaces.add(j));
                cap::register_cspace(spaces.add(j)).expect("register a space");
            }
            SPACES_READY = true;
        }
        &mut *spaces.add(i)
    }
}

/// The space inside the CNode `cnode`.
fn cnode_space(cnode: ObjectId) -> &'static mut KernelCapSpace {
    // SAFETY: cnode was carved as a CNode; no other reference to it is held.
    unsafe { cnode.as_cnode_mut() }
}

fn tcb() -> *mut Tcb {
    core::ptr::addr_of_mut!(TCB)
}

/// Runs selfcheck with interrupts off, as the syscall path does.
fn check() -> u64 {
    without_interrupts(selfcheck::check)
}

#[test_case]
fn a_space_under_the_wrong_id_breaks_the_registry() {
    assert_eq!(check(), 0);
    let own = space(1).id();
    let wrong = SpaceId::new(own.entry().unwrap(), 99).unwrap();
    assert!(space(1).set_id(wrong));
    assert_eq!(check(), invariant::REGISTRY);
    assert!(space(1).set_id(own));
    assert_eq!(check(), 0);
}

#[test_case]
fn a_link_to_a_capability_that_went_alone_breaks_links() {
    assert_eq!(check(), 0);
    let endpoint = region().retype_endpoint().expect("carve an endpoint");
    let original = space(0).insert(endpoint, Rights::all()).expect("insert");
    let copy = space(0).copy_into(original, space(1), 0, Rights::all()).expect("copy");
    assert_eq!(check(), 0);
    // the original goes without its subtree, as a broken revoke would leave it.
    space(0).remove(original);
    assert_eq!(check(), invariant::LINKS);
    space(1).remove(copy);
    assert_eq!(check(), 0);
}

#[test_case]
fn a_capability_to_a_cnode_out_of_the_registry_breaks_cnodes() {
    assert_eq!(check(), 0);
    let cnode = region().retype_cnode().expect("carve a cnode");
    let to_cnode = space(0).insert(cnode, Rights::all()).expect("insert");
    assert_eq!(check(), 0);
    let own = cnode_space(cnode).id();
    // the cnode's own id no longer names its entry: its entry is wrong, and
    // the capability names a cnode the registry does not hold.
    assert!(cnode_space(cnode).set_id(SpaceId(0)));
    assert_eq!(check(), invariant::REGISTRY | invariant::CNODES);
    assert!(cnode_space(cnode).set_id(own));
    cap::revoke_and_wake(space(0), to_cnode);
    assert_eq!(check(), 0);
}

#[test_case]
fn a_thread_never_started_breaks_threads() {
    assert_eq!(check(), 0);
    // SAFETY: interrupts are off; the TCB is a static that outlives the test.
    let id = without_interrupts(|| unsafe {
        *tcb() = Tcb::new();
        (*tcb()).cspace_ptr = core::ptr::from_mut(space(0));
        sched::register_thread(tcb())
    });
    assert_eq!(check(), invariant::THREADS);
    // SAFETY: interrupts are off; id came from register_thread.
    without_interrupts(|| unsafe { sched::retire_thread(id) });
    assert_eq!(check(), 0);
}

#[test_case]
fn the_running_thread_in_the_ready_set_breaks_ready() {
    assert_eq!(check(), 0);
    // SAFETY: interrupts are off; the TCB is a static that outlives the test.
    let id = without_interrupts(|| unsafe {
        *tcb() = Tcb::new();
        (*tcb()).state = TcbState::Running;
        (*tcb()).cspace_ptr = core::ptr::from_mut(space(0));
        sched::register_thread(tcb())
    });
    sched::mark_ready(id);
    assert_eq!(check(), 0);
    sched::set_current(id);
    assert_eq!(check(), invariant::READY);
    // SAFETY: interrupts are off; id came from register_thread.
    without_interrupts(|| unsafe { sched::retire_thread(id) });
    sched::set_current(usize::MAX);
    assert_eq!(check(), 0);
}

#[test_case]
fn a_parked_thread_the_scheduler_does_not_know_breaks_waits() {
    const ENDPOINT: u64 = 0x5e1f_c000;
    assert_eq!(check(), 0);
    // no receiver waits there, so the fault parks the thread, never registered.
    let message = fault_message(14, 0, 0, 0);
    assert!(without_interrupts(|| jos::syscall::deliver_fault(sched::MAX_THREADS - 1, ENDPOINT, 0, &message)));
    assert_eq!(check(), invariant::WAITS);
    without_interrupts(|| jos::syscall::cancel_waits_on(ENDPOINT));
    assert_eq!(check(), 0);
}

#[test_case]
fn a_recorded_mapping_missing_from_its_tables_breaks_mappings() {
    // a user address under root entry 1, the first a VSpace leaves to userspace.
    const VADDR: u64 = 0x0000_0080_0000_0000;
    assert_eq!(check(), 0);
    let vspace = region().retype_vspace().expect("carve a vspace");
    for _ in 0..3 {
        let table = region().retype_page_table().expect("carve a table");
        mapping::map_table(vspace, table, VADDR).expect("map a table");
    }
    let frame = region().retype_frame().expect("carve a frame");
    mapping::map_frame(vspace, frame, VADDR | map_flags::WRITE).expect("map the frame");
    assert_eq!(check(), 0);
    let entry = leaf_entry(vspace, VADDR);
    // SAFETY: entry points into a live page table this test made, and nothing
    // else touches it meanwhile.
    let saved = unsafe { entry.read() };
    // SAFETY: as above.
    unsafe { entry.write(0) };
    assert_eq!(check(), invariant::MAPPINGS);
    // SAFETY: as above.
    unsafe { entry.write(saved) };
    assert_eq!(check(), 0);
    assert!(mapping::unmap_object(frame.phys_addr()));
    assert_eq!(check(), 0);
}

/// Returns a pointer to the last-level entry that maps `vaddr` in `vspace`,
/// found by walking the tables through the identity map.
fn leaf_entry(vspace: ObjectId, vaddr: u64) -> *mut u64 {
    let indices = jos_core::page_table::indices(vaddr);
    let mut table = vspace.phys_addr();
    for index in indices.iter().take(3) {
        // SAFETY: each table on the path is a live, identity-mapped page table
        // this test mapped; the entry is only read.
        let entry = unsafe { (table as *const u64).add(*index).read() };
        table = jos_core::pte::frame_addr(entry);
    }
    assert_eq!(indices[3], pt_index(vaddr));
    (table as *mut u64).wrapping_add(indices[3])
}
