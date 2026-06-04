// tests/paging_heap.rs
//
// verifies the post 08-10 path end to end, headless: parse the multiboot2
// memory map into a frame allocator, build an identity-map page-table mapper,
// init the heap, then exercise heap allocation and a fresh 4 KiB page mapping.
// reports over serial and exits via isa-debug-exit.
#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};
use x86_64::structures::paging::OffsetPageTable;

use jos::memory::BootstrapFrameAllocator;

// grub passes info_ptr to kernel_main, but #[test_case] fns take no args, so
// stash it in a global for the tests to read.
static INFO_PTR: AtomicU32 = AtomicU32::new(0);

// the mapper and frame allocator are set up once in kernel_main and shared by
// the tests that need to map pages. they must be shared (not reconstructed per
// test): a fresh BootstrapFrameAllocator would re-hand-out frames the heap
// already took, corrupting any new mapping.
static mut MAPPER: Option<OffsetPageTable<'static>> = None;
static mut FRAME_ALLOC: Option<BootstrapFrameAllocator> = None;

// SAFETY: tests run single-threaded and sequentially; callers must not hold two
// references at once. valid only after kernel_main has initialized them.
unsafe fn shared_mapper() -> &'static mut OffsetPageTable<'static> {
    // SAFETY: initialized once in kernel_main before any test runs.
    unsafe { (*core::ptr::addr_of_mut!(MAPPER)).as_mut().unwrap() }
}

// SAFETY: same contract as shared_mapper.
unsafe fn shared_frame_allocator() -> &'static mut BootstrapFrameAllocator {
    // SAFETY: initialized once in kernel_main before any test runs.
    unsafe { (*core::ptr::addr_of_mut!(FRAME_ALLOC)).as_mut().unwrap() }
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, info_ptr: u32) -> ! {
    jos::init();
    INFO_PTR.store(info_ptr, Ordering::SeqCst);

    // set up paging + heap once, before the tests run (heap init is not
    // idempotent, so it must not live inside a #[test_case]). store the mapper
    // and allocator as shared statics so the mapping tests reuse them.
    // SAFETY: boot.s identity-maps the first 1 GiB; called once here, and no
    // test runs until test_main below.
    unsafe {
        let mut mapper = jos::memory::init_mapper();
        let mut frame_allocator = BootstrapFrameAllocator::new(info_ptr);
        jos::allocator::init_heap(&mut mapper, &mut frame_allocator).expect("heap init failed");
        MAPPER = Some(mapper);
        FRAME_ALLOC = Some(frame_allocator);
    }

    test_main();
    jos::hlt_loop()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}

// the multiboot2 memory map yields at least one usable frame.
#[test_case]
fn memory_map_has_usable_frames() {
    use x86_64::structures::paging::FrameAllocator;
    let info_ptr = INFO_PTR.load(Ordering::SeqCst);
    // SAFETY: info_ptr came from grub via kernel_main; identity-mapped.
    let mut fa = unsafe { jos::memory::BootstrapFrameAllocator::new(info_ptr) };
    assert!(fa.allocate_frame().is_some());
}

// box and vec allocations work after heap init.
#[test_case]
fn heap_allocation_works() {
    let b = Box::new(0xCAFE_u64);
    assert_eq!(*b, 0xCAFE);

    let v: Vec<u64> = (0..1024).collect();
    assert_eq!(v.len(), 1024);
    assert_eq!(v.iter().sum::<u64>(), (0..1024).sum());
}

// many small boxes do not collide (exercises the allocator's bookkeeping).
#[test_case]
fn many_boxes() {
    let mut boxes = Vec::new();
    for i in 0..500u64 {
        boxes.push(Box::new(i));
    }
    for (i, b) in boxes.iter().enumerate() {
        assert_eq!(**b, i as u64);
    }
}

// map a fresh upper-half page to a new frame, write and read it back, and
// confirm translate agrees. this proves map_to builds a 4 KiB hierarchy.
//
// it reuses the SHARED frame allocator (set up once in kernel_main, same one
// the heap used). a fresh BootstrapFrameAllocator here would re-hand-out the
// frames the heap already took, so map_to's new page-table frames would alias
// heap memory and the mapping would be corrupt.
#[test_case]
fn map_and_access_fresh_page() {
    use x86_64::structures::paging::{
        FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB, Translate,
    };
    use x86_64::VirtAddr;

    // SAFETY: single-threaded sequential tests; we take the shared mapper and
    // allocator set up in kernel_main and do not alias them elsewhere.
    let mapper = unsafe { shared_mapper() };
    let fa = unsafe { shared_frame_allocator() };

    // an upper-half address clear of the identity map and the heap.
    let virt = VirtAddr::new(0xFFFF_8000_4000_0000);
    let page: Page<Size4KiB> = Page::containing_address(virt);
    let frame = fa.allocate_frame().expect("no frame for test page");
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    // SAFETY: virt is a fresh unmapped upper-half page, frame is freshly
    // allocated and unique, so this mapping introduces no aliasing.
    unsafe {
        mapper
            .map_to(page, frame, flags, fa)
            .expect("map_to failed")
            .flush();
    }

    let ptr: *mut u64 = virt.as_mut_ptr();
    // SAFETY: page was just mapped present+writable; ptr is page-aligned.
    unsafe {
        ptr.write_volatile(0x1234_5678_9ABC_DEF0);
        assert_eq!(ptr.read_volatile(), 0x1234_5678_9ABC_DEF0);
    }

    assert_eq!(mapper.translate_addr(virt), Some(frame.start_address()));
}
