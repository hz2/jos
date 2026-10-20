//! The physical memory that is free at boot, as page-aligned ranges.
//!
//! The firmware memory map says which RAM is available, but some of it is
//! already in use when the kernel starts: the kernel image, the boot page
//! tables, the multiboot2 info structure, and the modules the loader placed,
//! the root task among them. Handing any of that out as free memory would let
//! a later allocation overwrite it. [`usable_regions`] takes the available
//! ranges and the reserved ones and returns what is really free, in whole
//! pages, sorted and disjoint, in a fixed-size list with no allocation.
//!
//! Firmware maps can be messy, so nothing here trusts its input: ranges may
//! overlap, arrive unsorted, be empty or inverted, or end at `u64::MAX`, and
//! no input makes the arithmetic overflow or panic.
//!
//! # Invariant
//!
//! Call a page free if it lies wholly inside an available range, ends at or
//! below the limit, and shares no byte with a reserved range. Every range in
//! the result is non-empty, page aligned, ends at or below the limit, and
//! holds only free pages. The ranges are sorted with a gap between neighbours,
//! so each one is a maximal run of free pages, and if
//! [`RegionList::dropped_bytes`] is zero, every free page is in one of them.
//! The `kani_proofs` harnesses at the bottom of this file prove this (BOOT-2).

use crate::page_table::PAGE_SIZE;

/// A half-open range of physical addresses, `[start, end)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PhysRange {
    /// The first address in the range.
    pub start: u64,
    /// The address one past the last; the range is empty unless this is above `start`.
    pub end: u64,
}

impl PhysRange {
    /// Returns the number of bytes in the range, or zero if it is empty or inverted.
    #[must_use]
    pub const fn len(self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Returns `true` if the range holds no bytes, as an empty or inverted one does.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.end <= self.start
    }
}

/// Up to `N` non-empty, page-aligned physical ranges, sorted by start, with a
/// gap between each range and the next.
#[derive(Clone, Debug)]
pub struct RegionList<const N: usize> {
    /// The ranges; only the first `len` are in the list.
    ranges: [PhysRange; N],
    /// How many ranges are in the list.
    len: usize,
    /// Bytes of free memory left out because the list was full.
    dropped: u64,
}

impl<const N: usize> RegionList<N> {
    /// Returns the ranges, sorted by start.
    #[must_use]
    pub fn as_slice(&self) -> &[PhysRange] {
        &self.ranges[..self.len]
    }

    /// Returns the number of bytes the ranges cover.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.as_slice().iter().fold(0, |sum, r| sum.saturating_add(r.len()))
    }

    /// Returns the number of free bytes left out because more than `N` ranges
    /// were needed.
    ///
    /// Zero means nothing was left out. When the available ranges overlap, a
    /// byte can be counted more than once, so this is then an upper bound.
    #[must_use]
    pub fn dropped_bytes(&self) -> u64 {
        self.dropped
    }

    /// Adds `piece`, merging it with every range it overlaps or touches. With
    /// no room for it, keeps the larger of it and the smallest range in the
    /// list, and counts the other as dropped.
    fn add(&mut self, piece: PhysRange) {
        let len = self.len;
        // ranges in the list never touch, so the ones piece meets form a run [first, last).
        let first = self.ranges[..len].iter().position(|r| r.end >= piece.start).unwrap_or(len);
        let mut last = first;
        while last < len && self.ranges[last].start <= piece.end {
            last += 1;
        }
        if first < last {
            self.ranges[first] = PhysRange {
                start: piece.start.min(self.ranges[first].start),
                end: piece.end.max(self.ranges[last - 1].end),
            };
            self.ranges.copy_within(last..len, first + 1);
            self.len -= last - first - 1;
            return;
        }
        let mut at = first;
        if len == N {
            let smallest = (0..len).min_by_key(|&i| self.ranges[i].len());
            let Some(i) = smallest.filter(|&i| self.ranges[i].len() < piece.len()) else {
                self.dropped = self.dropped.saturating_add(piece.len());
                return;
            };
            self.dropped = self.dropped.saturating_add(self.ranges[i].len());
            self.ranges.copy_within(i + 1..len, i);
            self.len -= 1;
            if i < at {
                at -= 1;
            }
        }
        self.ranges.copy_within(at..self.len, at + 1);
        self.ranges[at] = piece;
        self.len += 1;
    }
}

/// Returns the free physical memory: the `available` ranges minus the
/// `reserved` ones, below `limit`, in whole pages.
///
/// Available ranges shrink inward to page boundaries and reserved ones grow
/// outward, so a page that is only partly available, or partly reserved, is
/// never handed out; `limit` is rounded down to a page. The result is sorted
/// by start and its ranges never overlap or touch, whatever order and overlap
/// the inputs have. Empty and inverted ranges count for nothing.
///
/// If more than `N` ranges are needed, the smallest are left out and counted
/// in [`RegionList::dropped_bytes`].
#[must_use]
pub fn usable_regions<const N: usize>(
    available: impl IntoIterator<Item = PhysRange>,
    reserved: &[PhysRange],
    limit: u64,
) -> RegionList<N> {
    let mut list = RegionList { ranges: [PhysRange::default(); N], len: 0, dropped: 0 };
    let top = page_down(limit);
    for range in available {
        let end = page_down(range.end).min(top);
        let mut cursor = page_up(range.start);
        // walk up the range, stepping over reserved ranges and keeping what lies between.
        while cursor < end {
            if let Some(r) = reserved.iter().map(|&r| grow(r)).find(|r| r.start <= cursor && cursor < r.end) {
                cursor = r.end;
                continue;
            }
            let stop = reserved
                .iter()
                .map(|&r| grow(r))
                .filter(|r| cursor < r.start)
                .fold(end, |stop, r| stop.min(r.start));
            list.add(PhysRange { start: cursor, end: stop });
            cursor = stop;
        }
    }
    list
}

/// Returns `addr` rounded down to a page boundary.
const fn page_down(addr: u64) -> u64 {
    addr & !(PAGE_SIZE - 1)
}

/// Returns `addr` rounded up to a page boundary, or the last page boundary if
/// that would overflow.
const fn page_up(addr: u64) -> u64 {
    page_down(addr.saturating_add(PAGE_SIZE - 1))
}

/// Returns `r` grown outward to page boundaries. An empty or inverted range
/// reserves nothing, so it stays empty.
fn grow(r: PhysRange) -> PhysRange {
    if r.is_empty() {
        return PhysRange::default();
    }
    PhysRange { start: page_down(r.start), end: page_up(r.end) }
}

/// Host tests for the free-memory arithmetic, by hand and against a
/// page-by-page oracle.
#[cfg(test)]
mod tests {
    use super::{PAGE_SIZE, PhysRange, RegionList, usable_regions};
    use crate::rng::{KernelRng, SimRng};
    extern crate std;
    use std::vec::Vec;

    /// Returns the range `[start, end)`.
    fn r(start: u64, end: u64) -> PhysRange {
        PhysRange { start, end }
    }

    /// Runs [`usable_regions`] with room for 16 ranges and no limit to speak of.
    fn free(available: &[PhysRange], reserved: &[PhysRange]) -> RegionList<16> {
        usable_regions(available.iter().copied(), reserved, u64::MAX)
    }

    /// A QEMU-like e820 map loses exactly the boot page tables, the kernel
    /// image, the root task module, and the info structure, each to whole pages.
    #[test]
    fn carves_the_boot_reservations_out_of_a_qemu_map() {
        let available = [r(0, 0x9_fc00), r(0x10_0000, 0x7fe_0000)];
        let reserved = [
            r(0x1000, 0x4000),       // boot page tables
            r(0x10_0000, 0x2a_3456), // kernel image
            r(0x2a_5000, 0x2c_7a10), // root task module
            r(0x2c_8010, 0x2c_8460), // multiboot2 info structure
        ];
        let list = usable_regions::<8>(available, &reserved, 0x4000_0000);
        assert_eq!(
            list.as_slice(),
            [r(0, 0x1000), r(0x4000, 0x9_f000), r(0x2a_4000, 0x2a_5000), r(0x2c_9000, 0x7fe_0000)]
        );
        assert_eq!(list.dropped_bytes(), 0);
        assert_eq!(list.total_bytes(), 0x1000 + 0x9_b000 + 0x1000 + 0x7d1_7000);
    }

    /// Ranges are clipped to the limit rounded down to a page; one wholly
    /// above it is dropped, and a zero limit leaves nothing.
    #[test]
    fn clips_to_the_limit() {
        let available = [r(0, 0x1_0000), r(0x2_0000, 0x3_0000)];
        let list = usable_regions::<4>(available, &[], 0x8800);
        assert_eq!(list.as_slice(), [r(0, 0x8000)]);
        assert!(usable_regions::<4>(available, &[], 0).as_slice().is_empty());
    }

    /// Unsorted, overlapping, and touching inputs come out sorted and merged,
    /// and overlapping reservations are subtracted together.
    #[test]
    fn merges_messy_inputs() {
        let available = [r(0x5000, 0x9000), r(0x1000, 0x6000), r(0x8000, 0xa000), r(0xa000, 0xb000)];
        assert_eq!(free(&available, &[]).as_slice(), [r(0x1000, 0xb000)]);
        let reserved = [r(0x3000, 0x5000), r(0x2000, 0x4000), r(0xc000, 0xd000)];
        assert_eq!(free(&available, &reserved).as_slice(), [r(0x1000, 0x2000), r(0x5000, 0xb000)]);
        // a reservation that covers everything leaves nothing.
        assert!(free(&available, &[r(0, u64::MAX)]).as_slice().is_empty());
    }

    /// Partial pages are never handed out: available ranges shrink to whole
    /// pages and reservations grow to them.
    #[test]
    fn rounds_available_inward_and_reserved_outward() {
        assert_eq!(free(&[r(0x1001, 0x3fff)], &[]).as_slice(), [r(0x2000, 0x3000)]);
        assert!(free(&[r(0x1001, 0x1fff)], &[]).as_slice().is_empty());
        let list = free(&[r(0x4000, 0x9000)], &[r(0x5fff, 0x6001)]);
        assert_eq!(list.as_slice(), [r(0x4000, 0x5000), r(0x7000, 0x9000)]);
    }

    /// Empty and inverted ranges count for nothing, on either side.
    #[test]
    fn empty_and_inverted_ranges_count_for_nothing() {
        assert!(free(&[r(0x3000, 0x3000), r(0x5000, 0x2000)], &[]).as_slice().is_empty());
        let reserved = [r(0x1800, 0x1800), r(0x2800, 0x2700), r(0x9000, 0)];
        assert_eq!(free(&[r(0, 0x4000)], &reserved).as_slice(), [r(0, 0x4000)]);
    }

    /// Ranges ending at `u64::MAX` neither overflow nor reach the last page,
    /// whose end does not fit in a `u64`.
    #[test]
    fn handles_the_top_of_the_address_space() {
        let top = u64::MAX - (PAGE_SIZE - 1);
        let available = [r(top - 0x1000, u64::MAX), r(u64::MAX, u64::MAX), r(u64::MAX - 5, 3)];
        assert_eq!(free(&available, &[]).as_slice(), [r(top - 0x1000, top)]);
        assert_eq!(free(&available, &[r(u64::MAX - 1, u64::MAX)]).as_slice(), [r(top - 0x1000, top)]);
        assert!(free(&available, &[r(top - 0x800, u64::MAX)]).as_slice().is_empty());
        assert!(free(&[r(0, u64::MAX)], &[r(1, u64::MAX)]).as_slice().is_empty());
    }

    /// A full list keeps the larger ranges and counts the bytes it leaves out.
    #[test]
    fn a_full_list_keeps_the_larger_ranges() {
        let pages = |start: u64, count: u64| r(start * PAGE_SIZE, (start + count) * PAGE_SIZE);
        let available = [pages(0, 1), pages(10, 3), pages(20, 2), pages(30, 1)];
        let list = usable_regions::<2>(available, &[], u64::MAX);
        assert_eq!(list.as_slice(), [pages(10, 3), pages(20, 2)]);
        assert_eq!(list.dropped_bytes(), 2 * PAGE_SIZE);
        // a piece that merges into a stored range needs no room of its own.
        let list = usable_regions::<1>([pages(0, 2), pages(2, 1)], &[], u64::MAX);
        assert_eq!((list.as_slice(), list.dropped_bytes()), (&[pages(0, 3)][..], 0));
    }

    /// Pages in the oracle's address space.
    const PAGES: u64 = 256;

    /// Returns the maximal runs of free pages among the `PAGES` pages from
    /// `base`, one page at a time, and whether a free page lies wholly inside
    /// two available ranges.
    fn oracle(base: u64, available: &[PhysRange], reserved: &[PhysRange], limit: u64) -> (Vec<PhysRange>, bool) {
        let mut runs: Vec<PhysRange> = Vec::new();
        let mut overlap = false;
        for page in 0..PAGES {
            let start = base + page * PAGE_SIZE;
            // the last page of the address space has no representable end.
            let Some(end) = start.checked_add(PAGE_SIZE) else { continue };
            let inside = available.iter().filter(|a| a.start <= start && end <= a.end).count();
            let reserved = reserved.iter().any(|r| r.start < r.end && r.start < end && start < r.end);
            if inside == 0 || end > limit || reserved {
                continue;
            }
            overlap |= inside > 1;
            match runs.last_mut() {
                Some(run) if run.end == start => run.end = end,
                _ => runs.push(PhysRange { start, end }),
            }
        }
        (runs, overlap)
    }

    /// Returns a random address from `base` up to `PAGES` pages above it,
    /// page aligned half the time.
    fn address(rng: &mut SimRng, base: u64) -> u64 {
        let offset = rng.below(PAGES * PAGE_SIZE + 1);
        let offset = if rng.next_bool() { offset & !(PAGE_SIZE - 1) } else { offset };
        base.saturating_add(offset)
    }

    /// Returns a random range inside the oracle's window from `base`: mostly a
    /// few pages long, sometimes empty or inverted.
    fn range(rng: &mut SimRng, base: u64) -> PhysRange {
        let start = address(rng, base);
        let end = match rng.below(8) {
            0 => address(rng, base),
            _ => start.saturating_add(rng.below(64 * PAGE_SIZE)).min(base.saturating_add(PAGES * PAGE_SIZE)),
        };
        PhysRange { start, end }
    }

    /// Random maps, near zero and at the top of the address space, give
    /// exactly the oracle's runs when the list is big enough; a small list
    /// keeps only free pages and accounts for what it leaves out.
    #[test]
    fn matches_a_page_by_page_oracle() {
        let cases = if cfg!(miri) { 12 } else { 4000 };
        // how often the interesting paths ran: drops, overlaps, and the top of memory.
        let mut seen = [0_u32; 3];
        for seed in 0..cases {
            let mut rng = SimRng::new(seed);
            let base = if rng.below(4) == 0 { u64::MAX - PAGES * PAGE_SIZE + 1 } else { 0 };
            let available: Vec<PhysRange> = (0..rng.below(6)).map(|_| range(&mut rng, base)).collect();
            let reserved: Vec<PhysRange> = (0..rng.below(6)).map(|_| range(&mut rng, base)).collect();
            let limit = if rng.below(4) == 0 { u64::MAX } else { address(&mut rng, base) };
            let (want, overlap) = oracle(base, &available, &reserved, limit);
            let case = std::format!("seed {seed}: {available:x?} minus {reserved:x?} below {limit:#x}");

            // five available ranges minus five reserved ones make at most ten runs.
            let big = usable_regions::<16>(available.iter().copied(), &reserved, limit);
            assert_eq!(big.as_slice(), want.as_slice(), "{case}");
            assert_eq!(big.dropped_bytes(), 0, "{case}");

            let small = usable_regions::<2>(available.iter().copied(), &reserved, limit);
            let kept = small.as_slice();
            for (i, k) in kept.iter().enumerate() {
                assert!(want.iter().any(|w| w.start <= k.start && k.end <= w.end), "{case}: kept {k:x?}");
                assert!(i == 0 || kept[i - 1].end < k.start, "{case}: out of order");
            }
            let free_bytes: u64 = want.iter().map(|w| w.len()).sum();
            let accounted = small.total_bytes() + small.dropped_bytes();
            assert!(accounted >= free_bytes, "{case}: lost bytes without counting them");
            if !overlap {
                assert_eq!(accounted, free_bytes, "{case}: miscounted the dropped bytes");
            }
            if small.dropped_bytes() == 0 {
                assert_eq!(kept, want.as_slice(), "{case}");
            }
            seen[0] += u32::from(small.dropped_bytes() > 0);
            seen[1] += u32::from(overlap);
            seen[2] += u32::from(base > 0 && !want.is_empty());
        }
        assert!(cfg!(miri) || seen.iter().all(|&n| n > 0), "a path never ran: {seen:?}");
    }
}

/// Bounded proofs of the free-memory arithmetic (BOOT-2).
///
/// Every input is a fully symbolic `u64`, `u64::MAX` included, so the solver
/// covers every order, overlap, and rounding case of two available and two
/// reserved ranges. A page is checked through an arbitrary page address `p`,
/// which stands for every page at once. The harnesses state "free" from the
/// raw inputs, not through the rounding helpers under test.
#[cfg(kani)]
mod kani_proofs {
    use super::{PAGE_SIZE, PhysRange, usable_regions};

    /// Returns an arbitrary range, empty and inverted ones included.
    fn any_range() -> PhysRange {
        PhysRange { start: kani::any(), end: kani::any() }
    }

    /// Returns `true` if the page at `p` lies wholly inside `r`.
    fn page_inside(p: u64, r: PhysRange) -> bool {
        r.start <= p && p.checked_add(PAGE_SIZE).is_some_and(|end| end <= r.end)
    }

    /// Returns `true` if the page at `p` shares a byte with `r`.
    fn page_meets(p: u64, r: PhysRange) -> bool {
        r.start < r.end && r.start <= p + (PAGE_SIZE - 1) && p < r.end
    }

    /// Checks every BOOT-2 property of `usable_regions::<N>` on arbitrary
    /// inputs and returns the dropped byte count.
    fn check<const N: usize>() -> u64 {
        let available = [any_range(), any_range()];
        let reserved = [any_range(), any_range()];
        let limit: u64 = kani::any();
        let list = usable_regions::<N>(available, &reserved, limit);
        let out = list.as_slice();
        for (i, r) in out.iter().enumerate() {
            assert!(r.start < r.end && r.end <= limit);
            assert!(r.start % PAGE_SIZE == 0 && r.end % PAGE_SIZE == 0);
            assert!(i == 0 || out[i - 1].end < r.start);
        }
        let p: u64 = kani::any();
        kani::assume(p % PAGE_SIZE == 0);
        let covered = out.iter().any(|r| r.start <= p && p < r.end);
        let free = (page_inside(p, available[0]) || page_inside(p, available[1]))
            && p.checked_add(PAGE_SIZE).is_some_and(|end| end <= limit)
            && !page_meets(p, reserved[0])
            && !page_meets(p, reserved[1]);
        assert!(!covered || free);
        assert!(list.dropped_bytes() != 0 || !free || covered);
        list.dropped_bytes()
    }

    /// The result holds exactly the free pages, as sorted maximal runs, and
    /// four ranges always suffice for two available and two reserved ones.
    #[kani::proof]
    #[kani::unwind(6)] // the cursor walk of one available range takes at most 2 * 2 + 1 = 5 steps
    fn usable_regions_are_exactly_the_free_pages() {
        assert!(check::<4>() == 0);
    }

    /// With too little room the list still holds only free pages, sorted with
    /// gaps, and still holds every free page when it reports nothing dropped.
    #[kani::proof]
    #[kani::unwind(6)] // as above
    fn a_full_list_stays_sound() {
        check::<2>();
    }
}
