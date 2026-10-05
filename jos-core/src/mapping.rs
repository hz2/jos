//! The mapping registry: where each page table and frame is mapped.
//!
//! Userspace builds address spaces from capabilities: it maps page tables into
//! a `VSpace` level by level, then maps frames at the leaves. The kernel records
//! every such mapping here, keyed by the mapped object, for two reasons:
//!
//! 1. An object is mapped at most once. A page table installed at two places
//!    would alias two address ranges, and a frame mapped twice would outlive
//!    the revocation of one of its mappings.
//! 2. Revoking a capability must remove the access it granted. The registry
//!    tells the kernel where a revoked frame or table is mapped so it can clear
//!    that entry, and which mappings sat beneath a revoked table.
//!
//! The registry is pure bookkeeping: it never touches page tables. The kernel
//! updates the hardware tables and this record together.

/// Which kind of entry a mapping occupies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// A page table installed in a root entry (it serves as a PDPT).
    Pdpt,
    /// A page table installed in a PDPT entry (it serves as a page directory).
    Pd,
    /// A page table installed in a page-directory entry (a last-level table).
    Pt,
    /// A frame installed in a last-level table entry.
    Frame,
}

impl Level {
    /// Returns the number of bytes of address space an object at this level
    /// covers: everything beneath a table, or one page for a frame.
    #[must_use]
    pub const fn span(self) -> u64 {
        match self {
            Level::Pdpt => 1 << 39,
            Level::Pd => 1 << 30,
            Level::Pt => 1 << 21,
            Level::Frame => 1 << 12,
        }
    }
}

/// One recorded mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    /// Physical address of the mapped object (a page table or a frame).
    pub object: u64,
    /// Physical address of the root of the address space it is mapped into.
    pub vspace: u64,
    /// The virtual address the mapping covers, aligned to [`Level::span`].
    pub vaddr: u64,
    /// Which kind of entry it occupies.
    pub level: Level,
}

impl Mapping {
    /// Returns `true` if this mapping lies inside the address range a table
    /// mapped at `table` covers, in the same address space.
    #[must_use]
    pub fn is_beneath(&self, table: &Mapping) -> bool {
        self.vspace == table.vspace
            && self.object != table.object
            && self.vaddr >= table.vaddr
            && self.vaddr - table.vaddr < table.level.span()
    }
}

/// Why a mapping could not be recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// The object is already mapped somewhere.
    AlreadyMapped,
    /// The registry has no free entry.
    Full,
}

/// A fixed-capacity registry of mappings, at most one per object.
#[derive(Clone, Copy, Debug)]
pub struct MappingTable<const N: usize> {
    entries: [Option<Mapping>; N],
}

impl<const N: usize> MappingTable<N> {
    /// Creates an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    /// Returns where `object` is mapped, if it is.
    #[must_use]
    pub fn find(&self, object: u64) -> Option<Mapping> {
        self.entries.iter().flatten().find(|m| m.object == object).copied()
    }

    /// Records `mapping`.
    ///
    /// # Errors
    ///
    /// [`RecordError::AlreadyMapped`] if its object is already recorded, or
    /// [`RecordError::Full`] if there is no free entry. Either way the registry
    /// is unchanged.
    pub fn record(&mut self, mapping: Mapping) -> Result<(), RecordError> {
        if self.find(mapping.object).is_some() {
            return Err(RecordError::AlreadyMapped);
        }
        let slot = self.entries.iter_mut().find(|e| e.is_none()).ok_or(RecordError::Full)?;
        *slot = Some(mapping);
        Ok(())
    }

    /// Removes and returns the mapping of `object`, if it is mapped.
    pub fn forget(&mut self, object: u64) -> Option<Mapping> {
        let slot = self.entries.iter_mut().find(|e| e.is_some_and(|m| m.object == object))?;
        slot.take()
    }

    /// Removes every mapping that lies beneath `table` and calls `f` with each,
    /// so the kernel can drop the records a revoked table made unreachable.
    pub fn forget_beneath(&mut self, table: &Mapping, mut f: impl FnMut(Mapping)) {
        for slot in &mut self.entries {
            if let Some(m) = *slot
                && m.is_beneath(table)
            {
                *slot = None;
                f(m);
            }
        }
    }

    /// Returns the number of recorded mappings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    /// Returns `true` if nothing is recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<const N: usize> Default for MappingTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{Level, Mapping, MappingTable, RecordError};

    fn frame(object: u64, vaddr: u64) -> Mapping {
        Mapping { object, vspace: 0x1000, vaddr, level: Level::Frame }
    }

    #[test]
    fn records_and_finds_a_mapping() {
        let mut t: MappingTable<4> = MappingTable::new();
        t.record(frame(0x5000, 0x4000_0000)).unwrap();
        assert_eq!(t.find(0x5000), Some(frame(0x5000, 0x4000_0000)));
        assert_eq!(t.find(0x6000), None);
    }

    #[test]
    fn an_object_is_mapped_at_most_once() {
        let mut t: MappingTable<4> = MappingTable::new();
        t.record(frame(0x5000, 0x4000_0000)).unwrap();
        assert_eq!(t.record(frame(0x5000, 0x4000_1000)), Err(RecordError::AlreadyMapped));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn a_full_registry_refuses() {
        let mut t: MappingTable<1> = MappingTable::new();
        t.record(frame(0x5000, 0)).unwrap();
        assert_eq!(t.record(frame(0x6000, 0x1000)), Err(RecordError::Full));
    }

    #[test]
    fn forget_frees_the_object() {
        let mut t: MappingTable<2> = MappingTable::new();
        t.record(frame(0x5000, 0)).unwrap();
        assert_eq!(t.forget(0x5000), Some(frame(0x5000, 0)));
        assert!(t.is_empty());
        // a forgotten object can be mapped again.
        t.record(frame(0x5000, 0x1000)).unwrap();
    }

    #[test]
    fn forget_beneath_drops_only_the_covered_range() {
        let mut t: MappingTable<4> = MappingTable::new();
        // a last-level table covering [0x20_0000, 0x40_0000).
        let pt = Mapping { object: 0x9000, vspace: 0x1000, vaddr: 0x20_0000, level: Level::Pt };
        t.record(pt).unwrap();
        t.record(frame(0x5000, 0x20_1000)).unwrap(); // beneath
        t.record(frame(0x6000, 0x40_0000)).unwrap(); // just past the end
        let mut dropped = 0;
        t.forget_beneath(&pt, |_| dropped += 1);
        assert_eq!(dropped, 1);
        assert!(t.find(0x5000).is_none());
        assert!(t.find(0x6000).is_some());
        // the table itself is not beneath itself.
        assert!(t.find(0x9000).is_some());
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::{Level, Mapping, MappingTable};

    fn any_frame() -> Mapping {
        Mapping { object: kani::any(), vspace: kani::any(), vaddr: kani::any(), level: Level::Frame }
    }

    /// Over any sequence of records and forgets, no object is ever recorded
    /// twice: the registry never holds two mappings of the same object.
    #[kani::proof]
    #[kani::unwind(5)]
    fn objects_are_mapped_at_most_once() {
        let mut t: MappingTable<3> = MappingTable::new();
        for _ in 0..3 {
            if kani::any() {
                let _ = t.record(any_frame());
            } else {
                let _ = t.forget(kani::any());
            }
        }
        let a: usize = kani::any();
        let b: usize = kani::any();
        kani::assume(a < 3 && b < 3 && a != b);
        if let (Some(x), Some(y)) = (t.entries[a], t.entries[b]) {
            assert!(x.object != y.object);
        }
    }

    /// A successful record is found afterwards, and a forget removes exactly it.
    #[kani::proof]
    #[kani::unwind(4)]
    fn record_then_forget_round_trips() {
        let mut t: MappingTable<2> = MappingTable::new();
        let m = any_frame();
        if t.record(m).is_ok() {
            assert!(t.find(m.object) == Some(m));
            assert!(t.forget(m.object) == Some(m));
            assert!(t.find(m.object).is_none());
        }
    }
}
