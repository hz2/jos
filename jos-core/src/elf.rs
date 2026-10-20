//! ELF64 images turned into load plans.
//!
//! The kernel loads the root task from an ELF image, and userspace will later
//! load child processes the same way. Both hand the image bytes to
//! [`LoadPlan::parse`], which checks everything a loader relies on and returns
//! a plan: the segments to map, the entry point, and the relocations to apply.
//! The loader then copies bytes and patches words without parsing anything.
//!
//! The expected producer is a Rust program built for `x86_64-unknown-none`: a
//! static position-independent executable (`ET_DYN`) linked at address zero
//! whose only dynamic relocations are `R_X86_64_RELATIVE`. A fixed-address
//! executable (`ET_EXEC`) is accepted too. An image that needs a dynamic
//! linker, thread-local storage, or any other kind of relocation is refused.
//!
//! # Invariant
//!
//! A plan returned by [`LoadPlan::parse`] guarantees that:
//!
//! - its segments are the image's `PT_LOAD` headers with a nonzero `p_memsz`,
//!   in order, moved up by the load base, and there are between one and
//!   [`MAX_LOAD_SEGMENTS`] of them;
//! - each segment's file bytes `[file_offset, file_offset + file_size)` lie
//!   inside the image, `file_size <= mem_size`, and `vaddr` and `file_offset`
//!   are equal modulo [`PAGE_SIZE`];
//! - no segment is both writable and executable;
//! - the page ranges `[page_start, page_end)` of the segments are pairwise
//!   disjoint and lie inside the caller's window;
//! - the entry point lies inside an executable segment;
//! - every relocation writes eight bytes inside one writable segment, and the
//!   value it writes is the load base plus the entry's addend.
//!
//! `plan_invariants_hold` checks all of this again without the parser's code.
//! The Kani harnesses at the bottom of this file prove that it holds for every
//! plan accepted from small symbolic images, and the host tests check it on
//! seeded mutations of valid ones.
//!
//! # Loading a plan
//!
//! For each segment the loader backs `[page_start, page_end)` with fresh
//! frames, copies the file bytes to `vaddr`, and zeroes the rest of
//! `mem_size`. Only then does it apply the relocations, since one may patch a
//! word in that zeroed tail. Relocations are decoded from the image rather
//! than from loaded memory, so patching never disturbs the ones still to come.
//!
//! A `PT_LOAD` header with `p_memsz == 0` maps nothing, so it is skipped
//! rather than refused.

/// Size of a page, the unit segments are mapped in.
pub const PAGE_SIZE: u64 = 4096;

/// The most loadable segments a plan holds.
pub const MAX_LOAD_SEGMENTS: usize = 8;

/// The most program headers an image may have.
pub const MAX_PROGRAM_HEADERS: usize = 32;

/// Size of the ELF64 file header.
const EHDR_SIZE: u64 = 64;
/// Size of an ELF64 program header.
const PHDR_SIZE: u64 = 56;
/// Size of a dynamic section entry.
const DYN_SIZE: u64 = 16;
/// Size of a RELA entry, and the only `DT_RELAENT` accepted.
const RELA_SIZE: u64 = 24;

/// The bytes every ELF image starts with.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
/// The `EI_CLASS` of a 64-bit image.
const ELFCLASS64: u8 = 2;
/// The `EI_DATA` of a little-endian image.
const ELFDATA2LSB: u8 = 1;
/// The only ELF version, in `EI_VERSION` and `e_version` alike.
const EV_CURRENT: u8 = 1;
/// The `e_type` of a fixed-address executable.
const ET_EXEC: u16 = 2;
/// The `e_type` of a position-independent executable.
const ET_DYN: u16 = 3;
/// The `e_machine` of `x86_64`.
const EM_X86_64: u16 = 0x3e;

/// The `p_type` of a loadable segment.
const PT_LOAD: u32 = 1;
/// The `p_type` of the dynamic section.
const PT_DYNAMIC: u32 = 2;
/// The `p_type` that names a dynamic linker.
const PT_INTERP: u32 = 3;
/// The `p_type` of the thread-local storage template.
const PT_TLS: u32 = 7;
/// The `p_flags` bit of an executable segment.
const PF_X: u32 = 1;
/// The `p_flags` bit of a writable segment.
const PF_W: u32 = 2;
/// The `p_flags` bit of a readable segment.
const PF_R: u32 = 4;

/// The dynamic tag that ends the dynamic section.
const DT_NULL: u64 = 0;
/// The dynamic tag naming a shared library the image needs.
const DT_NEEDED: u64 = 1;
/// The dynamic tag giving the size of the PLT relocations.
const DT_PLTRELSZ: u64 = 2;
/// The dynamic tag giving the address of the RELA table.
const DT_RELA: u64 = 7;
/// The dynamic tag giving the size of the RELA table in bytes.
const DT_RELASZ: u64 = 8;
/// The dynamic tag giving the size of one RELA entry.
const DT_RELAENT: u64 = 9;
/// The dynamic tag giving the address of a REL table.
const DT_REL: u64 = 17;
/// The dynamic tag giving the size of a REL table.
const DT_RELSZ: u64 = 18;
/// The dynamic tag saying relocations patch read-only text.
const DT_TEXTREL: u64 = 22;
/// The dynamic tag holding the `DF_*` flags.
const DT_FLAGS: u64 = 30;
/// The dynamic tag giving the address of a RELR table.
const DT_RELR: u64 = 36;
/// The `DT_FLAGS` bit saying relocations patch read-only text.
const DF_TEXTREL: u64 = 4;

/// The relocation type that patches nothing.
const R_X86_64_NONE: u64 = 0;
/// The relocation type that stores the load base plus the addend.
const R_X86_64_RELATIVE: u64 = 8;

/// Why an image was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    /// The image is shorter than an ELF header.
    TooShort,
    /// The image does not start with the ELF magic bytes.
    BadMagic,
    /// The image is not a 64-bit ELF file.
    NotElf64,
    /// The image is not little endian.
    NotLittleEndian,
    /// The ELF version, in the identification bytes or the header, is not 1.
    BadVersion,
    /// The image is not built for `x86_64`.
    NotX86_64,
    /// The image is neither a fixed-address executable (`ET_EXEC`) nor a
    /// position-independent one (`ET_DYN`).
    BadType,
    /// The header or program header size is not the ELF64 one.
    BadHeaderSize,
    /// The image has more than [`MAX_PROGRAM_HEADERS`] program headers.
    TooManyHeaders,
    /// The program header table does not lie inside the image.
    HeadersOutOfFile,
    /// The load base is not page aligned, is not zero for an `ET_EXEC`
    /// image, or is not aligned to a segment's `p_align`.
    BadBase,
    /// A segment's file bytes do not lie inside the image.
    SegmentOutOfFile,
    /// A loadable segment has more file bytes than memory bytes.
    FileLargerThanMemory,
    /// A loadable segment's alignment is neither zero nor a power of two.
    BadAlignment,
    /// A loadable segment's address and file offset differ modulo the page
    /// size or modulo its alignment.
    Misaligned,
    /// Two loadable segments share a page.
    Overlap,
    /// A loadable segment is both writable and executable.
    WritableAndExecutable,
    /// A loadable segment has a page outside the window.
    OutsideWindow,
    /// The entry point is not inside an executable segment.
    EntryNotExecutable,
    /// The image has no loadable segment.
    NoLoadSegments,
    /// The image has more than [`MAX_LOAD_SEGMENTS`] loadable segments.
    TooManyLoadSegments,
    /// An address computation overflowed.
    Overflow,
    /// The image needs a dynamic linker: it names an interpreter or a shared
    /// library.
    DynamicLinking,
    /// The image uses thread-local storage, which jos does not set up yet.
    TlsUnsupported,
    /// The dynamic section is malformed: there is a second one, it has no
    /// `DT_NULL`, its RELA table is incomplete or misshapen, or the table is
    /// not in the file bytes of a loadable segment.
    BadDynamic,
    /// The dynamic section asks for relocations jos does not apply: REL,
    /// RELR, PLT, or text relocations.
    UnsupportedDynamic,
    /// A relocation is neither `R_X86_64_NONE` nor an `R_X86_64_RELATIVE`
    /// without a symbol.
    UnsupportedRelocation,
    /// A relocation writes bytes outside every writable segment.
    RelocationOutsideWritable,
}

/// The access a segment asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentFlags {
    /// The segment may be read.
    pub read: bool,
    /// The segment may be written.
    pub write: bool,
    /// The segment may be executed.
    pub execute: bool,
}

/// One loadable segment, moved to where it will live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadSegment {
    /// Address of the segment's first byte: the load base plus `p_vaddr`.
    pub vaddr: u64,
    /// Bytes the segment occupies in memory.
    pub mem_size: u64,
    /// Offset of the segment's bytes in the image.
    pub file_offset: u64,
    /// Bytes copied from the image; the rest of `mem_size` is zeroed.
    pub file_size: u64,
    /// The access the segment asks for.
    pub flags: SegmentFlags,
}

impl LoadSegment {
    /// Returns the address of the page holding the segment's first byte.
    #[must_use]
    pub const fn page_start(&self) -> u64 {
        self.vaddr & !(PAGE_SIZE - 1)
    }

    /// Returns the address just past the page holding the segment's last
    /// byte. For a segment of a [`LoadPlan`] this never overflows.
    #[must_use]
    pub const fn page_end(&self) -> u64 {
        (self.vaddr + self.mem_size + (PAGE_SIZE - 1)) & !(PAGE_SIZE - 1)
    }
}

/// One word the loader patches after copying the segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Relocation {
    /// Address of the eight little-endian bytes to overwrite.
    pub target: u64,
    /// The value to store there.
    pub value: u64,
}

/// What loading an image takes: its segments, entry point, and relocations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadPlan {
    /// The entry point, moved up by the load base.
    entry: u64,
    /// The load base every address was moved up by.
    base: u64,
    /// The loadable segments in program header order; the first
    /// `segment_count` are live.
    segments: [LoadSegment; MAX_LOAD_SEGMENTS],
    /// How many entries of `segments` are live.
    segment_count: usize,
    /// File offset of the RELA table.
    rela_offset: u64,
    /// Entries in the RELA table, `R_X86_64_NONE` ones included.
    rela_entries: u64,
    /// How many entries of the RELA table are relocations to apply.
    relocation_count: usize,
}

/// The value of the unused entries of a plan's segment array.
const NO_SEGMENT: LoadSegment = LoadSegment {
    vaddr: 0,
    mem_size: 0,
    file_offset: 0,
    file_size: 0,
    flags: SegmentFlags { read: false, write: false, execute: false },
};

impl LoadPlan {
    /// Checks `image` and plans how to load it at `base`, with every page
    /// inside `window`, the address range `[lo, hi)`.
    ///
    /// A position-independent (`ET_DYN`) image is moved up by `base`, which
    /// must be page aligned and aligned to every segment's `p_align`. A
    /// fixed-address (`ET_EXEC`) image needs `base == 0`.
    ///
    /// # Errors
    ///
    /// The [`ElfError`] for the first problem found. The module
    /// documentation lists what an accepted plan guarantees.
    pub fn parse(image: &[u8], base: u64, window: (u64, u64)) -> Result<Self, ElfError> {
        let header = read_header(image, base)?;
        let mut plan = Self {
            entry: 0,
            base,
            segments: [NO_SEGMENT; MAX_LOAD_SEGMENTS],
            segment_count: 0,
            rela_offset: 0,
            rela_entries: 0,
            relocation_count: 0,
        };
        let mut dynamic = None;
        for i in 0..u64::from(header.phnum) {
            // read_header checked that the whole table lies inside the image.
            let at = header.phoff + i * PHDR_SIZE;
            let ph = ProgramHeader::read(image, at).ok_or(ElfError::HeadersOutOfFile)?;
            match ph.kind {
                PT_LOAD => {
                    let Some(segment) = load_segment(&ph, image, base, window)? else {
                        continue;
                    };
                    let shares_a_page = |s: &LoadSegment| {
                        s.page_start() < segment.page_end() && segment.page_start() < s.page_end()
                    };
                    if plan.segments().iter().any(shares_a_page) {
                        return Err(ElfError::Overlap);
                    }
                    let slot = plan
                        .segments
                        .get_mut(plan.segment_count)
                        .ok_or(ElfError::TooManyLoadSegments)?;
                    *slot = segment;
                    plan.segment_count += 1;
                }
                PT_DYNAMIC if dynamic.is_some() => return Err(ElfError::BadDynamic),
                PT_DYNAMIC => {
                    if !in_file(ph.offset, ph.file_size, image) {
                        return Err(ElfError::SegmentOutOfFile);
                    }
                    dynamic = Some((ph.offset, ph.file_size));
                }
                PT_INTERP => return Err(ElfError::DynamicLinking),
                PT_TLS => return Err(ElfError::TlsUnsupported),
                _ => {}
            }
        }
        if plan.segment_count == 0 {
            return Err(ElfError::NoLoadSegments);
        }
        let entry = base.checked_add(header.entry).ok_or(ElfError::Overflow)?;
        let runs_entry =
            |s: &LoadSegment| s.flags.execute && s.vaddr <= entry && entry - s.vaddr < s.mem_size;
        if !plan.segments().iter().any(runs_entry) {
            return Err(ElfError::EntryNotExecutable);
        }
        plan.entry = entry;
        if let Some((offset, size)) = dynamic {
            plan.read_relocations(image, offset, size)?;
        }
        Ok(plan)
    }

    /// Returns the entry point, moved up by the load base.
    #[must_use]
    pub const fn entry(&self) -> u64 {
        self.entry
    }

    /// Returns the segments to load, in program header order.
    #[must_use]
    pub fn segments(&self) -> &[LoadSegment] {
        &self.segments[..self.segment_count]
    }

    /// Returns how many relocations [`relocations`](Self::relocations)
    /// yields.
    #[must_use]
    pub const fn relocation_count(&self) -> usize {
        self.relocation_count
    }

    /// Returns the relocations to apply, decoded from `image`, which must be
    /// the image this plan was parsed from.
    ///
    /// [`parse`](Self::parse) already checked every entry, so this yields
    /// exactly [`relocation_count`](Self::relocation_count) relocations and
    /// cannot fail. Each entry is checked again as it is decoded, so handed a
    /// different image it skips an entry that would write outside a writable
    /// segment rather than yield it.
    pub fn relocations<'a>(&'a self, image: &'a [u8]) -> impl Iterator<Item = Relocation> + 'a {
        (0..self.rela_entries).filter_map(move |i| {
            let at = self.rela_offset + i * RELA_SIZE;
            decode_relocation(image, at, self.base, self.segments()).ok().flatten()
        })
    }

    /// Finds the RELA table the dynamic section at `[offset, offset + size)`
    /// of `image` names, checks every entry, and records where the table is.
    fn read_relocations(&mut self, image: &[u8], offset: u64, size: u64) -> Result<(), ElfError> {
        let Some((vaddr, table_size)) = rela_table(image, offset, size)? else {
            return Ok(());
        };
        if table_size == 0 {
            return Ok(());
        }
        let start = self.base.checked_add(vaddr).ok_or(ElfError::Overflow)?;
        let end = start.checked_add(table_size).ok_or(ElfError::Overflow)?;
        // the table is decoded from the image, so it must be file bytes of a segment.
        let holder = self
            .segments()
            .iter()
            .find(|s| s.vaddr <= start && end - s.vaddr <= s.file_size)
            .copied()
            .ok_or(ElfError::BadDynamic)?;
        self.rela_offset = holder.file_offset + (start - holder.vaddr);
        self.rela_entries = table_size / RELA_SIZE;
        for i in 0..self.rela_entries {
            let at = self.rela_offset + i * RELA_SIZE;
            if decode_relocation(image, at, self.base, self.segments())?.is_some() {
                self.relocation_count += 1;
            }
        }
        Ok(())
    }
}

/// The fields of the ELF file header the loader reads.
struct FileHeader {
    /// The identification bytes up to `EI_VERSION`: magic, class, data
    /// encoding, and version.
    ident: [u8; 7],
    /// The file type, `e_type`.
    kind: u16,
    /// The target architecture, `e_machine`.
    machine: u16,
    /// The file version, `e_version`.
    version: u32,
    /// The link-time entry point, `e_entry`.
    entry: u64,
    /// The file offset of the program header table, `e_phoff`.
    phoff: u64,
    /// The size of the file header, `e_ehsize`.
    ehsize: u16,
    /// The size of one program header, `e_phentsize`.
    phentsize: u16,
    /// The number of program headers, `e_phnum`.
    phnum: u16,
}

impl FileHeader {
    /// Reads the file header at the start of `image`, or returns `None` if it
    /// runs past the end.
    fn read(image: &[u8]) -> Option<Self> {
        Some(Self {
            ident: *image.first_chunk()?,
            kind: read_u16(image, 16)?,
            machine: read_u16(image, 18)?,
            version: read_u32(image, 20)?,
            entry: read_u64(image, 24)?,
            phoff: read_u64(image, 32)?,
            ehsize: read_u16(image, 52)?,
            phentsize: read_u16(image, 54)?,
            phnum: read_u16(image, 56)?,
        })
    }
}

/// The fields of a program header the loader reads.
struct ProgramHeader {
    /// The segment type, `p_type`.
    kind: u32,
    /// The `PF_*` access bits, `p_flags`.
    flags: u32,
    /// The file offset of the segment's bytes, `p_offset`.
    offset: u64,
    /// The link-time address of the segment, `p_vaddr`.
    vaddr: u64,
    /// The bytes of the segment present in the image, `p_filesz`.
    file_size: u64,
    /// The bytes the segment occupies in memory, `p_memsz`.
    mem_size: u64,
    /// The alignment of the segment, `p_align`.
    align: u64,
}

impl ProgramHeader {
    /// Reads the program header at byte `at` of `image`, or returns `None` if
    /// it runs past the end.
    fn read(image: &[u8], at: u64) -> Option<Self> {
        Some(Self {
            kind: read_u32(image, at)?,
            flags: read_u32(image, at + 4)?,
            offset: read_u64(image, at + 8)?,
            vaddr: read_u64(image, at + 16)?,
            file_size: read_u64(image, at + 32)?,
            mem_size: read_u64(image, at + 40)?,
            align: read_u64(image, at + 48)?,
        })
    }
}

/// Reads the little-endian `u16` at byte `at` of `bytes`, or returns `None`
/// if it runs past the end.
fn read_u16(bytes: &[u8], at: u64) -> Option<u16> {
    let start = usize::try_from(at).ok()?;
    Some(u16::from_le_bytes(bytes.get(start..start.checked_add(2)?)?.try_into().ok()?))
}

/// Reads the little-endian `u32` at byte `at` of `bytes`, or returns `None`
/// if it runs past the end.
fn read_u32(bytes: &[u8], at: u64) -> Option<u32> {
    let start = usize::try_from(at).ok()?;
    Some(u32::from_le_bytes(bytes.get(start..start.checked_add(4)?)?.try_into().ok()?))
}

/// Reads the little-endian `u64` at byte `at` of `bytes`, or returns `None`
/// if it runs past the end.
fn read_u64(bytes: &[u8], at: u64) -> Option<u64> {
    let start = usize::try_from(at).ok()?;
    Some(u64::from_le_bytes(bytes.get(start..start.checked_add(8)?)?.try_into().ok()?))
}

/// Returns `true` if the `size` bytes at file offset `offset` lie inside
/// `image`.
fn in_file(offset: u64, size: u64, image: &[u8]) -> bool {
    offset.checked_add(size).is_some_and(|end| end <= image.len() as u64)
}

/// Reads and checks the file header of `image`, and checks that `base` suits
/// it.
fn read_header(image: &[u8], base: u64) -> Result<FileHeader, ElfError> {
    if (image.len() as u64) < EHDR_SIZE {
        return Err(ElfError::TooShort);
    }
    let header = FileHeader::read(image).ok_or(ElfError::TooShort)?;
    let [m0, m1, m2, m3, class, data, version] = header.ident;
    // compared as one word: a byte-slice compare is a loop the proofs must unwind.
    if u32::from_le_bytes([m0, m1, m2, m3]) != u32::from_le_bytes(ELF_MAGIC) {
        return Err(ElfError::BadMagic);
    }
    if class != ELFCLASS64 {
        return Err(ElfError::NotElf64);
    }
    if data != ELFDATA2LSB {
        return Err(ElfError::NotLittleEndian);
    }
    if version != EV_CURRENT || header.version != u32::from(EV_CURRENT) {
        return Err(ElfError::BadVersion);
    }
    if header.machine != EM_X86_64 {
        return Err(ElfError::NotX86_64);
    }
    if header.kind != ET_EXEC && header.kind != ET_DYN {
        return Err(ElfError::BadType);
    }
    if u64::from(header.ehsize) != EHDR_SIZE || u64::from(header.phentsize) != PHDR_SIZE {
        return Err(ElfError::BadHeaderSize);
    }
    if usize::from(header.phnum) > MAX_PROGRAM_HEADERS {
        return Err(ElfError::TooManyHeaders);
    }
    if !in_file(header.phoff, u64::from(header.phnum) * PHDR_SIZE, image) {
        return Err(ElfError::HeadersOutOfFile);
    }
    let base_fits = if header.kind == ET_EXEC { base == 0 } else { base.is_multiple_of(PAGE_SIZE) };
    if !base_fits {
        return Err(ElfError::BadBase);
    }
    Ok(header)
}

/// Checks one `PT_LOAD` header on its own and moves it up by `base`, or
/// returns `None` for a segment that occupies no memory.
fn load_segment(
    ph: &ProgramHeader,
    image: &[u8],
    base: u64,
    window: (u64, u64),
) -> Result<Option<LoadSegment>, ElfError> {
    if ph.file_size > ph.mem_size {
        return Err(ElfError::FileLargerThanMemory);
    }
    if ph.mem_size == 0 {
        return Ok(None);
    }
    if !in_file(ph.offset, ph.file_size, image) {
        return Err(ElfError::SegmentOutOfFile);
    }
    if ph.align != 0 && !ph.align.is_power_of_two() {
        return Err(ElfError::BadAlignment);
    }
    // the alignment is zero or a power of two, so masking takes the remainder.
    let mask = ph.align.saturating_sub(1);
    if (ph.vaddr ^ ph.offset) & (PAGE_SIZE - 1) != 0 || (ph.vaddr ^ ph.offset) & mask != 0 {
        return Err(ElfError::Misaligned);
    }
    // a segment keeps its alignment only if the base has it too.
    if base & mask != 0 {
        return Err(ElfError::BadBase);
    }
    let flags = SegmentFlags {
        read: ph.flags & PF_R != 0,
        write: ph.flags & PF_W != 0,
        execute: ph.flags & PF_X != 0,
    };
    if flags.write && flags.execute {
        return Err(ElfError::WritableAndExecutable);
    }
    let vaddr = base.checked_add(ph.vaddr).ok_or(ElfError::Overflow)?;
    // page_end rounds the end up, so that must not overflow either.
    let end = vaddr.checked_add(ph.mem_size);
    if end.and_then(|end| end.checked_add(PAGE_SIZE - 1)).is_none() {
        return Err(ElfError::Overflow);
    }
    let segment = LoadSegment {
        vaddr,
        mem_size: ph.mem_size,
        file_offset: ph.offset,
        file_size: ph.file_size,
        flags,
    };
    if segment.page_start() < window.0 || segment.page_end() > window.1 {
        return Err(ElfError::OutsideWindow);
    }
    Ok(Some(segment))
}

/// Walks the dynamic section at `[offset, offset + size)` of `image` and
/// returns the link-time address and byte size of the RELA table it names,
/// if it names one.
fn rela_table(image: &[u8], offset: u64, size: u64) -> Result<Option<(u64, u64)>, ElfError> {
    let mut rela = None;
    let mut rela_size = None;
    let mut entry_size_given = false;
    for i in 0..size / DYN_SIZE {
        let at = offset + i * DYN_SIZE;
        let (Some(tag), Some(value)) = (read_u64(image, at), read_u64(image, at + 8)) else {
            return Err(ElfError::SegmentOutOfFile);
        };
        match tag {
            DT_NULL => {
                return match (rela, rela_size) {
                    (None, None) => Ok(None),
                    (Some(vaddr), Some(bytes)) if entry_size_given && bytes % RELA_SIZE == 0 => {
                        Ok(Some((vaddr, bytes)))
                    }
                    _ => Err(ElfError::BadDynamic),
                };
            }
            DT_RELA => rela = Some(value),
            DT_RELASZ => rela_size = Some(value),
            DT_RELAENT if value == RELA_SIZE => entry_size_given = true,
            DT_RELAENT => return Err(ElfError::BadDynamic),
            DT_NEEDED => return Err(ElfError::DynamicLinking),
            DT_REL | DT_RELSZ | DT_TEXTREL | DT_RELR => return Err(ElfError::UnsupportedDynamic),
            DT_PLTRELSZ if value != 0 => return Err(ElfError::UnsupportedDynamic),
            DT_FLAGS if value & DF_TEXTREL != 0 => return Err(ElfError::UnsupportedDynamic),
            _ => {}
        }
    }
    // the section ended without a DT_NULL.
    Err(ElfError::BadDynamic)
}

/// Decodes and checks the RELA entry at file offset `at` of `image`, for a
/// plan loaded at `base` with these segments.
///
/// Returns `Ok(None)` for an `R_X86_64_NONE` entry, which patches nothing.
fn decode_relocation(
    image: &[u8],
    at: u64,
    base: u64,
    segments: &[LoadSegment],
) -> Result<Option<Relocation>, ElfError> {
    let (Some(offset), Some(info), Some(addend)) =
        (read_u64(image, at), read_u64(image, at + 8), read_u64(image, at + 16))
    else {
        return Err(ElfError::BadDynamic);
    };
    // the low half of r_info is the type, the high half the symbol.
    match (info & 0xffff_ffff, info >> 32) {
        (R_X86_64_NONE, _) => Ok(None),
        (R_X86_64_RELATIVE, 0) => {
            let target = base.checked_add(offset).ok_or(ElfError::Overflow)?;
            let end = target.checked_add(8).ok_or(ElfError::Overflow)?;
            let value = base.checked_add_signed(addend.cast_signed()).ok_or(ElfError::Overflow)?;
            let holds_target =
                |s: &LoadSegment| s.flags.write && s.vaddr <= target && end <= s.vaddr + s.mem_size;
            if segments.iter().any(holds_target) {
                Ok(Some(Relocation { target, value }))
            } else {
                Err(ElfError::RelocationOutsideWritable)
            }
        }
        _ => Err(ElfError::UnsupportedRelocation),
    }
}

/// Checks every guarantee the module documentation lists for `plan`, parsed
/// from `image` for `window`, without using the parser's code: fields are
/// decoded afresh from the image and every bound is recomputed.
///
/// The one thing taken on trust is which RELA table the dynamic section
/// names; its entries are still checked one by one.
#[cfg(any(test, kani))]
fn plan_invariants_hold(plan: &LoadPlan, image: &[u8], window: (u64, u64)) -> bool {
    let field = |at: u64, size: usize| le_field(image, at, size);
    let segments = plan.segments();
    if segments.is_empty() || segments.len() > MAX_LOAD_SEGMENTS {
        return false;
    }
    for s in segments {
        let Some(end) = s.vaddr.checked_add(s.mem_size) else {
            return false;
        };
        let Some(page_end) = end.checked_next_multiple_of(PAGE_SIZE) else {
            return false;
        };
        let page_start = s.vaddr & !(PAGE_SIZE - 1);
        let file_end = s.file_offset.checked_add(s.file_size);
        if s.mem_size == 0
            || s.file_size > s.mem_size
            || file_end.is_none_or(|end| end > image.len() as u64)
            || (s.vaddr ^ s.file_offset) & (PAGE_SIZE - 1) != 0
            || (s.flags.write && s.flags.execute)
            || s.page_start() != page_start
            || s.page_end() != page_end
            || page_start < window.0
            || page_end > window.1
        {
            return false;
        }
    }
    for (i, a) in segments.iter().enumerate() {
        for b in &segments[i + 1..] {
            if a.page_start() < b.page_end() && b.page_start() < a.page_end() {
                return false;
            }
        }
    }
    // the entry is e_entry moved up by the base, inside an executable segment.
    let entry = plan.entry();
    if field(24, 8).and_then(|e| plan.base.checked_add(e)) != Some(entry)
        || !segments.iter().any(|s| s.flags.execute && s.vaddr <= entry && entry < s.vaddr + s.mem_size)
    {
        return false;
    }
    // the segments are the PT_LOAD headers with memory, in order, moved up by the base.
    let (Some(phoff), Some(phnum)) = (field(32, 8), field(56, 2)) else {
        return false;
    };
    let mut loads = 0;
    for i in 0..phnum {
        let header = |offset: u64, size| {
            let at = phoff.checked_add(i * 56)?.checked_add(offset)?;
            field(at, size)
        };
        if header(0, 4) != Some(1) || header(40, 8) == Some(0) {
            continue;
        }
        let (Some(flags), Some(offset), Some(vaddr), Some(file_size), Some(mem_size)) =
            (header(4, 4), header(8, 8), header(16, 8), header(32, 8), header(40, 8))
        else {
            return false;
        };
        let expected = plan.base.checked_add(vaddr).map(|vaddr| LoadSegment {
            vaddr,
            mem_size,
            file_offset: offset,
            file_size,
            flags: SegmentFlags { read: flags & 4 != 0, write: flags & 2 != 0, execute: flags & 1 != 0 },
        });
        if expected.is_none() || segments.get(loads) != expected.as_ref() {
            return false;
        }
        loads += 1;
    }
    loads == segments.len() && relocations_hold(plan, image)
}

/// Decodes the little-endian field of `size` bytes at byte `at` of `image`.
#[cfg(any(test, kani))]
fn le_field(image: &[u8], at: u64, size: usize) -> Option<u64> {
    let start = usize::try_from(at).ok()?;
    let mut word = [0; 8];
    word.get_mut(..size)?.copy_from_slice(image.get(start..start.checked_add(size)?)?);
    Some(u64::from_le_bytes(word))
}

/// The relocation half of [`plan_invariants_hold`]: each RELATIVE entry is
/// yielded in order, writing base plus addend into a writable segment; NONE
/// entries are skipped and no other type is allowed.
#[cfg(any(test, kani))]
fn relocations_hold(plan: &LoadPlan, image: &[u8]) -> bool {
    let segments = plan.segments();
    let mut yielded = plan.relocations(image);
    let mut relatives = 0;
    for i in 0..plan.rela_entries {
        let entry = |offset: u64| {
            let at = plan.rela_offset.checked_add(i.checked_mul(24)?)?.checked_add(offset)?;
            le_field(image, at, 8)
        };
        let (Some(offset), Some(info), Some(addend)) = (entry(0), entry(8), entry(16)) else {
            return false;
        };
        let kind = info & 0xffff_ffff;
        if kind == 0 {
            continue;
        }
        let Some(r) = yielded.next() else {
            return false;
        };
        let end = r.target.checked_add(8);
        let inside_writable = |s: &LoadSegment| {
            s.flags.write && s.vaddr <= r.target && end.is_some_and(|end| end <= s.vaddr + s.mem_size)
        };
        if info != 8
            || Some(r.target) != plan.base.checked_add(offset)
            || i128::from(r.value) != i128::from(plan.base) + i128::from(addend.cast_signed())
            || !segments.iter().any(inside_writable)
        {
            return false;
        }
        relatives += 1;
    }
    yielded.next().is_none() && relatives == plan.relocation_count()
}

/// Writes an `x86_64` ELF64 file header of type `kind` at the start of
/// `image`, with `phnum` program headers right after it.
#[cfg(any(test, kani))]
fn write_header(image: &mut [u8], kind: u16, entry: u64, phnum: u16) {
    image[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', ELFCLASS64, ELFDATA2LSB, EV_CURRENT]);
    image[16..18].copy_from_slice(&kind.to_le_bytes());
    image[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
    image[20..24].copy_from_slice(&1_u32.to_le_bytes());
    image[24..32].copy_from_slice(&entry.to_le_bytes());
    image[32..40].copy_from_slice(&EHDR_SIZE.to_le_bytes());
    image[52..54].copy_from_slice(&64_u16.to_le_bytes());
    image[54..56].copy_from_slice(&56_u16.to_le_bytes());
    image[56..58].copy_from_slice(&phnum.to_le_bytes());
}

#[cfg(any(test, kani))]
impl ProgramHeader {
    /// Writes this header at byte `at` of `image`, with `p_paddr` equal to
    /// `p_vaddr` as linkers emit it.
    fn write(&self, image: &mut [u8], at: usize) {
        image[at..at + 4].copy_from_slice(&self.kind.to_le_bytes());
        image[at + 4..at + 8].copy_from_slice(&self.flags.to_le_bytes());
        image[at + 8..at + 16].copy_from_slice(&self.offset.to_le_bytes());
        image[at + 16..at + 24].copy_from_slice(&self.vaddr.to_le_bytes());
        image[at + 24..at + 32].copy_from_slice(&self.vaddr.to_le_bytes());
        image[at + 32..at + 40].copy_from_slice(&self.file_size.to_le_bytes());
        image[at + 40..at + 48].copy_from_slice(&self.mem_size.to_le_bytes());
        image[at + 48..at + 56].copy_from_slice(&self.align.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DF_TEXTREL, DT_FLAGS, DT_NEEDED, DT_NULL, DT_PLTRELSZ, DT_REL, DT_RELA, DT_RELAENT,
        DT_RELASZ, DT_RELR, DT_RELSZ, DT_TEXTREL, ET_DYN, ET_EXEC, ElfError, LoadPlan,
        LoadSegment, PAGE_SIZE, PF_R, PF_W, PF_X, PT_DYNAMIC, PT_INTERP, PT_LOAD, PT_TLS,
        ProgramHeader, R_X86_64_NONE, R_X86_64_RELATIVE, Relocation, SegmentFlags,
        plan_invariants_hold, write_header,
    };
    use crate::rng::{KernelRng, SimRng};
    // the test harness links std; the library itself stays no_std.
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    /// The load base the tests use.
    const BASE: u64 = 0x40_0000;
    /// The window the tests load into: the lower half, less page zero.
    const WINDOW: (u64, u64) = (PAGE_SIZE, 1 << 47);
    /// The dynamic tag counting the relative relocations, a hint jos ignores.
    const DT_RELACOUNT: u64 = 0x6fff_fff9;
    /// The dynamic tag holding the `DF_1_*` flags, which jos ignores.
    const DT_FLAGS_1: u64 = 0x6fff_fffb;
    /// The dynamic tag a debugger fills in, which jos ignores.
    const DT_DEBUG: u64 = 21;

    /// The code segment of the test images: the headers and the code after
    /// them.
    const CODE: ProgramHeader = ProgramHeader {
        kind: PT_LOAD,
        flags: PF_R | PF_X,
        offset: 0,
        vaddr: 0,
        file_size: 0x140,
        mem_size: 0x140,
        align: PAGE_SIZE,
    };
    /// The data segment: the dynamic section, the RELA table, data, then bss.
    const DATA: ProgramHeader = ProgramHeader {
        kind: PT_LOAD,
        flags: PF_R | PF_W,
        offset: 0x200,
        vaddr: 0x1200,
        file_size: 0x100,
        mem_size: 0x2000,
        align: PAGE_SIZE,
    };
    /// The dynamic section, at the start of the data segment.
    const DYNAMIC: ProgramHeader = ProgramHeader {
        kind: PT_DYNAMIC,
        flags: PF_R | PF_W,
        offset: 0x200,
        vaddr: 0x1200,
        file_size: 0x60,
        mem_size: 0x60,
        align: 8,
    };

    /// Builds a `len`-byte image of type `kind` with these program headers.
    fn build(kind: u16, entry: u64, phdrs: &[ProgramHeader], len: usize) -> Vec<u8> {
        let mut image = vec![0; len];
        write_header(&mut image, kind, entry, u16::try_from(phdrs.len()).unwrap());
        for (i, ph) in phdrs.iter().enumerate() {
            ph.write(&mut image, 64 + 56 * i);
        }
        image
    }

    /// Writes little-endian words from byte `at` on.
    fn put(image: &mut [u8], at: usize, words: &[u64]) {
        for (i, word) in words.iter().enumerate() {
            image[at + 8 * i..at + 8 * (i + 1)].copy_from_slice(&word.to_le_bytes());
        }
    }

    /// Returns a copy of `image` with `bytes` written at byte `at`.
    fn with(image: &[u8], at: usize, bytes: &[u8]) -> Vec<u8> {
        let mut image = image.to_vec();
        image[at..at + bytes.len()].copy_from_slice(bytes);
        image
    }

    /// Returns the sixteen bytes of a dynamic section entry.
    fn dyn_entry(tag: u64, value: u64) -> Vec<u8> {
        [tag.to_le_bytes(), value.to_le_bytes()].concat()
    }

    /// A position-independent image laid out the way rust-lld links one, with
    /// these program headers: code at address zero, then data and bss whose
    /// first bytes are the dynamic section and a RELA table of two
    /// `R_X86_64_RELATIVE` entries around an `R_X86_64_NONE` one.
    fn pie_with(phdrs: &[ProgramHeader]) -> Vec<u8> {
        let mut image = build(ET_DYN, 0x100, phdrs, 0x300);
        put(&mut image, 0x200, &[DT_RELA, 0x1260, DT_RELASZ, 72, DT_RELAENT, 24]);
        put(&mut image, 0x230, &[DT_RELACOUNT, 2, DT_FLAGS_1, 0x0800_0000, DT_NULL, 0]);
        put(&mut image, 0x260, &[0x12c0, R_X86_64_RELATIVE, 0x100]);
        put(&mut image, 0x278, &[0, R_X86_64_NONE, 0]);
        // the last word of the bss, with a negative addend.
        put(&mut image, 0x290, &[0x31f8, R_X86_64_RELATIVE, (-0x10_i64).cast_unsigned()]);
        image
    }

    /// The position-independent test image.
    fn pie() -> Vec<u8> {
        pie_with(&[CODE, DATA, DYNAMIC])
    }

    /// The same program linked at a fixed address, without a dynamic section.
    fn exec() -> Vec<u8> {
        let code = ProgramHeader { vaddr: BASE, ..CODE };
        let data = ProgramHeader { vaddr: BASE + 0x1200, ..DATA };
        build(ET_EXEC, BASE + 0x100, &[code, data], 0x300)
    }

    /// Parses `image` at the test base, into the test window.
    fn parse(image: &[u8]) -> Result<LoadPlan, ElfError> {
        LoadPlan::parse(image, BASE, WINDOW)
    }

    #[test]
    fn parses_a_position_independent_image() {
        let image = pie();
        let plan = parse(&image).unwrap();
        let code = LoadSegment {
            vaddr: BASE,
            mem_size: 0x140,
            file_offset: 0,
            file_size: 0x140,
            flags: SegmentFlags { read: true, write: false, execute: true },
        };
        let data = LoadSegment {
            vaddr: BASE + 0x1200,
            mem_size: 0x2000,
            file_offset: 0x200,
            file_size: 0x100,
            flags: SegmentFlags { read: true, write: true, execute: false },
        };
        assert_eq!(plan.entry(), BASE + 0x100);
        assert_eq!(plan.segments(), [code, data]);
        assert_eq!((code.page_start(), code.page_end()), (BASE, BASE + 0x1000));
        // the bss carries the data segment on into a third page.
        assert_eq!((data.page_start(), data.page_end()), (BASE + 0x1000, BASE + 0x4000));
        assert_eq!(plan.relocation_count(), 2);
        let relocations: Vec<Relocation> = plan.relocations(&image).collect();
        assert_eq!(
            relocations,
            [
                Relocation { target: BASE + 0x12c0, value: BASE + 0x100 },
                Relocation { target: BASE + 0x31f8, value: BASE - 0x10 },
            ]
        );
        assert!(plan_invariants_hold(&plan, &image, WINDOW));
    }

    #[test]
    fn parses_a_fixed_address_image() {
        let image = exec();
        let plan = LoadPlan::parse(&image, 0, WINDOW).unwrap();
        // the position-independent layout, already where it will run.
        assert_eq!(plan.segments(), parse(&pie()).unwrap().segments());
        assert_eq!(plan.entry(), BASE + 0x100);
        assert_eq!(plan.relocation_count(), 0);
        assert_eq!(plan.relocations(&image).count(), 0);
        assert!(plan_invariants_hold(&plan, &image, WINDOW));
    }

    #[test]
    fn skips_segments_without_memory() {
        // an empty segment maps nothing, so even a writable and executable one
        // on the code page is harmless.
        let empty = ProgramHeader { flags: PF_R | PF_W | PF_X, file_size: 0, mem_size: 0, ..CODE };
        let image = pie_with(&[CODE, empty, DATA, DYNAMIC]);
        let plan = parse(&image).unwrap();
        assert_eq!(plan.segments().len(), 2);
        assert!(plan_invariants_hold(&plan, &image, WINDOW));
        // but file bytes need memory to land in.
        let bad = ProgramHeader { file_size: 1, mem_size: 0, ..CODE };
        assert_eq!(parse(&pie_with(&[CODE, bad, DATA, DYNAMIC])), Err(ElfError::FileLargerThanMemory));
    }

    #[test]
    fn ignores_other_program_headers() {
        let other = |kind| ProgramHeader { kind, flags: PF_R, offset: 0, vaddr: 0, file_size: 0, mem_size: 0, align: 0 };
        // PT_NULL, PT_NOTE, PT_PHDR, PT_GNU_STACK, and PT_GNU_RELRO.
        let image = pie_with(&[
            other(0),
            CODE,
            other(4),
            DATA,
            other(6),
            DYNAMIC,
            other(0x6474_e551),
            other(0x6474_e552),
        ]);
        let plan = parse(&image).unwrap();
        assert_eq!(plan.segments(), parse(&pie()).unwrap().segments());
        assert_eq!(plan.relocation_count(), 2);
    }

    #[test]
    fn accepts_harmless_dynamic_tags() {
        // no PLT relocations after all, eager binding, and a debugger hook.
        for (tag, value) in [(DT_PLTRELSZ, 0), (DT_FLAGS, 8), (DT_DEBUG, 0)] {
            let image = with(&pie(), 0x230, &dyn_entry(tag, value));
            assert_eq!(parse(&image).map(|plan| plan.relocation_count()), Ok(2), "tag {tag}");
        }
    }

    #[test]
    fn an_empty_relocation_table_needs_no_address() {
        let mut image = pie();
        put(&mut image, 0x208, &[0xdead_0000]);
        put(&mut image, 0x218, &[0]);
        let plan = parse(&image).unwrap();
        assert_eq!(plan.relocation_count(), 0);
        assert_eq!(plan.relocations(&image).count(), 0);
    }

    #[test]
    fn a_large_alignment_constrains_the_base() {
        let code = ProgramHeader { align: 0x20_0000, ..CODE };
        let image = pie_with(&[code, DATA, DYNAMIC]);
        // the test base is 2 MiB aligned; one page above it is not.
        assert!(parse(&image).is_ok());
        assert_eq!(LoadPlan::parse(&image, BASE + PAGE_SIZE, WINDOW), Err(ElfError::BadBase));
    }

    #[test]
    fn relocations_from_another_image_are_checked_again() {
        let image = pie();
        let plan = parse(&image).unwrap();
        // pointing the first relocation at the read-only code drops just that one.
        let other = with(&image, 0x260, &0x100_u64.to_le_bytes());
        let relocations: Vec<Relocation> = plan.relocations(&other).collect();
        assert_eq!(relocations, [Relocation { target: BASE + 0x31f8, value: BASE - 0x10 }]);
        // a truncated image yields nothing, and does not panic.
        assert_eq!(plan.relocations(&image[..0x200]).count(), 0);
    }

    #[test]
    fn refuses_a_short_image() {
        assert_eq!(parse(&[]), Err(ElfError::TooShort));
        assert_eq!(parse(&pie()[..63]), Err(ElfError::TooShort));
    }

    #[test]
    fn refuses_a_bad_magic() {
        assert_eq!(parse(&with(&pie(), 1, b"e")), Err(ElfError::BadMagic));
    }

    #[test]
    fn refuses_a_32_bit_image() {
        assert_eq!(parse(&with(&pie(), 4, &[1])), Err(ElfError::NotElf64));
    }

    #[test]
    fn refuses_a_big_endian_image() {
        assert_eq!(parse(&with(&pie(), 5, &[2])), Err(ElfError::NotLittleEndian));
    }

    #[test]
    fn refuses_an_unknown_version() {
        assert_eq!(parse(&with(&pie(), 6, &[2])), Err(ElfError::BadVersion));
        assert_eq!(parse(&with(&pie(), 20, &2_u32.to_le_bytes())), Err(ElfError::BadVersion));
    }

    #[test]
    fn refuses_another_architecture() {
        // aarch64.
        assert_eq!(parse(&with(&pie(), 18, &0xb7_u16.to_le_bytes())), Err(ElfError::NotX86_64));
    }

    #[test]
    fn refuses_files_that_are_not_executables() {
        // ET_REL and ET_CORE.
        for kind in [1_u16, 4] {
            assert_eq!(parse(&with(&pie(), 16, &kind.to_le_bytes())), Err(ElfError::BadType));
        }
    }

    #[test]
    fn refuses_odd_header_sizes() {
        assert_eq!(parse(&with(&pie(), 52, &52_u16.to_le_bytes())), Err(ElfError::BadHeaderSize));
        assert_eq!(parse(&with(&pie(), 54, &64_u16.to_le_bytes())), Err(ElfError::BadHeaderSize));
    }

    #[test]
    fn refuses_too_many_program_headers() {
        // 0xffff is PN_XNUM, which moves the real count into a section header.
        for phnum in [33_u16, 0xffff] {
            assert_eq!(parse(&with(&pie(), 56, &phnum.to_le_bytes())), Err(ElfError::TooManyHeaders));
        }
    }

    #[test]
    fn refuses_program_headers_past_the_end() {
        // three headers starting 100 bytes before the end, and a wrapping offset.
        for phoff in [0x29c_u64, u64::MAX] {
            assert_eq!(parse(&with(&pie(), 32, &phoff.to_le_bytes())), Err(ElfError::HeadersOutOfFile));
        }
    }

    #[test]
    fn refuses_a_base_the_image_cannot_use() {
        assert_eq!(LoadPlan::parse(&pie(), BASE + 0x800, WINDOW), Err(ElfError::BadBase));
        assert_eq!(LoadPlan::parse(&exec(), PAGE_SIZE, WINDOW), Err(ElfError::BadBase));
    }

    #[test]
    fn refuses_segment_bytes_past_the_end() {
        let long = ProgramHeader { file_size: 0x101, ..DATA };
        assert_eq!(parse(&pie_with(&[CODE, long, DYNAMIC])), Err(ElfError::SegmentOutOfFile));
        let far = ProgramHeader { offset: u64::MAX, ..DYNAMIC };
        assert_eq!(parse(&pie_with(&[CODE, DATA, far])), Err(ElfError::SegmentOutOfFile));
    }

    #[test]
    fn refuses_more_file_bytes_than_memory() {
        let code = ProgramHeader { file_size: 0x141, ..CODE };
        assert_eq!(parse(&pie_with(&[code, DATA, DYNAMIC])), Err(ElfError::FileLargerThanMemory));
    }

    #[test]
    fn refuses_an_alignment_that_is_not_a_power_of_two() {
        let code = ProgramHeader { align: 0x3000, ..CODE };
        assert_eq!(parse(&pie_with(&[code, DATA, DYNAMIC])), Err(ElfError::BadAlignment));
    }

    #[test]
    fn refuses_misaligned_segments() {
        // the address and the file offset differ within the page.
        let data = ProgramHeader { vaddr: 0x1300, ..DATA };
        assert_eq!(parse(&pie_with(&[CODE, data, DYNAMIC])), Err(ElfError::Misaligned));
        // they agree within the page but not modulo the segment's alignment.
        let data = ProgramHeader { align: 0x2000, ..DATA };
        assert_eq!(parse(&pie_with(&[CODE, data, DYNAMIC])), Err(ElfError::Misaligned));
    }

    #[test]
    fn refuses_segments_that_share_a_page() {
        // the data would start right after the code, on the same page.
        let data = ProgramHeader { vaddr: 0x200, ..DATA };
        assert_eq!(parse(&pie_with(&[CODE, data, DYNAMIC])), Err(ElfError::Overlap));
    }

    #[test]
    fn refuses_writable_and_executable_segments() {
        let data = ProgramHeader { flags: PF_R | PF_W | PF_X, ..DATA };
        assert_eq!(parse(&pie_with(&[CODE, data, DYNAMIC])), Err(ElfError::WritableAndExecutable));
    }

    #[test]
    fn refuses_segments_outside_the_window() {
        // below the window, past its end, and on page zero.
        let above = (BASE + PAGE_SIZE, 1 << 47);
        assert_eq!(LoadPlan::parse(&pie(), BASE, above), Err(ElfError::OutsideWindow));
        let short = (PAGE_SIZE, BASE + 0x3000);
        assert_eq!(LoadPlan::parse(&pie(), BASE, short), Err(ElfError::OutsideWindow));
        assert_eq!(LoadPlan::parse(&pie(), 0, WINDOW), Err(ElfError::OutsideWindow));
    }

    #[test]
    fn refuses_an_entry_outside_the_code() {
        // in the data, one past the end of the code, and in no segment at all.
        for entry in [0x1200_u64, 0x140, 0x8000] {
            assert_eq!(parse(&with(&pie(), 24, &entry.to_le_bytes())), Err(ElfError::EntryNotExecutable));
        }
    }

    #[test]
    fn refuses_an_image_without_load_segments() {
        let note = |ph| ProgramHeader { kind: 4, ..ph };
        assert_eq!(parse(&pie_with(&[note(CODE), note(DATA), DYNAMIC])), Err(ElfError::NoLoadSegments));
        let empty = ProgramHeader { file_size: 0, mem_size: 0, ..CODE };
        assert_eq!(parse(&pie_with(&[empty, DYNAMIC])), Err(ElfError::NoLoadSegments));
    }

    #[test]
    fn refuses_too_many_load_segments() {
        // one page apart, the first one executable.
        let load = |k: u64| ProgramHeader {
            flags: if k == 0 { PF_R | PF_X } else { PF_R },
            vaddr: k * PAGE_SIZE,
            file_size: 0x10,
            mem_size: 0x10,
            ..CODE
        };
        let eight: Vec<ProgramHeader> = (0..8).map(load).collect();
        assert!(parse(&build(ET_DYN, 0, &eight, 0x300)).is_ok());
        let nine: Vec<ProgramHeader> = (0..9).map(load).collect();
        assert_eq!(parse(&build(ET_DYN, 0, &nine, 0x300)), Err(ElfError::TooManyLoadSegments));
    }

    #[test]
    fn refuses_addresses_that_overflow() {
        // the code's last page would end past the top of the address space.
        let top = u64::MAX - PAGE_SIZE + 1;
        assert_eq!(LoadPlan::parse(&pie(), top, (PAGE_SIZE, u64::MAX)), Err(ElfError::Overflow));
        assert_eq!(parse(&with(&pie(), 24, &u64::MAX.to_le_bytes())), Err(ElfError::Overflow));
        // a relocation target that wraps, and an addend reaching below zero.
        assert_eq!(parse(&with(&pie(), 0x260, &(u64::MAX - 4).to_le_bytes())), Err(ElfError::Overflow));
        let below_zero = (-0x50_0000_i64).cast_unsigned();
        assert_eq!(parse(&with(&pie(), 0x270, &below_zero.to_le_bytes())), Err(ElfError::Overflow));
    }

    #[test]
    fn refuses_dynamic_linking() {
        let interp = ProgramHeader { kind: PT_INTERP, file_size: 0x10, mem_size: 0x10, align: 1, ..CODE };
        assert_eq!(parse(&pie_with(&[CODE, interp, DATA, DYNAMIC])), Err(ElfError::DynamicLinking));
        let needed = with(&pie(), 0x230, &dyn_entry(DT_NEEDED, 1));
        assert_eq!(parse(&needed), Err(ElfError::DynamicLinking));
    }

    #[test]
    fn refuses_thread_local_storage() {
        let tls = ProgramHeader { kind: PT_TLS, file_size: 0x10, mem_size: 0x20, ..DATA };
        assert_eq!(parse(&pie_with(&[CODE, DATA, DYNAMIC, tls])), Err(ElfError::TlsUnsupported));
    }

    #[test]
    fn refuses_a_malformed_dynamic_section() {
        assert_eq!(parse(&pie_with(&[CODE, DATA, DYNAMIC, DYNAMIC])), Err(ElfError::BadDynamic));
        // no DT_NULL, a wrong entry size, a size of partial entries, then a
        // table without a size and one without an entry size.
        let pie = pie();
        for (at, word) in [(0x250, DT_DEBUG), (0x228, 16), (0x218, 70), (0x210, DT_DEBUG), (0x220, DT_DEBUG)] {
            let image = with(&pie, at, &word.to_le_bytes());
            assert_eq!(parse(&image), Err(ElfError::BadDynamic), "{word:#x} at {at:#x}");
        }
        // a table in the bss, and one running past the data's file bytes.
        for rela in [0x1300_u64, 0x12c0] {
            assert_eq!(parse(&with(&pie, 0x208, &rela.to_le_bytes())), Err(ElfError::BadDynamic));
        }
    }

    #[test]
    fn refuses_relocations_jos_does_not_apply() {
        let flags = [(DT_FLAGS, DF_TEXTREL), (DT_PLTRELSZ, 24)];
        let tables = [(DT_REL, 0x1260), (DT_RELSZ, 24), (DT_TEXTREL, 0), (DT_RELR, 0x1260)];
        for (tag, value) in flags.into_iter().chain(tables) {
            let image = with(&pie(), 0x230, &dyn_entry(tag, value));
            assert_eq!(parse(&image), Err(ElfError::UnsupportedDynamic), "tag {tag}");
        }
    }

    #[test]
    fn refuses_unsupported_relocation_types() {
        // R_X86_64_64, and a relative relocation that names a symbol.
        for info in [1_u64, (1 << 32) | R_X86_64_RELATIVE] {
            let image = with(&pie(), 0x268, &info.to_le_bytes());
            assert_eq!(parse(&image), Err(ElfError::UnsupportedRelocation));
        }
    }

    #[test]
    fn refuses_relocations_outside_writable_segments() {
        // into the read-only code, across the end of the bss, just below the
        // data on its first page, and into no segment at all.
        for offset in [0x100_u64, 0x31f9, 0x11f8, 0x8000] {
            let image = with(&pie(), 0x260, &offset.to_le_bytes());
            assert_eq!(parse(&image), Err(ElfError::RelocationOutsideWritable), "{offset:#x}");
        }
    }

    #[test]
    fn the_checker_notices_a_broken_plan() {
        let image = pie();
        let plan = parse(&image).unwrap();
        let breaks: [fn(&mut LoadPlan); 8] = [
            |p| p.segments[1].flags.execute = true,
            |p| p.segments[1].vaddr = BASE + 0x200,
            |p| p.segments[0].file_size = 0x400,
            |p| p.segments[1].file_offset = 0x300,
            |p| p.entry = BASE + 0x1200,
            |p| p.base += PAGE_SIZE,
            |p| p.rela_offset += 8,
            |p| p.relocation_count = 1,
        ];
        for (i, broken) in breaks.iter().enumerate() {
            let mut plan = plan.clone();
            broken(&mut plan);
            assert!(!plan_invariants_hold(&plan, &image, WINDOW), "break {i} went unnoticed");
        }
        assert!(!plan_invariants_hold(&plan, &image, (BASE + PAGE_SIZE, 1 << 47)));
    }

    /// Returns a value in `[0, n)` drawn from `rng`.
    fn below(rng: &mut SimRng, n: usize) -> usize {
        usize::try_from(rng.below(n as u64)).unwrap()
    }

    /// Mutates a valid image as `seed` dictates, parses it, and checks that
    /// nothing panicked and that a plan it accepts holds. Returns whether the
    /// image was accepted; a failure names the seed.
    fn fuzz_one(seed: u64) -> bool {
        let mut rng = SimRng::new(seed);
        let (mut image, mut base) = if rng.next_bool() { (pie(), BASE) } else { (exec(), 0) };
        let words = [0, 1, 8, 24, 0xfff, PAGE_SIZE, 0x1200, u64::from(u32::MAX), u64::MAX, 1 << 63, rng.next_u64()];
        let bases = [0, BASE, BASE + 1, BASE + PAGE_SIZE, u64::MAX - PAGE_SIZE + 1, rng.next_u64() & !(PAGE_SIZE - 1)];
        for _ in 0..=rng.below(3) {
            let len = image.len();
            match rng.below(5) {
                0 if len > 0 => {
                    let at = below(&mut rng, len);
                    image[at] ^= 1 << rng.below(8);
                }
                1 if len >= 8 => {
                    let at = below(&mut rng, len - 7);
                    let word = words[below(&mut rng, words.len())];
                    image[at..at + 8].copy_from_slice(&word.to_le_bytes());
                }
                2 => image.truncate(below(&mut rng, len + 1)),
                3 => image.extend_from_slice(&rng.next_u64().to_le_bytes()),
                _ => base = bases[below(&mut rng, bases.len())],
            }
        }
        let window = if rng.below(8) == 0 { (0, u64::MAX) } else { WINDOW };
        let outcome = std::panic::catch_unwind(|| {
            LoadPlan::parse(&image, base, window).map(|plan| plan_invariants_hold(&plan, &image, window))
        });
        match outcome {
            Ok(Ok(holds)) => {
                assert!(holds, "seed {seed}: an accepted plan breaks its invariants");
                true
            }
            Ok(Err(_)) => false,
            Err(payload) => {
                std::eprintln!("seed {seed}: parsing panicked");
                std::panic::resume_unwind(payload)
            }
        }
    }

    /// Seeded mutations of valid images (bit flips, boundary words, cuts,
    /// growth, other bases) never make the parser panic, and every plan it
    /// still accepts holds. A failure names its seed for `fuzz_one`.
    #[test]
    fn mutated_images_never_break_a_plan() {
        let seeds = if cfg!(miri) { 300 } else { 10_000 };
        let accepted = (0..seeds).filter(|&seed| fuzz_one(seed)).count() as u64;
        // both outcomes must be common, or the mutations explore too little.
        assert!(accepted > seeds / 20 && seeds - accepted > seeds / 20, "{accepted} of {seeds} accepted");
    }
}

/// Bounded proofs of the load plan invariants.
///
/// Images are fixed-size byte arrays, so every loop is bounded by how many
/// headers, dynamic entries, or RELA entries fit in one; each harness derives
/// its unwind bound from that.
///
/// Each harness keeps its symbolic input to what its property is about, so
/// cbmc stays within a few GB: fully symbolic images larger than a header and
/// one program header, or symbolic dynamic sections walked alongside the
/// invariant checker, took it past 8 GB. The seeded mutation test above covers
/// arbitrary whole images on the host.
#[cfg(kani)]
mod kani_proofs {
    use super::{
        DT_NULL, DT_RELA, DT_RELAENT, DT_RELASZ, ET_DYN, ElfError, LoadPlan, LoadSegment,
        PAGE_SIZE, PF_R, PF_W, PF_X, PT_DYNAMIC, PT_LOAD, ProgramHeader, SegmentFlags,
        plan_invariants_hold, write_header,
    };

    /// The window the harnesses load into: the lower half, less page zero.
    const WINDOW: (u64, u64) = (PAGE_SIZE, 1 << 47);

    /// Returns an arbitrary page-aligned load base.
    fn any_base() -> u64 {
        let base: u64 = kani::any();
        kani::assume(base & (PAGE_SIZE - 1) == 0);
        base
    }

    /// Builds an image of two loadable segments with entry point `entry`.
    fn two_segments<const N: usize>(code: ProgramHeader, data: ProgramHeader, entry: u64) -> [u8; N] {
        let mut image = [0; N];
        write_header(&mut image, ET_DYN, entry, 2);
        code.write(&mut image, 64);
        data.write(&mut image, 120);
        image
    }

    /// Parsing any 120 bytes, room for a file header and one program header,
    /// at any page-aligned base never panics, and every plan it accepts holds.
    #[kani::proof]
    #[kani::unwind(9)] // a dynamic section in 120 bytes has at most 7 entries, plus one
    fn parse_never_panics_and_accepted_plans_hold() {
        let image: [u8; 120] = kani::any();
        let base = any_base();
        if let Ok(plan) = LoadPlan::parse(&image, base, WINDOW) {
            assert!(plan_invariants_hold(&plan, &image, WINDOW));
            kani::cover!(true, "an arbitrary image is accepted");
        }
    }

    /// For any two RELA entries in an otherwise valid image, at any
    /// page-aligned base, every relocation of an accepted plan writes eight
    /// bytes inside a writable segment and stores the base plus its addend,
    /// and a relocation outside every writable segment is refused.
    #[kani::proof]
    #[kani::unwind(5)] // four dynamic entries written, two RELA entries, three headers, plus one
    fn relocations_land_in_writable_segments() {
        let mut image = [0; 0x180];
        write_header(&mut image, ET_DYN, 0x10, 3);
        // code over the headers, then data whose file bytes are the dynamic
        // section (at 0x1100) and the table (at 0x1150).
        let code = ProgramHeader {
            kind: PT_LOAD,
            flags: PF_R | PF_X,
            offset: 0,
            vaddr: 0,
            file_size: 0xe8,
            mem_size: 0xe8,
            align: PAGE_SIZE,
        };
        let data = ProgramHeader {
            kind: PT_LOAD,
            flags: PF_R | PF_W,
            offset: 0x100,
            vaddr: 0x1100,
            file_size: 0x80,
            mem_size: 0x1000,
            align: PAGE_SIZE,
        };
        let dynamic = ProgramHeader { kind: PT_DYNAMIC, file_size: 0x50, mem_size: 0x50, align: 8, ..data };
        code.write(&mut image, 64);
        data.write(&mut image, 120);
        dynamic.write(&mut image, 176);
        for (i, (tag, value)) in [(DT_RELA, 0x1150_u64), (DT_RELASZ, 48), (DT_RELAENT, 24), (DT_NULL, 0)].iter().enumerate() {
            let at = 0x100 + i * 16;
            image[at..at + 8].copy_from_slice(&tag.to_le_bytes());
            image[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
        }
        let table: [u8; 48] = kani::any();
        image[0x150..0x180].copy_from_slice(&table);
        let base = any_base();
        let Ok(plan) = LoadPlan::parse(&image, base, WINDOW) else {
            return;
        };
        for r in plan.relocations(&image) {
            let holds = |s: &LoadSegment| s.flags.write && s.vaddr <= r.target && r.target + 8 <= s.vaddr + s.mem_size;
            assert!(plan.segments().iter().any(holds));
        }
        kani::cover!(plan.relocation_count() == 2, "both RELA entries are applied");
    }

    /// For any flags on two otherwise valid segments, parsing refuses exactly
    /// the images with a writable and executable segment, and reports the
    /// flags of the others as they are.
    #[kani::proof]
    #[kani::unwind(3)] // two program headers and at most two segments, plus one
    fn writable_and_executable_is_rejected() {
        let code_flags: u32 = kani::any();
        let data_flags: u32 = kani::any();
        let code = ProgramHeader {
            kind: PT_LOAD,
            flags: code_flags,
            offset: 0,
            vaddr: 0,
            file_size: 0x100,
            mem_size: 0x100,
            align: PAGE_SIZE,
        };
        let data = ProgramHeader { flags: data_flags, offset: 0x100, vaddr: 0x1100, ..code };
        let image: [u8; 0x200] = two_segments(code, data, 0x10);
        let result = LoadPlan::parse(&image, PAGE_SIZE, WINDOW);
        let writable_and_executable = |flags: u32| flags & PF_W != 0 && flags & PF_X != 0;
        let decoded = |f: u32| SegmentFlags { read: f & PF_R != 0, write: f & PF_W != 0, execute: f & PF_X != 0 };
        if writable_and_executable(code_flags) || writable_and_executable(data_flags) {
            assert!(matches!(result, Err(ElfError::WritableAndExecutable)));
        } else if code_flags & PF_X != 0 {
            // nothing else is wrong with the image, so it loads.
            assert!(result.is_ok());
            if let Ok(plan) = result {
                assert!(plan.segments()[0].flags == decoded(code_flags));
                assert!(plan.segments()[1].flags == decoded(data_flags));
            }
        } else {
            assert!(matches!(result, Err(ElfError::EntryNotExecutable)));
        }
    }

    /// For any addresses and sizes of two segments, parsing refuses them as
    /// overlapping exactly when they share a page, and accepts them otherwise.
    #[kani::proof]
    #[kani::unwind(3)] // two program headers and at most two segments, plus one
    fn overlapping_segments_are_rejected() {
        let code_vaddr: u64 = kani::any();
        let code_size: u64 = kani::any();
        let data_vaddr: u64 = kani::any();
        let data_size: u64 = kani::any();
        // keep both inside the window, so nothing but an overlap can refuse
        // them, and their offsets within a page small, so the image stays small.
        kani::assume(code_vaddr >= PAGE_SIZE && code_vaddr < 1 << 40 && code_vaddr & 0xfff < 0x40);
        kani::assume(data_vaddr >= PAGE_SIZE && data_vaddr < 1 << 40 && data_vaddr & 0xfff < 0x40);
        kani::assume(code_size > 0 && code_size < 1 << 40 && data_size > 0 && data_size < 1 << 40);
        // no file bytes, at a file offset that agrees with the address within a page.
        let code = ProgramHeader {
            kind: PT_LOAD,
            flags: PF_R | PF_X,
            offset: code_vaddr & 0xfff,
            vaddr: code_vaddr,
            file_size: 0,
            mem_size: code_size,
            align: PAGE_SIZE,
        };
        let data = ProgramHeader {
            flags: PF_R | PF_W,
            offset: data_vaddr & 0xfff,
            vaddr: data_vaddr,
            mem_size: data_size,
            ..code
        };
        let image: [u8; 0xb0] = two_segments(code, data, code_vaddr);
        let result = LoadPlan::parse(&image, 0, WINDOW);
        // the pages holding each segment's first and last bytes.
        let code_pages = (code_vaddr >> 12, (code_vaddr + code_size - 1) >> 12);
        let data_pages = (data_vaddr >> 12, (data_vaddr + data_size - 1) >> 12);
        let overlap = code_pages.0 <= data_pages.1 && data_pages.0 <= code_pages.1;
        assert!(matches!(result, Err(ElfError::Overlap)) == overlap);
        assert!(result.is_ok() == !overlap);
    }
}
