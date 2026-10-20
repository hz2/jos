//! Bounds-checked multiboot2 boot information parser.
//!
//! A multiboot2 loader such as GRUB leaves [`BOOTLOADER_MAGIC`] in EAX and the
//! physical address of the boot information structure in EBX. The structure is
//! an 8-byte header (`u32 total_size`, `u32 reserved`) followed by tags. Each
//! tag is an 8-byte header (`u32 type`, `u32 size`) and `size - 8` bytes of
//! payload, and starts on an 8-byte boundary, so the next tag begins at `size`
//! rounded up to 8. A type 0 tag of size 8 ends the list.
//!
//! The kernel turns the structure into a byte slice and this module does the
//! rest. It never sees a pointer: every field is a little-endian decode of a
//! bounds-checked subslice. Boot data comes from outside the kernel, so the
//! parser is total: a structure that lies about its sizes ends the walk early
//! instead of making it read out of bounds, panic, or spin.
//!
//! # Invariant
//!
//! The tag walk yields only tags inside the first `total_size` bytes, each one
//! the tag the format places where the previous one ended. It stops at the end
//! tag, at a tag smaller than its own header, or at a tag that runs past
//! `total_size`, and since every tag it yields takes at least 8 bytes, it
//! yields fewer than `total_size / 8`. Memory map entries and module command
//! lines are cut from their own tag's payload. The `kani_proofs` harnesses at
//! the bottom of this file prove all of this (BOOT-1).

use core::slice::ChunksExact;

/// The value a multiboot2 loader leaves in EAX when it enters the kernel.
pub const BOOTLOADER_MAGIC: u32 = 0x36d7_6289;

/// Tag type of the end tag, which closes the tag list.
pub const TAG_END: u32 = 0;
/// Tag type of the kernel command line, a NUL-terminated string.
pub const TAG_COMMAND_LINE: u32 = 1;
/// Tag type of the bootloader name, a NUL-terminated string.
pub const TAG_BOOTLOADER_NAME: u32 = 2;
/// Tag type of a boot module: its physical start and end, then its command line.
pub const TAG_MODULE: u32 = 3;
/// Tag type of the basic memory information, lower and upper memory in KiB.
pub const TAG_BASIC_MEMINFO: u32 = 4;
/// Tag type of the memory map.
pub const TAG_MEMORY_MAP: u32 = 6;
/// Tag type of a copy of the ACPI 1.0 root system description pointer.
pub const TAG_ACPI_OLD: u32 = 14;
/// Tag type of a copy of the ACPI 2.0 or later root system description pointer.
pub const TAG_ACPI_NEW: u32 = 15;

/// Memory map type of RAM that is free to use.
pub const MEMORY_AVAILABLE: u32 = 1;
/// Memory map type of reserved memory. Any type not listed here means the same.
pub const MEMORY_RESERVED: u32 = 2;
/// Memory map type of RAM that holds ACPI tables and is free once they are read.
pub const MEMORY_ACPI_RECLAIMABLE: u32 = 3;
/// Memory map type of memory to preserve across hibernation (ACPI NVS).
pub const MEMORY_NVS: u32 = 4;
/// Memory map type of defective RAM.
pub const MEMORY_BAD: u32 = 5;

/// Size in bytes of the info structure header and of every tag header.
const HEADER_SIZE: usize = 8;
/// Every tag starts at a multiple of this many bytes from the start of the structure.
const TAG_ALIGN: usize = 8;
/// The smallest memory map entry the format allows: base, length, type, and a reserved word.
const MEMORY_ENTRY_MIN: usize = 24;

/// Why a byte slice is not a multiboot2 info structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The slice ends before the header does, or before the size the header declares.
    Truncated,
    /// The header declares a total size smaller than the header itself.
    BadTotalSize,
}

/// Returns the total size the info structure at the start of `header` declares,
/// or `None` if `header` is too short to hold it.
///
/// The kernel reads this from the first 8 bytes to learn how long a slice to
/// build before handing it to [`BootInformation::parse`].
#[must_use]
pub fn total_size(header: &[u8]) -> Option<u32> {
    read_u32(header, 0)
}

/// A multiboot2 info structure whose header has been checked.
///
/// It holds exactly the `total_size` bytes the header declares, so nothing
/// below reads past them. It is a small `Copy` view, so the accessors take it
/// by value and what they return borrows only the underlying bytes.
#[derive(Clone, Copy, Debug)]
pub struct BootInformation<'a> {
    /// The whole structure, header included.
    bytes: &'a [u8],
}

impl<'a> BootInformation<'a> {
    /// Checks the header of the info structure at the start of `bytes` and
    /// keeps the `total_size` bytes it declares. Bytes past those are ignored.
    ///
    /// # Errors
    ///
    /// [`ParseError::Truncated`] if `bytes` is shorter than the header or than
    /// the declared size, or [`ParseError::BadTotalSize`] if the declared size
    /// is smaller than the header.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let size = total_size(bytes).ok_or(ParseError::Truncated)? as usize;
        if size < HEADER_SIZE {
            return Err(ParseError::BadTotalSize);
        }
        let bytes = bytes.get(..size).ok_or(ParseError::Truncated)?;
        Ok(Self { bytes })
    }

    /// Returns the tags in order, up to the end tag or the first malformed tag.
    #[must_use]
    pub fn tags(self) -> Tags<'a> {
        Tags { bytes: self.bytes, offset: HEADER_SIZE }
    }

    /// Returns the kernel command line without its terminating NUL.
    #[must_use]
    pub fn command_line(self) -> Option<&'a [u8]> {
        self.first_payload(TAG_COMMAND_LINE).map(until_nul)
    }

    /// Returns the bootloader name without its terminating NUL.
    #[must_use]
    pub fn bootloader_name(self) -> Option<&'a [u8]> {
        self.first_payload(TAG_BOOTLOADER_NAME).map(until_nul)
    }

    /// Returns the loader's copy of the ACPI root system description pointer,
    /// preferring the 2.0 one, which also locates the XSDT.
    #[must_use]
    pub fn rsdp(self) -> Option<Rsdp<'a>> {
        match self.first_payload(TAG_ACPI_NEW) {
            Some(bytes) => Some(Rsdp::V2(bytes)),
            None => self.first_payload(TAG_ACPI_OLD).map(Rsdp::V1),
        }
    }

    /// Returns every entry of every memory map tag, in order.
    ///
    /// A tag whose entry size is below 24 bytes is malformed and yields nothing,
    /// and a partial entry at the end of a tag is ignored.
    pub fn memory_map(self) -> impl Iterator<Item = MemoryArea> {
        self.tags()
            .filter(|tag| tag.tag_type == TAG_MEMORY_MAP)
            .flat_map(|tag| memory_map_entries(tag.payload))
            .filter_map(|entry| {
                Some(MemoryArea {
                    base: read_u64(entry, 0)?,
                    length: read_u64(entry, 8)?,
                    area_type: read_u32(entry, 16)?,
                })
            })
    }

    /// Returns every boot module, in order. A module tag too short to hold both
    /// addresses is malformed and skipped.
    pub fn modules(self) -> impl Iterator<Item = Module<'a>> {
        self.tags().filter(|tag| tag.tag_type == TAG_MODULE).filter_map(|tag| {
            Some(Module {
                start: read_u32(tag.payload, 0)?,
                end: read_u32(tag.payload, 4)?,
                cmdline: until_nul(tag.payload.get(8..)?),
            })
        })
    }

    /// Returns the payload of the first tag of type `tag_type`.
    fn first_payload(self, tag_type: u32) -> Option<&'a [u8]> {
        self.tags().find(|tag| tag.tag_type == tag_type).map(|tag| tag.payload)
    }
}

/// One tag of the info structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tag<'a> {
    /// The tag type: one of the `TAG_*` constants, or a type this parser does not know.
    pub tag_type: u32,
    /// The bytes after the tag header, up to the size the header declares.
    pub payload: &'a [u8],
}

/// An iterator over the tags of an info structure, from [`BootInformation::tags`].
#[derive(Clone, Debug)]
pub struct Tags<'a> {
    /// The whole info structure, `total_size` bytes.
    bytes: &'a [u8],
    /// Where the next tag header starts.
    offset: usize,
}

impl<'a> Iterator for Tags<'a> {
    type Item = Tag<'a>;

    fn next(&mut self) -> Option<Tag<'a>> {
        let rest = self.bytes.get(self.offset..)?;
        let tag_type = read_u32(rest, 0)?;
        let size = read_u32(rest, 4)? as usize;
        // every stop leaves offset where it is, so later calls stop too.
        if tag_type == TAG_END || size < HEADER_SIZE {
            return None;
        }
        // a tag that runs past total_size is malformed as well.
        let payload = rest.get(HEADER_SIZE..size)?;
        self.offset += size.next_multiple_of(TAG_ALIGN);
        Some(Tag { tag_type, payload })
    }
}

/// One entry of the memory map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryArea {
    /// Physical address of the first byte of the area.
    pub base: u64,
    /// Length of the area in bytes.
    pub length: u64,
    /// What the area holds: [`MEMORY_AVAILABLE`] for free RAM, or another `MEMORY_*` type.
    pub area_type: u32,
}

/// A boot module: a file the loader placed in physical memory, such as the
/// root task image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Module<'a> {
    /// Physical address of the first byte of the module.
    pub start: u32,
    /// Physical address one past the last byte of the module.
    pub end: u32,
    /// The module's command line, without its terminating NUL.
    pub cmdline: &'a [u8],
}

/// The loader's copy of the ACPI root system description pointer, by revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rsdp<'a> {
    /// The ACPI 1.0 pointer from tag 14, which locates the RSDT.
    V1(&'a [u8]),
    /// The ACPI 2.0 or later pointer from tag 15, which also locates the XSDT.
    V2(&'a [u8]),
}

/// Splits a memory map tag's payload into its entries, which follow the 8 bytes
/// of entry size and entry version.
fn memory_map_entries(payload: &[u8]) -> ChunksExact<'_, u8> {
    let entry_size = read_u32(payload, 0).map_or(0, |size| size as usize);
    if entry_size < MEMORY_ENTRY_MIN {
        // too small for base, length, and type: skip the whole tag.
        let none: &[u8] = &[];
        return none.chunks_exact(MEMORY_ENTRY_MIN);
    }
    payload.get(8..).unwrap_or_default().chunks_exact(entry_size)
}

/// Reads the little-endian `u32` at byte `at` of `bytes`, if all four bytes are there.
fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(*bytes.get(at..)?.first_chunk()?))
}

/// Reads the little-endian `u64` at byte `at` of `bytes`, if all eight bytes are there.
fn read_u64(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(*bytes.get(at..)?.first_chunk()?))
}

/// Returns `bytes` up to the first NUL, or all of `bytes` if there is none.
fn until_nul(bytes: &[u8]) -> &[u8] {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    &bytes[..len]
}

/// Host tests for the parser, on hand-built and random info structures.
#[cfg(test)]
mod tests {
    use super::{
        BootInformation, MEMORY_AVAILABLE, MEMORY_RESERVED, MemoryArea, Module, ParseError, Rsdp,
        TAG_ACPI_NEW, TAG_ACPI_OLD, TAG_BOOTLOADER_NAME, TAG_COMMAND_LINE, TAG_END, TAG_MEMORY_MAP,
        TAG_MODULE, total_size,
    };
    use crate::rng::{KernelRng, SimRng};
    extern crate std;
    use std::vec::Vec;

    /// An info structure under construction: the header, then tags padded to 8 bytes.
    struct Info(Vec<u8>);

    impl Info {
        /// Starts a structure with room for the header.
        fn new() -> Self {
            Info(std::vec![0; 8])
        }

        /// Appends a tag holding `payload`, padded to the next 8-byte boundary.
        fn tag(&mut self, tag_type: u32, payload: &[u8]) -> &mut Self {
            let size = u32::try_from(8 + payload.len()).unwrap();
            self.raw(tag_type, size, payload)
        }

        /// Appends a tag header declaring `size`, whatever the payload really is.
        fn raw(&mut self, tag_type: u32, size: u32, payload: &[u8]) -> &mut Self {
            self.0.extend_from_slice(&tag_type.to_le_bytes());
            self.0.extend_from_slice(&size.to_le_bytes());
            self.0.extend_from_slice(payload);
            while !self.0.len().is_multiple_of(8) {
                self.0.push(0);
            }
            self
        }

        /// Appends the end tag, fills in the total size, and returns the bytes.
        fn finish(&mut self) -> Vec<u8> {
            self.tag(TAG_END, &[]);
            let total = u32::try_from(self.0.len()).unwrap();
            self.0[..4].copy_from_slice(&total.to_le_bytes());
            core::mem::take(&mut self.0)
        }
    }

    /// Builds a memory map payload of `entry_size`-byte entries.
    fn memory_map(entry_size: u32, entries: &[(u64, u64, u32)]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&entry_size.to_le_bytes());
        payload.extend_from_slice(&0_u32.to_le_bytes());
        for &(base, length, area_type) in entries {
            let start = payload.len();
            payload.extend_from_slice(&base.to_le_bytes());
            payload.extend_from_slice(&length.to_le_bytes());
            payload.extend_from_slice(&area_type.to_le_bytes());
            payload.resize(start + entry_size as usize, 0);
        }
        payload
    }

    /// Builds a module payload: the two addresses, then `cmdline` as given.
    fn module(start: u32, end: u32, cmdline: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&start.to_le_bytes());
        payload.extend_from_slice(&end.to_le_bytes());
        payload.extend_from_slice(cmdline);
        payload
    }

    /// Returns the area of one memory map entry.
    fn area(base: u64, length: u64, area_type: u32) -> MemoryArea {
        MemoryArea { base, length, area_type }
    }

    /// A structure laid out the way GRUB lays one out for QEMU reads back field
    /// by field.
    #[test]
    fn reads_a_grub_like_structure() {
        let e820 = [
            (0, 0x9_fc00, MEMORY_AVAILABLE),
            (0x9_fc00, 0x400, MEMORY_RESERVED),
            (0xf_0000, 0x1_0000, MEMORY_RESERVED),
            (0x10_0000, 0x7ee_0000, MEMORY_AVAILABLE),
            (0x7fe_0000, 0x2_0000, MEMORY_RESERVED),
        ];
        let rsdp_v1 = [0x11_u8; 20];
        let rsdp_v2 = [0x22_u8; 36];
        let bytes = Info::new()
            .tag(TAG_COMMAND_LINE, b"console=ttyS0\0")
            .tag(TAG_BOOTLOADER_NAME, b"GRUB 2.12\0")
            .tag(TAG_MODULE, &module(0x2a_5000, 0x2c_7a10, b"root\0"))
            .tag(TAG_MODULE, &module(0x2c_8000, 0x2c_8100, b"\0"))
            .tag(TAG_MEMORY_MAP, &memory_map(24, &e820))
            .tag(TAG_ACPI_OLD, &rsdp_v1)
            .tag(TAG_ACPI_NEW, &rsdp_v2)
            .finish();

        assert_eq!(total_size(&bytes), Some(u32::try_from(bytes.len()).unwrap()));
        let info = BootInformation::parse(&bytes).unwrap();
        assert_eq!(info.tags().count(), 7);
        assert_eq!(info.command_line(), Some(&b"console=ttyS0"[..]));
        assert_eq!(info.bootloader_name(), Some(&b"GRUB 2.12"[..]));
        let modules: Vec<Module<'_>> = info.modules().collect();
        assert_eq!(
            modules,
            [
                Module { start: 0x2a_5000, end: 0x2c_7a10, cmdline: b"root" },
                Module { start: 0x2c_8000, end: 0x2c_8100, cmdline: b"" },
            ]
        );
        let areas: Vec<MemoryArea> = info.memory_map().collect();
        let want: Vec<MemoryArea> = e820.iter().map(|&(b, l, t)| area(b, l, t)).collect();
        assert_eq!(areas, want);
        assert_eq!(info.rsdp(), Some(Rsdp::V2(&rsdp_v2)));
    }

    /// A header that is cut short or declares an impossible size is refused.
    #[test]
    fn rejects_a_bad_header() {
        assert_eq!(BootInformation::parse(&[]).unwrap_err(), ParseError::Truncated);
        assert_eq!(BootInformation::parse(&[16, 0, 0]).unwrap_err(), ParseError::Truncated);
        assert_eq!(total_size(&[16, 0, 0]), None);
        let mut bytes = [0_u8; 16];
        for size in [0_u32, 7] {
            bytes[..4].copy_from_slice(&size.to_le_bytes());
            assert_eq!(BootInformation::parse(&bytes).unwrap_err(), ParseError::BadTotalSize);
        }
        bytes[..4].copy_from_slice(&17_u32.to_le_bytes());
        assert_eq!(BootInformation::parse(&bytes).unwrap_err(), ParseError::Truncated);
        // a header alone is a valid, empty structure.
        bytes[..4].copy_from_slice(&8_u32.to_le_bytes());
        assert_eq!(BootInformation::parse(&bytes).unwrap().tags().count(), 0);
    }

    /// Bytes past the declared total size are never walked, even if they look
    /// like a tag.
    #[test]
    fn stops_at_the_declared_size() {
        let mut bytes = Info::new().tag(TAG_COMMAND_LINE, b"a\0").finish();
        // drop the end tag from the declared size, then put a tag where it was.
        let total = u32::try_from(bytes.len() - 8).unwrap();
        bytes[..4].copy_from_slice(&total.to_le_bytes());
        let at = bytes.len() - 8;
        bytes[at..at + 4].copy_from_slice(&TAG_BOOTLOADER_NAME.to_le_bytes());
        bytes[at + 4..].copy_from_slice(&8_u32.to_le_bytes());
        let info = BootInformation::parse(&bytes).unwrap();
        assert_eq!(info.tags().count(), 1);
        assert_eq!(info.bootloader_name(), None);
    }

    /// A tag smaller than its own header ends the walk instead of spinning on
    /// it, and nothing after it is read: the regression the kernel walker's
    /// step clamp guarded against.
    #[test]
    fn undersized_tag_ends_the_walk() {
        for size in [0, 3, 7] {
            let bytes = Info::new()
                .tag(TAG_COMMAND_LINE, b"a\0")
                .raw(9, size, &[0; 8])
                .tag(TAG_BOOTLOADER_NAME, b"b\0")
                .finish();
            let info = BootInformation::parse(&bytes).unwrap();
            assert_eq!(info.tags().count(), 1, "size {size}");
            assert_eq!(info.bootloader_name(), None, "size {size}");
        }
    }

    /// A tag that claims to run past the total size ends the walk; the tags
    /// before it are still read.
    #[test]
    fn oversized_tag_ends_the_walk() {
        let bytes = Info::new()
            .tag(TAG_COMMAND_LINE, b"a\0")
            .raw(TAG_MODULE, 0x1000, &module(0, 0x1000, b"m\0"))
            .finish();
        let info = BootInformation::parse(&bytes).unwrap();
        assert_eq!(info.tags().count(), 1);
        assert_eq!(info.modules().count(), 0);
        assert_eq!(info.command_line(), Some(&b"a"[..]));
    }

    /// Without an end tag the walk still ends, once no further header fits.
    #[test]
    fn missing_end_tag_still_terminates() {
        let mut bytes = Info::new().tag(TAG_COMMAND_LINE, b"abc\0").finish();
        bytes.truncate(bytes.len() - 8);
        let total = u32::try_from(bytes.len()).unwrap();
        bytes[..4].copy_from_slice(&total.to_le_bytes());
        let info = BootInformation::parse(&bytes).unwrap();
        assert_eq!(info.tags().count(), 1);
    }

    /// Once the walk has ended, it stays ended.
    #[test]
    fn the_walk_stays_ended() {
        let bytes = Info::new().raw(9, 3, &[]).finish();
        let mut tags = BootInformation::parse(&bytes).unwrap().tags();
        assert_eq!(tags.next(), None);
        assert_eq!(tags.next(), None);
    }

    /// Entries are read at the stride the tag declares, a partial entry at the
    /// end is ignored, a tag with too small an entry size yields nothing, and
    /// the entries of several memory map tags come out in order.
    #[test]
    fn memory_map_honours_the_entry_size() {
        let mut wide = memory_map(32, &[(0x1000, 0x2000, MEMORY_AVAILABLE), (0x8000, 0x1000, 3)]);
        wide.extend_from_slice(&[0xff; 20]);
        let mut narrow = memory_map(16, &[]);
        narrow.extend_from_slice(&[0xff; 32]);
        let bytes = Info::new()
            .tag(TAG_MEMORY_MAP, &wide)
            .tag(TAG_MEMORY_MAP, &narrow)
            .tag(TAG_MEMORY_MAP, &memory_map(24, &[(0x10_0000, 0x10_0000, MEMORY_AVAILABLE)]))
            .tag(TAG_MEMORY_MAP, &[1, 2])
            .finish();
        let areas: Vec<MemoryArea> = BootInformation::parse(&bytes).unwrap().memory_map().collect();
        assert_eq!(
            areas,
            [
                area(0x1000, 0x2000, MEMORY_AVAILABLE),
                area(0x8000, 0x1000, 3),
                area(0x10_0000, 0x10_0000, MEMORY_AVAILABLE),
            ]
        );
    }

    /// A module command line with no NUL runs to the end of the tag, and a
    /// module tag too short for both addresses is skipped.
    #[test]
    fn module_edge_cases() {
        let bytes = Info::new()
            .tag(TAG_MODULE, &module(0x1000, 0x2000, b"no-nul"))
            .tag(TAG_MODULE, &[1, 2, 3, 4, 5])
            .tag(TAG_MODULE, &module(0x3000, 0x4000, b"a\0b"))
            .finish();
        let modules: Vec<Module<'_>> = BootInformation::parse(&bytes).unwrap().modules().collect();
        // the first tag is padded with zeros, but the padding lies outside its size.
        assert_eq!(
            modules,
            [
                Module { start: 0x1000, end: 0x2000, cmdline: b"no-nul" },
                Module { start: 0x3000, end: 0x4000, cmdline: b"a" },
            ]
        );
    }

    /// The newer RSDP copy wins when both are present; the old one is used
    /// when it is alone.
    #[test]
    fn rsdp_prefers_the_newer_copy() {
        let old = Info::new().tag(TAG_ACPI_OLD, &[1; 20]).finish();
        let info = BootInformation::parse(&old).unwrap();
        assert_eq!(info.rsdp(), Some(Rsdp::V1(&[1; 20])));
        let both = Info::new().tag(TAG_ACPI_OLD, &[1; 20]).tag(TAG_ACPI_NEW, &[2; 36]).finish();
        assert_eq!(BootInformation::parse(&both).unwrap().rsdp(), Some(Rsdp::V2(&[2; 36])));
        let none = Info::new().finish();
        assert_eq!(BootInformation::parse(&none).unwrap().rsdp(), None);
    }

    /// Random structures, malformed ones included, never make the walk leave
    /// the declared bytes, misplace a tag, or run longer than the size allows.
    #[test]
    fn random_structures_stay_inside_their_bytes() {
        let cases = if cfg!(miri) { 16 } else { 4000 };
        for seed in 0..cases {
            let mut rng = SimRng::new(seed);
            let mut builder = Info::new();
            for _ in 0..rng.below(8) {
                let tag_type = u32::try_from(rng.below(8)).unwrap();
                let payload: Vec<u8> = (0..rng.below(48)).map(|_| u8::try_from(rng.below(4)).unwrap()).collect();
                // mostly honest sizes, sometimes too small or too large.
                let size = match rng.below(8) {
                    0 => u32::try_from(rng.below(8)).unwrap(),
                    1 => u32::try_from(rng.below(512)).unwrap(),
                    _ => u32::try_from(8 + payload.len()).unwrap(),
                };
                builder.raw(tag_type, size, &payload);
            }
            let mut bytes = builder.finish();
            if rng.below(4) == 0 {
                let total = u32::try_from(rng.below(bytes.len() as u64 + 16)).unwrap();
                bytes[..4].copy_from_slice(&total.to_le_bytes());
            }
            let Ok(info) = BootInformation::parse(&bytes) else { continue };
            let total = total_size(&bytes).unwrap() as usize;
            let base = bytes.as_ptr().addr();
            let mut count = 0;
            for tag in info.tags() {
                let at = tag.payload.as_ptr().addr() - base;
                assert!(at.is_multiple_of(8) && at >= 16, "seed {seed}: payload at {at}");
                assert!(at + tag.payload.len() <= total, "seed {seed}: tag runs past {total}");
                count += 1;
            }
            assert!(count < total / 8, "seed {seed}: {count} tags in {total} bytes");
            assert!(info.memory_map().count() <= total / 24, "seed {seed}: too many entries");
            for module in info.modules() {
                assert!(!module.cmdline.contains(&0), "seed {seed}: module {module:?}");
            }
            let _ = (info.command_line(), info.bootloader_name(), info.rsdp());
        }
    }
}

/// Bounded proofs that the parser stays inside the structure (BOOT-1).
///
/// The input is a fully symbolic byte array, so the solver considers every
/// structure of that length, every declared total size, and every tag layout.
/// The harnesses decode the expected fields with their own little-endian reads
/// rather than the parser's, and locate a returned slice by its address
/// relative to the array.
#[cfg(kani)]
mod kani_proofs {
    use super::{BootInformation, MemoryArea, TAG_END, TAG_MEMORY_MAP, TAG_MODULE};

    /// Decodes the little-endian `u32` at byte `at` of `buf`.
    fn le32(buf: &[u8], at: usize) -> u32 {
        u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
    }

    /// Decodes the little-endian `u64` at byte `at` of `buf`.
    fn le64(buf: &[u8], at: usize) -> u64 {
        u64::from(le32(buf, at)) | (u64::from(le32(buf, at + 4)) << 32)
    }

    /// Returns where `part`, a subslice of `whole`, starts within it.
    fn offset_in(whole: &[u8], part: &[u8]) -> usize {
        part.as_ptr().addr() - whole.as_ptr().addr()
    }

    /// Every tag the walk yields is the tag the format places where the last one
    /// ended, starts 8-aligned, and lies inside the first total_size bytes. The
    /// walk stops only at an end tag, a tag smaller than its header, or a tag
    /// past total_size, yields fewer than total_size / 8 tags, and stays stopped.
    #[kani::proof]
    #[kani::unwind(8)] // at most 64 / 8 - 1 = 7 tags fit, plus one exit check
    fn tag_walk_stays_inside_the_structure() {
        let buf: [u8; 64] = kani::any();
        let Ok(info) = BootInformation::parse(&buf) else { return };
        let total = le32(&buf, 0) as usize;
        let mut tags = info.tags();
        // where the format puts the next tag header.
        let mut at = 8;
        let mut count = 0;
        while let Some(tag) = tags.next() {
            let payload_at = offset_in(&buf, tag.payload);
            assert!(payload_at == at + 8 && payload_at % 8 == 0);
            let size = le32(&buf, at + 4) as usize;
            assert!(tag.tag_type == le32(&buf, at) && tag.tag_type != TAG_END);
            assert!(tag.payload.len() + 8 == size && at + size <= total);
            at += size.next_multiple_of(8);
            count += 1;
        }
        assert!(count < total / 8);
        if at + 8 <= total {
            let size = le32(&buf, at + 4) as usize;
            assert!(le32(&buf, at) == TAG_END || size < 8 || at + size > total);
        }
        assert!(tags.next().is_none());
    }

    /// The memory map yields exactly the entries the format places in each
    /// memory map tag, in order, each decoded from bytes inside its own tag:
    /// entry k of a tag sits at payload offset 8 + k * entry_size and ends
    /// inside the tag, and a tag whose entry size is below 24 yields nothing.
    #[kani::proof]
    #[kani::unwind(9)] // at most 72 / 8 - 1 = 8 tags fit, plus one exit check
    fn memory_map_entries_lie_inside_their_tag() {
        // 72 bytes is the smallest structure with two entries in one tag.
        let buf: [u8; 72] = kani::any();
        let Ok(info) = BootInformation::parse(&buf) else { return };
        let mut areas = info.memory_map();
        for tag in info.tags() {
            if tag.tag_type != TAG_MEMORY_MAP || tag.payload.len() < 4 {
                continue;
            }
            let start = offset_in(&buf, tag.payload);
            let end = start + tag.payload.len();
            let entry_size = le32(&buf, start) as usize;
            if entry_size < 24 {
                continue;
            }
            let mut at = start + 8;
            while at + entry_size <= end {
                let want = MemoryArea {
                    base: le64(&buf, at),
                    length: le64(&buf, at + 8),
                    area_type: le32(&buf, at + 16),
                };
                assert!(areas.next() == Some(want));
                at += entry_size;
            }
        }
        assert!(areas.next().is_none());
    }

    /// Every module is decoded from its own tag: the addresses from the first
    /// 8 payload bytes, and the command line from the bytes after them, up to
    /// the first NUL or the end of the tag. A tag too short for both addresses
    /// yields nothing.
    #[kani::proof]
    #[kani::unwind(25)] // a 48-byte structure leaves at most 24 command line bytes to scan
    fn module_cmdlines_lie_inside_their_tag() {
        let buf: [u8; 48] = kani::any();
        let Ok(info) = BootInformation::parse(&buf) else { return };
        let mut modules = info.modules();
        for tag in info.tags() {
            if tag.tag_type != TAG_MODULE || tag.payload.len() < 8 {
                continue;
            }
            let start = offset_in(&buf, tag.payload);
            let end = start + tag.payload.len();
            let Some(module) = modules.next() else { panic!("a module tag was skipped") };
            assert!(module.start == le32(&buf, start) && module.end == le32(&buf, start + 4));
            let cmd_at = offset_in(&buf, module.cmdline);
            let cmd_end = cmd_at + module.cmdline.len();
            assert!(cmd_at == start + 8 && cmd_end <= end);
            assert!(cmd_end == end || buf[cmd_end] == 0);
            let i: usize = kani::any();
            if i < module.cmdline.len() {
                assert!(module.cmdline[i] != 0);
            }
        }
        assert!(modules.next().is_none());
    }
}
