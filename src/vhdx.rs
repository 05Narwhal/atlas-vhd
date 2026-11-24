// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Microsoft Hyper-V virtual disk (`.vhdx`): fixed, dynamic and differencing.
//!
//! # Layout
//!
//! Source: "[MS-VHDX]: Virtual Hard Disk v2 (VHDX) File Format", Microsoft,
//! public. All integers are little-endian; GUIDs are stored in the mixed
//! order Microsoft uses (the first three fields little-endian).
//!
//! - The file starts with the file type identifier `vhdxfile`.
//! - Two 4 KiB headers sit at 64 KiB and 128 KiB: signature `head`, a
//!   CRC-32C (Castagnoli) of the 4 KiB with the checksum field zeroed, a
//!   sequence number, the log GUID, the version (1). The valid header with
//!   the higher sequence number is current.
//! - Two 64 KiB region tables sit at 192 KiB and 256 KiB: signature `regi`,
//!   a CRC-32C over all 64 KiB, and entries (GUID, file offset, length,
//!   required flag) locating the BAT and the metadata region.
//! - The metadata region begins with a table (`metadata`, entry count,
//!   entries of GUID, offset, length, flags). Items read: file parameters
//!   (block size, has-parent flag), virtual disk size, logical sector size
//!   and the parent locator.
//! - The BAT holds one `u64` per entry: bits 0 to 2 the state, bits 20 to 63
//!   the file offset in MiB. Payload block entries and sector bitmap entries
//!   are interleaved: a chunk of `chunk ratio = 2^23 * sector size / block
//!   size` payload entries is followed by one bitmap entry. Payload states
//!   0 (not present), 1 (undefined), 2 (zero) and 3 (unmapped) hold no data;
//!   6 (fully present) reads from the file; 7 (partially present) is
//!   differencing only and consults the chunk's sector bitmap, a 1 MiB block
//!   with one bit per logical sector, bit 0 of byte 0 first: a set bit reads
//!   from this file, a clear bit from the parent.
//!
//! # The log is never replayed
//!
//! A header whose log GUID is non-zero names a log that may hold metadata
//! updates that were not yet applied to their final place. This reader is
//! read-only and never replays the log: the disk is read as the file stands,
//! which for a cleanly closed disk is the same thing. [`VhdxSource::has_log`]
//! reports whether the active header names a log, so a caller can warn.
//!
//! # Choices where the specification is silent
//!
//! - Both headers invalid is `Corrupt`; one valid is enough. A header
//!   version other than 1 or a log version other than 0 is `Unsupported`.
//! - A region table is taken from the first copy that passes its CRC-32C.
//!   A required region or metadata item this reader does not know is
//!   `Unsupported`; an optional unknown one is ignored.
//! - Block size must be a power of two from 1 MiB to 256 MiB; the logical
//!   sector size 512 or 4096; the disk at most 64 TiB. Else `Corrupt`.
//! - A BAT over 64 MiB is `Unsupported`; a BAT that does not fit in its
//!   region or in the file is `Corrupt`.
//! - A BAT entry in state 6 or 7 whose offset is zero or at or past the end
//!   of the file is `Corrupt`; a block cut short by the end of the file reads
//!   its missing part as zeros. An unknown payload state is `Corrupt`, and
//!   so is state 7 in a disk without a parent.
//! - Where the specification says a not-present block of a differencing disk
//!   is in the parent, it is read from the parent; the same state in other
//!   disks reads as zeros. A partially present block whose chunk has no
//!   present bitmap is `Corrupt`.
//! - A parent shorter than the child reads zeros past its end. Parent
//!   linkage GUIDs and the locator type GUID are not compared.
//! - [`open`] tries the parent locator keys `relative_path`, `volume_path`
//!   and `absolute_win32_path` in that order, relative paths from the
//!   child's folder. A chain of more than 8 disks is `Unsupported`, which
//!   also stops a loop. A parent that is not found is `Unsupported` and
//!   names the child file.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use atlas_fs_core::error::{CorruptKind, Corruption, Error, Location, Result};
use atlas_fs_core::io::block::{BlockSource, check_range};
use atlas_fs_core::io::file::FileSource;

const KIB: u64 = 1 << 10;
const MIB: u64 = 1 << 20;

/// File type identifier at the start of the file.
const FILE_ID: [u8; 8] = *b"vhdxfile";
/// Offsets of the two headers.
const HEADER_AT: [u64; 2] = [64 * KIB, 128 * KIB];
/// Size of a header.
const HEADER_LEN: usize = 4096;
/// Offsets of the two region tables.
const REGION_AT: [u64; 2] = [192 * KIB, 256 * KIB];
/// Size of a region table and of the metadata table.
const TABLE_LEN: usize = 64 * 1024;
/// Most entries in a region table or the metadata table.
const MAX_TABLE_ENTRIES: u64 = 2047;
/// Largest disk read.
const MAX_DISK: u64 = 64 << 40;
/// Block size limits.
const MIN_BLOCK: u64 = MIB;
const MAX_BLOCK: u64 = 256 * MIB;
/// Most BAT bytes held in memory.
const MAX_BAT_BYTES: u64 = 64 * MIB;
/// Longest parent locator read, in bytes.
const MAX_LOCATOR_BYTES: u32 = 64 * 1024;
/// Most parent disks followed by [`open`].
const MAX_PARENT_DEPTH: usize = 8;
/// Sectors covered by one sector bitmap block: 2^23.
const CHUNK_SECTORS: u64 = 1 << 23;

const HEADER: &str = "VHDX header";
const REGIONS: &str = "VHDX region table";
const METADATA: &str = "VHDX metadata";
const BAT: &str = "VHDX block allocation table";

/// A GUID as stored: the first three fields little-endian.
const fn guid(a: u32, b: u16, c: u16, d: [u8; 8]) -> [u8; 16] {
    let a = a.to_le_bytes();
    let b = b.to_le_bytes();
    let c = c.to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5], d[6],
        d[7],
    ]
}

const REGION_BAT: [u8; 16] = guid(
    0x2DC2_7766,
    0xF623,
    0x4200,
    [0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08],
);
const REGION_METADATA: [u8; 16] = guid(
    0x8B7C_A206,
    0x4790,
    0x4B9A,
    [0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E],
);
const ITEM_FILE_PARAMETERS: [u8; 16] = guid(
    0xCAA1_6737,
    0xFA36,
    0x4D43,
    [0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B],
);
const ITEM_DISK_SIZE: [u8; 16] = guid(
    0x2FA5_4224,
    0xCD1B,
    0x4876,
    [0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8],
);
const ITEM_DISK_ID: [u8; 16] = guid(
    0xBECA_12AB,
    0xB2E6,
    0x4523,
    [0x93, 0xEF, 0xC3, 0x09, 0xE0, 0x00, 0xC7, 0x46],
);
const ITEM_LOGICAL_SECTOR: [u8; 16] = guid(
    0x8141_BF1D,
    0xA96F,
    0x4709,
    [0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F],
);
const ITEM_PHYSICAL_SECTOR: [u8; 16] = guid(
    0xCDA3_48C7,
    0x445D,
    0x4471,
    [0x9C, 0xC9, 0xE9, 0x88, 0x52, 0x51, 0xC5, 0x56],
);
const ITEM_PARENT_LOCATOR: [u8; 16] = guid(
    0xA8D3_5F2D,
    0xB30B,
    0x454D,
    [0xAB, 0xF7, 0xD3, 0xD8, 0x48, 0x34, 0xAB, 0x0C],
);

/// Payload block states.
const STATE_NOT_PRESENT: u64 = 0;
const STATE_UNDEFINED: u64 = 1;
const STATE_ZERO: u64 = 2;
const STATE_UNMAPPED: u64 = 3;
const STATE_FULLY_PRESENT: u64 = 6;
const STATE_PARTIALLY_PRESENT: u64 = 7;
/// Sector bitmap state "present".
const BITMAP_PRESENT: u64 = 6;

fn corrupt(what: &'static str, offset: u64, kind: CorruptKind) -> Error {
    Error::Corrupt(Corruption::new(what, Location::Byte(offset), kind))
}

fn invalid(what: &'static str, offset: u64, field: &'static str, value: u64) -> Error {
    corrupt(what, offset, CorruptKind::InvalidValue { field, value })
}

fn field<const N: usize>(buf: &[u8], offset: usize) -> Option<[u8; N]> {
    offset
        .checked_add(N)
        .and_then(|end| buf.get(offset..end))
        .and_then(|b| <[u8; N]>::try_from(b).ok())
}

fn truncated(what: &'static str, offset: usize, needed: u64) -> Error {
    corrupt(
        what,
        offset as u64,
        CorruptKind::Truncated {
            needed,
            available: 0,
        },
    )
}

fn le16(buf: &[u8], offset: usize, what: &'static str) -> Result<u16> {
    field(buf, offset)
        .map(u16::from_le_bytes)
        .ok_or_else(|| truncated(what, offset, 2))
}

fn le32(buf: &[u8], offset: usize, what: &'static str) -> Result<u32> {
    field(buf, offset)
        .map(u32::from_le_bytes)
        .ok_or_else(|| truncated(what, offset, 4))
}

fn le64(buf: &[u8], offset: usize, what: &'static str) -> Result<u64> {
    field(buf, offset)
        .map(u64::from_le_bytes)
        .ok_or_else(|| truncated(what, offset, 8))
}

/// Continues a CRC-32C (reflected polynomial 0x82F63B78) over `bytes`. Bit
/// by bit: the checksums covered are at most 64 KiB, read once at open.
fn crc_update(mut crc: u32, bytes: &[u8]) -> u32 {
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// CRC-32C of `buf` with the four bytes at `zeroed` read as zeros.
fn crc32c_zeroed(buf: &[u8], zeroed: usize) -> u32 {
    let end = zeroed.saturating_add(4);
    let mut crc = !0u32;
    crc = crc_update(crc, buf.get(..zeroed).unwrap_or(buf));
    crc = crc_update(crc, &[0; 4]);
    crc = crc_update(crc, buf.get(end..).unwrap_or(&[]));
    !crc
}

/// Reads `len` bytes at `offset`; a range outside the file is `Corrupt`.
fn read_checked(
    file: &dyn BlockSource,
    what: &'static str,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>> {
    let file_len = file.len();
    let want = u64::try_from(len).unwrap_or(u64::MAX);
    match offset.checked_add(want) {
        Some(end) if end <= file_len => {}
        _ => {
            return Err(corrupt(
                what,
                offset,
                CorruptKind::Truncated {
                    needed: want,
                    available: file_len.saturating_sub(offset),
                },
            ));
        }
    }
    let mut buf = vec![0u8; len];
    file.read_at(offset, &mut buf)?;
    Ok(buf)
}

/// Reads `buf` from `file` at `start`; whatever lies past the end of the
/// file reads as zeros.
fn read_clamped(file: &dyn BlockSource, start: u64, buf: &mut [u8], bulk: bool) -> Result<()> {
    let file_len = file.len();
    let avail =
        usize::try_from(file_len.saturating_sub(start)).map_or(buf.len(), |a| a.min(buf.len()));
    let want = u64::try_from(buf.len()).unwrap_or(u64::MAX);
    let (data, zeros) = buf.split_at_mut_checked(avail).ok_or(Error::OutOfBounds {
        offset: start,
        len: want,
        size: file_len,
    })?;
    if !data.is_empty() {
        if bulk {
            file.read_bulk(start, data)?;
        } else {
            file.read_at(start, data)?;
        }
    }
    zeros.fill(0);
    Ok(())
}

/// What the active header says.
struct HeaderInfo {
    sequence: u64,
    log_guid_set: bool,
}

fn parse_header(buf: &[u8]) -> Result<HeaderInfo> {
    let sig: [u8; 4] = field(buf, 0).ok_or_else(|| truncated(HEADER, 0, 4))?;
    if &sig != b"head" {
        return Err(corrupt(
            HEADER,
            0,
            CorruptKind::BadSignature {
                expected: u64::from(u32::from_le_bytes(*b"head")),
                found: u64::from(u32::from_le_bytes(sig)),
            },
        ));
    }
    let stored = le32(buf, 4, HEADER)?;
    if stored != crc32c_zeroed(buf, 4) {
        return Err(invalid(HEADER, 4, "checksum", u64::from(stored)));
    }
    let version = le16(buf, 66, HEADER)?;
    if version != 1 {
        return Err(Error::unsupported(format!("VHDX version {version}")));
    }
    let log_version = le16(buf, 64, HEADER)?;
    let log_guid: [u8; 16] = field(buf, 48).ok_or_else(|| truncated(HEADER, 48, 16))?;
    let log_guid_set = log_guid.iter().any(|b| *b != 0);
    if log_guid_set && log_version != 0 {
        return Err(Error::unsupported(format!(
            "VHDX log version {log_version}"
        )));
    }
    Ok(HeaderInfo {
        sequence: le64(buf, 8, HEADER)?,
        log_guid_set,
    })
}

/// The current header: the valid one with the higher sequence number.
fn read_header(file: &dyn BlockSource) -> Result<HeaderInfo> {
    let mut best: Option<HeaderInfo> = None;
    let mut first_error: Option<Error> = None;
    for at in HEADER_AT {
        let parsed = read_checked(file, HEADER, at, HEADER_LEN).and_then(|buf| parse_header(&buf));
        match parsed {
            Ok(info) => {
                if best.as_ref().is_none_or(|b| info.sequence > b.sequence) {
                    best = Some(info);
                }
            }
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    best.ok_or_else(|| {
        first_error.unwrap_or_else(|| corrupt(HEADER, 0, CorruptKind::Other("no VHDX header")))
    })
}

/// A file range the region table names.
#[derive(Clone, Copy)]
struct Region {
    offset: u64,
    length: u64,
}

struct Regions {
    bat: Region,
    metadata: Region,
}

fn parse_regions(buf: &[u8], file_len: u64) -> Result<Regions> {
    let sig: [u8; 4] = field(buf, 0).ok_or_else(|| truncated(REGIONS, 0, 4))?;
    if &sig != b"regi" {
        return Err(corrupt(
            REGIONS,
            0,
            CorruptKind::BadSignature {
                expected: u64::from(u32::from_le_bytes(*b"regi")),
                found: u64::from(u32::from_le_bytes(sig)),
            },
        ));
    }
    let stored = le32(buf, 4, REGIONS)?;
    if stored != crc32c_zeroed(buf, 4) {
        return Err(invalid(REGIONS, 4, "checksum", u64::from(stored)));
    }
    let count = u64::from(le32(buf, 8, REGIONS)?);
    if count > MAX_TABLE_ENTRIES {
        return Err(corrupt(
            REGIONS,
            8,
            CorruptKind::OutOfRange {
                field: "entry count",
                value: count,
                limit_name: "table capacity",
                limit: MAX_TABLE_ENTRIES,
            },
        ));
    }
    let mut bat = None;
    let mut metadata = None;
    // At most 2047 passes.
    for i in 0..usize::try_from(count).unwrap_or(0) {
        let at = i.saturating_mul(32).saturating_add(16);
        let id: [u8; 16] = field(buf, at).ok_or_else(|| truncated(REGIONS, at, 16))?;
        let offset = le64(buf, at.saturating_add(16), REGIONS)?;
        let length = u64::from(le32(buf, at.saturating_add(24), REGIONS)?);
        let required = le32(buf, at.saturating_add(28), REGIONS)? & 1 != 0;
        let slot = if id == REGION_BAT {
            &mut bat
        } else if id == REGION_METADATA {
            &mut metadata
        } else if required {
            return Err(Error::unsupported(
                "VHDX with a required region this reader does not know",
            ));
        } else {
            continue;
        };
        if offset < MIB || offset.checked_add(length).is_none_or(|end| end > file_len) {
            return Err(corrupt(
                REGIONS,
                at as u64,
                CorruptKind::OutOfRange {
                    field: "region offset",
                    value: offset,
                    limit_name: "file size",
                    limit: file_len,
                },
            ));
        }
        if slot.is_none() {
            *slot = Some(Region { offset, length });
        }
    }
    match (bat, metadata) {
        (Some(bat), Some(metadata)) => Ok(Regions { bat, metadata }),
        _ => Err(corrupt(
            REGIONS,
            0,
            CorruptKind::Other("region table lacks the BAT or the metadata region"),
        )),
    }
}

fn read_regions(file: &dyn BlockSource) -> Result<Regions> {
    let mut first_error: Option<Error> = None;
    for at in REGION_AT {
        let parsed = read_checked(file, REGIONS, at, TABLE_LEN)
            .and_then(|buf| parse_regions(&buf, file.len()));
        match parsed {
            Ok(regions) => return Ok(regions),
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    Err(first_error
        .unwrap_or_else(|| corrupt(REGIONS, 0, CorruptKind::Other("no VHDX region table"))))
}

/// A metadata item: its range inside the metadata region.
#[derive(Clone, Copy)]
struct Item {
    offset: u64,
    length: u32,
}

#[derive(Default)]
struct Items {
    file_parameters: Option<Item>,
    disk_size: Option<Item>,
    logical_sector: Option<Item>,
    parent_locator: Option<Item>,
}

fn parse_metadata_table(table: &[u8], region: Region) -> Result<Items> {
    let sig: [u8; 8] = field(table, 0).ok_or_else(|| truncated(METADATA, 0, 8))?;
    if &sig != b"metadata" {
        return Err(corrupt(
            METADATA,
            region.offset,
            CorruptKind::BadSignature {
                expected: u64::from_le_bytes(*b"metadata"),
                found: u64::from_le_bytes(sig),
            },
        ));
    }
    let count = u64::from(le16(table, 10, METADATA)?);
    if count > MAX_TABLE_ENTRIES {
        return Err(corrupt(
            METADATA,
            region.offset,
            CorruptKind::OutOfRange {
                field: "entry count",
                value: count,
                limit_name: "table capacity",
                limit: MAX_TABLE_ENTRIES,
            },
        ));
    }
    let mut items = Items::default();
    // At most 2047 passes.
    for i in 0..usize::try_from(count).unwrap_or(0) {
        let at = i.saturating_mul(32).saturating_add(32);
        let id: [u8; 16] = field(table, at).ok_or_else(|| truncated(METADATA, at, 16))?;
        let offset = u64::from(le32(table, at.saturating_add(16), METADATA)?);
        let length = le32(table, at.saturating_add(20), METADATA)?;
        let required = le32(table, at.saturating_add(24), METADATA)? & 4 != 0;
        let slot = if id == ITEM_FILE_PARAMETERS {
            &mut items.file_parameters
        } else if id == ITEM_DISK_SIZE {
            &mut items.disk_size
        } else if id == ITEM_LOGICAL_SECTOR {
            &mut items.logical_sector
        } else if id == ITEM_PARENT_LOCATOR {
            &mut items.parent_locator
        } else if id == ITEM_DISK_ID || id == ITEM_PHYSICAL_SECTOR {
            continue;
        } else if required {
            return Err(Error::unsupported(
                "VHDX with a required metadata item this reader does not know",
            ));
        } else {
            continue;
        };
        let end = offset.checked_add(u64::from(length));
        if offset < TABLE_LEN as u64 || end.is_none_or(|end| end > region.length) {
            return Err(corrupt(
                METADATA,
                region.offset.saturating_add(at as u64),
                CorruptKind::OutOfRange {
                    field: "item offset",
                    value: offset,
                    limit_name: "metadata region size",
                    limit: region.length,
                },
            ));
        }
        if slot.is_none() {
            *slot = Some(Item { offset, length });
        }
    }
    Ok(items)
}

fn read_item(
    file: &dyn BlockSource,
    region: Region,
    item: Option<Item>,
    what: &'static str,
    min_len: u32,
) -> Result<Vec<u8>> {
    let item = item.ok_or_else(|| {
        corrupt(
            what,
            region.offset,
            CorruptKind::Other("metadata item missing"),
        )
    })?;
    if item.length < min_len {
        return Err(corrupt(
            what,
            region.offset.saturating_add(item.offset),
            CorruptKind::Truncated {
                needed: u64::from(min_len),
                available: u64::from(item.length),
            },
        ));
    }
    let at = region.offset.checked_add(item.offset).ok_or_else(|| {
        corrupt(
            what,
            region.offset,
            CorruptKind::Overflow {
                field: "item offset",
            },
        )
    })?;
    let len = usize::try_from(item.length).map_err(|_| {
        corrupt(
            what,
            at,
            CorruptKind::Overflow {
                field: "item length",
            },
        )
    })?;
    read_checked(file, what, at, len)
}

fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|a| u16::from_le_bytes(*a))
        .take_while(|unit| *unit != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// The key and value strings of a parent locator.
fn parse_locator(buf: &[u8]) -> Result<Vec<(String, String)>> {
    let count = usize::from(le16(buf, 18, METADATA)?);
    let mut out = Vec::new();
    // At most 65535 passes, and each entry must fit in the item.
    for i in 0..count {
        let at = i.saturating_mul(12).saturating_add(20);
        let key_offset = usize::try_from(le32(buf, at, METADATA)?).unwrap_or(usize::MAX);
        let value_offset =
            usize::try_from(le32(buf, at.saturating_add(4), METADATA)?).unwrap_or(usize::MAX);
        let key_len = usize::from(le16(buf, at.saturating_add(8), METADATA)?);
        let value_len = usize::from(le16(buf, at.saturating_add(10), METADATA)?);
        let slice = |offset: usize, len: usize| {
            offset
                .checked_add(len)
                .and_then(|end| buf.get(offset..end))
                .ok_or_else(|| {
                    corrupt(
                        METADATA,
                        at as u64,
                        CorruptKind::OutOfRange {
                            field: "locator string",
                            value: offset as u64,
                            limit_name: "locator size",
                            limit: buf.len() as u64,
                        },
                    )
                })
        };
        let key = utf16le(slice(key_offset, key_len)?);
        let value = utf16le(slice(value_offset, value_len)?);
        out.push((key, value));
    }
    Ok(out)
}

/// Everything read from the file's structures.
struct Parsed {
    len: u64,
    block_size: u64,
    sector_size: u32,
    chunk_ratio: u64,
    has_parent: bool,
    log_guid_set: bool,
    /// The BAT as stored: little-endian `u64` entries.
    bat: Vec<u8>,
    locator: Vec<(String, String)>,
}

impl Parsed {
    fn parse(file: &dyn BlockSource) -> Result<Self> {
        let file_len = file.len();
        let mut id = [0u8; 8];
        if file_len < 8 {
            return Err(truncated(HEADER, 0, 8));
        }
        file.read_at(0, &mut id)?;
        if id != FILE_ID {
            return Err(corrupt(
                HEADER,
                0,
                CorruptKind::BadSignature {
                    expected: u64::from_le_bytes(FILE_ID),
                    found: u64::from_le_bytes(id),
                },
            ));
        }
        let header = read_header(file)?;
        let regions = read_regions(file)?;
        let region = regions.metadata;
        let table_len = u64::try_from(TABLE_LEN).unwrap_or(u64::MAX);
        if region.length < table_len {
            return Err(corrupt(
                METADATA,
                region.offset,
                CorruptKind::Truncated {
                    needed: table_len,
                    available: region.length,
                },
            ));
        }
        let table = read_checked(file, METADATA, region.offset, TABLE_LEN)?;
        let items = parse_metadata_table(&table, region)?;

        let params = read_item(file, region, items.file_parameters, METADATA, 8)?;
        let block_size = u64::from(le32(&params, 0, METADATA)?);
        let flags = le32(&params, 4, METADATA)?;
        let has_parent = flags & 2 != 0;
        let size_item = read_item(file, region, items.disk_size, METADATA, 8)?;
        let len = le64(&size_item, 0, METADATA)?;
        let sector_item = read_item(file, region, items.logical_sector, METADATA, 4)?;
        let sector_size = le32(&sector_item, 0, METADATA)?;

        if !(MIN_BLOCK..=MAX_BLOCK).contains(&block_size) || !block_size.is_power_of_two() {
            return Err(invalid(METADATA, region.offset, "block size", block_size));
        }
        if sector_size != 512 && sector_size != 4096 {
            return Err(invalid(
                METADATA,
                region.offset,
                "logical sector size",
                u64::from(sector_size),
            ));
        }
        if len == 0 || len > MAX_DISK {
            return Err(invalid(METADATA, region.offset, "virtual disk size", len));
        }
        let overflow = || {
            corrupt(
                BAT,
                regions.bat.offset,
                CorruptKind::Overflow { field: "BAT size" },
            )
        };
        // 2^23 * 4096 / 1 MiB at most, so no overflow; block size is nonzero.
        let chunk_ratio = CHUNK_SECTORS
            .checked_mul(u64::from(sector_size))
            .and_then(|v| v.checked_div(block_size))
            .filter(|r| *r > 0)
            .ok_or_else(overflow)?;
        let payload_blocks = len.div_ceil(block_size);
        let entries = if has_parent {
            payload_blocks
                .div_ceil(chunk_ratio)
                .checked_mul(chunk_ratio.checked_add(1).ok_or_else(overflow)?)
                .ok_or_else(overflow)?
        } else {
            payload_blocks
                .saturating_sub(1)
                .checked_div(chunk_ratio)
                .and_then(|extra| payload_blocks.checked_add(extra))
                .ok_or_else(overflow)?
        };
        let bat_bytes = entries.checked_mul(8).ok_or_else(overflow)?;
        if bat_bytes > MAX_BAT_BYTES {
            return Err(Error::unsupported(format!(
                "VHDX block table of {bat_bytes} bytes (over {MAX_BAT_BYTES})"
            )));
        }
        if bat_bytes > regions.bat.length {
            return Err(corrupt(
                BAT,
                regions.bat.offset,
                CorruptKind::OutOfRange {
                    field: "BAT size",
                    value: bat_bytes,
                    limit_name: "BAT region size",
                    limit: regions.bat.length,
                },
            ));
        }
        let bat_len = usize::try_from(bat_bytes).map_err(|_| overflow())?;
        let bat = read_checked(file, BAT, regions.bat.offset, bat_len)?;

        // Check every entry that can be read from, before any read.
        let stride = chunk_ratio.saturating_add(1);
        for (i, raw) in bat.as_chunks::<8>().0.iter().enumerate() {
            let entry = u64::from_le_bytes(*raw);
            let state = entry & 7;
            let at = regions
                .bat
                .offset
                .saturating_add((i as u64).saturating_mul(8));
            let is_bitmap = (i as u64).checked_rem(stride) == Some(chunk_ratio);
            let has_data = if is_bitmap {
                if state != 0 && state != BITMAP_PRESENT {
                    return Err(invalid(BAT, at, "bitmap state", state));
                }
                state == BITMAP_PRESENT
            } else {
                match state {
                    STATE_NOT_PRESENT | STATE_UNDEFINED | STATE_ZERO | STATE_UNMAPPED => false,
                    STATE_FULLY_PRESENT => true,
                    STATE_PARTIALLY_PRESENT if has_parent => true,
                    _ => return Err(invalid(BAT, at, "payload state", state)),
                }
            };
            if has_data {
                // 44 bits shifted by 20 fit in a u64.
                let offset = (entry >> 20) << 20;
                if offset == 0 || offset >= file_len {
                    return Err(corrupt(
                        BAT,
                        at,
                        CorruptKind::OutOfRange {
                            field: "block offset",
                            value: offset,
                            limit_name: "file size",
                            limit: file_len,
                        },
                    ));
                }
            }
        }

        let locator = if has_parent {
            let item = items.parent_locator.ok_or_else(|| {
                corrupt(
                    METADATA,
                    region.offset,
                    CorruptKind::Other("differencing disk without a parent locator"),
                )
            })?;
            if item.length > MAX_LOCATOR_BYTES {
                return Err(corrupt(
                    METADATA,
                    region.offset.saturating_add(item.offset),
                    CorruptKind::LimitExceeded {
                        what: "parent locator bytes",
                        limit: u64::from(MAX_LOCATOR_BYTES),
                    },
                ));
            }
            let bytes = read_item(file, region, Some(item), METADATA, 20)?;
            parse_locator(&bytes)?
        } else {
            Vec::new()
        };

        Ok(Self {
            len,
            block_size,
            sector_size,
            chunk_ratio,
            has_parent,
            log_guid_set: header.log_guid_set,
            bat,
            locator,
        })
    }
}

/// Opens the VHDX at `path` read-only. A differencing disk's parent is
/// found through its parent locator (see the module docs).
pub fn open(path: &Path) -> Result<Arc<dyn BlockSource>> {
    open_depth(path, 0)
}

fn open_depth(path: &Path, depth: usize) -> Result<Arc<dyn BlockSource>> {
    if depth > MAX_PARENT_DEPTH {
        return Err(Error::unsupported(format!(
            "VHDX parent chain longer than {MAX_PARENT_DEPTH} disks at {}",
            path.display()
        )));
    }
    let file: Arc<dyn BlockSource> = Arc::new(FileSource::open(path)?);
    let parsed = Parsed::parse(&*file)?;
    let parent = if parsed.has_parent {
        Some(open_parent(path, &parsed.locator, depth)?)
    } else {
        None
    };
    Ok(Arc::new(VhdxSource::from_parsed(file, parsed, parent)?))
}

fn open_parent(
    child: &Path,
    locator: &[(String, String)],
    depth: usize,
) -> Result<Arc<dyn BlockSource>> {
    let folder = child.parent().unwrap_or_else(|| Path::new("."));
    let mut tried = Vec::new();
    for key in ["relative_path", "volume_path", "absolute_win32_path"] {
        for (_, value) in locator.iter().filter(|(k, _)| k == key) {
            if value.is_empty() {
                continue;
            }
            tried.push(value.clone());
            let value = if cfg!(windows) {
                value.clone()
            } else {
                value.replace('\\', "/")
            };
            let candidate = Path::new(&value);
            let resolved: PathBuf = if candidate.is_absolute() {
                candidate.to_path_buf()
            } else {
                folder.join(candidate)
            };
            if resolved.is_file() {
                return open_depth(&resolved, depth.saturating_add(1));
            }
        }
    }
    Err(Error::unsupported(format!(
        "VHDX parent disk not found for {} (looked for: {})",
        child.display(),
        if tried.is_empty() {
            "no parent path".to_string()
        } else {
            tried.join(", ")
        }
    )))
}

/// The disk a VHDX presents.
pub struct VhdxSource {
    file: Arc<dyn BlockSource>,
    /// The parent of a differencing disk.
    parent: Option<Arc<dyn BlockSource>>,
    len: u64,
    block_size: u64,
    sector_size: u32,
    chunk_ratio: u64,
    log_guid_set: bool,
    /// The BAT as stored: little-endian `u64` entries.
    bat: Vec<u8>,
}

impl VhdxSource {
    /// Parses the VHDX stored in `file`.
    ///
    /// A differencing disk needs `parent`, the disk it was taken from; any
    /// other kind ignores it. Fails with [`Error::Corrupt`] on damage and
    /// [`Error::Unsupported`] for what the module docs list.
    pub fn new(file: Arc<dyn BlockSource>, parent: Option<Arc<dyn BlockSource>>) -> Result<Self> {
        let parsed = Parsed::parse(&*file)?;
        Self::from_parsed(file, parsed, parent)
    }

    fn from_parsed(
        file: Arc<dyn BlockSource>,
        parsed: Parsed,
        parent: Option<Arc<dyn BlockSource>>,
    ) -> Result<Self> {
        let parent = if parsed.has_parent {
            Some(parent.ok_or_else(|| {
                Error::unsupported("a differencing VHDX needs its parent disk to be read")
            })?)
        } else {
            None
        };
        Ok(Self {
            file,
            parent,
            len: parsed.len,
            block_size: parsed.block_size,
            sector_size: parsed.sector_size,
            chunk_ratio: parsed.chunk_ratio,
            log_guid_set: parsed.log_guid_set,
            bat: parsed.bat,
        })
    }

    /// True when the active header names a log. The log is never replayed
    /// (module docs), so metadata updates still in it are not applied.
    pub fn has_log(&self) -> bool {
        self.log_guid_set
    }

    fn entry(&self, index: u64) -> Option<u64> {
        let at = usize::try_from(index).ok()?.checked_mul(8)?;
        field(&self.bat, at).map(u64::from_le_bytes)
    }

    /// Fills `buf` from the parent at disk offset `pos`, or with zeros.
    fn read_parent(&self, pos: u64, buf: &mut [u8], bulk: bool) -> Result<()> {
        let Some(parent) = &self.parent else {
            buf.fill(0);
            return Ok(());
        };
        read_clamped(&**parent, pos, buf, bulk)
    }

    /// Reads `chunk`, which lies in the partially present block `block` at
    /// `within` bytes in, at disk offset `pos`. `data` is the file offset of
    /// the block, `bitmap` that of its chunk's sector bitmap.
    fn read_partial(
        &self,
        (block, within): (u64, u64),
        (data, bitmap): (u64, u64),
        pos: u64,
        chunk: &mut [u8],
        bulk: bool,
    ) -> Result<()> {
        let chunk_len = chunk.len();
        let oob = || Error::OutOfBounds {
            offset: pos,
            len: u64::try_from(chunk_len).unwrap_or(u64::MAX),
            size: self.len,
        };
        let n = u64::try_from(chunk_len).map_err(|_| oob())?;
        let ss = u64::from(self.sector_size);
        // Offset of the block's start inside its chunk.
        let base = block
            .checked_rem(self.chunk_ratio)
            .and_then(|b| b.checked_mul(self.block_size))
            .ok_or_else(oob)?;
        let start = base.checked_add(within).ok_or_else(oob)?;
        let first_sector = start.checked_div(ss).ok_or_else(oob)?;
        let last_sector = start
            .checked_add(n)
            .ok_or_else(oob)?
            .saturating_sub(1)
            .checked_div(ss)
            .ok_or_else(oob)?;
        let first_byte = first_sector / 8;
        let bitmap_len = usize::try_from(
            (last_sector / 8)
                .saturating_sub(first_byte)
                .saturating_add(1),
        )
        .map_err(|_| oob())?;
        let mut bits = vec![0u8; bitmap_len];
        read_clamped(
            &*self.file,
            bitmap.checked_add(first_byte).ok_or_else(oob)?,
            &mut bits,
            false,
        )?;
        let set = |sector: u64| -> Result<bool> {
            let index =
                usize::try_from((sector / 8).saturating_sub(first_byte)).map_err(|_| oob())?;
            let byte = bits.get(index).copied().ok_or_else(oob)?;
            Ok(byte & (1 << (sector % 8)) != 0)
        };
        // Each pass takes at least one byte, so at most `chunk.len()` passes.
        let mut cur = 0u64;
        while cur < n {
            let state = set(start.saturating_add(cur).checked_div(ss).ok_or_else(oob)?)?;
            let mut end = cur;
            while end < n {
                let sector = start.saturating_add(end).checked_div(ss).ok_or_else(oob)?;
                if set(sector)? != state {
                    break;
                }
                end = sector
                    .saturating_add(1)
                    .saturating_mul(ss)
                    .saturating_sub(start)
                    .min(n);
            }
            let a = usize::try_from(cur).map_err(|_| oob())?;
            let b = usize::try_from(end).map_err(|_| oob())?;
            let part = chunk.get_mut(a..b).ok_or_else(oob)?;
            if state {
                let at = data
                    .checked_add(within)
                    .and_then(|v| v.checked_add(cur))
                    .ok_or_else(oob)?;
                read_clamped(&*self.file, at, part, bulk)?;
            } else {
                self.read_parent(pos.checked_add(cur).ok_or_else(oob)?, part, bulk)?;
            }
            cur = end;
        }
        Ok(())
    }

    fn read_with(&self, offset: u64, buf: &mut [u8], bulk: bool) -> Result<()> {
        check_range(offset, buf.len(), self.len)?;
        let size = self.file.len();
        let oob = |offset: u64, len: usize| Error::OutOfBounds {
            offset,
            len: u64::try_from(len).unwrap_or(u64::MAX),
            size,
        };
        let mut pos = offset;
        let mut rest = buf;
        // Each pass takes at least one byte: `within < block_size`.
        while !rest.is_empty() {
            let left = rest.len();
            let block = pos
                .checked_div(self.block_size)
                .ok_or_else(|| oob(pos, left))?;
            let within = pos
                .checked_rem(self.block_size)
                .ok_or_else(|| oob(pos, left))?;
            let in_block = self
                .block_size
                .checked_sub(within)
                .ok_or_else(|| oob(pos, left))?;
            let n = usize::try_from(in_block).map_or(left, |in_block| in_block.min(left));
            let (chunk, tail) = rest.split_at_mut_checked(n).ok_or_else(|| oob(pos, left))?;
            // Payload block `block` is BAT entry block + block / chunk ratio.
            let chunk_index = block
                .checked_div(self.chunk_ratio)
                .ok_or_else(|| oob(pos, left))?;
            let index = block
                .checked_add(chunk_index)
                .ok_or_else(|| oob(pos, left))?;
            let entry = self.entry(index).ok_or_else(|| {
                corrupt(
                    BAT,
                    index.saturating_mul(8),
                    CorruptKind::OutOfRange {
                        field: "block index",
                        value: index,
                        limit_name: "table entries",
                        limit: (self.bat.len() / 8) as u64,
                    },
                )
            })?;
            let data = (entry >> 20) << 20;
            match entry & 7 {
                STATE_FULLY_PRESENT => {
                    let at = data.checked_add(within).ok_or_else(|| oob(pos, left))?;
                    read_clamped(&*self.file, at, chunk, bulk)?;
                }
                STATE_PARTIALLY_PRESENT => {
                    // The chunk's bitmap entry follows its payload entries.
                    let bitmap_index = chunk_index
                        .checked_mul(self.chunk_ratio.saturating_add(1))
                        .and_then(|v| v.checked_add(self.chunk_ratio))
                        .ok_or_else(|| oob(pos, left))?;
                    let bitmap_entry = self.entry(bitmap_index).unwrap_or(0);
                    if bitmap_entry & 7 != BITMAP_PRESENT {
                        return Err(corrupt(
                            BAT,
                            bitmap_index.saturating_mul(8),
                            CorruptKind::Other("partially present block without a sector bitmap"),
                        ));
                    }
                    let bitmap = (bitmap_entry >> 20) << 20;
                    self.read_partial((block, within), (data, bitmap), pos, chunk, bulk)?;
                }
                // Not present: the parent holds it (zeros without one).
                STATE_NOT_PRESENT => self.read_parent(pos, chunk, bulk)?,
                _ => chunk.fill(0),
            }
            pos = pos
                .checked_add(u64::try_from(n).unwrap_or(u64::MAX))
                .ok_or_else(|| oob(pos, n))?;
            rest = tail;
        }
        Ok(())
    }
}

impl BlockSource for VhdxSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.read_with(offset, buf, false)
    }

    fn read_bulk(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.read_with(offset, buf, true)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use atlas_fs_core::io::block::MemSource;

    const BS: u64 = MIB;
    const META_AT: u64 = MIB;
    const BAT_AT: u64 = 2 * MIB;
    const DATA_AT: u64 = 3 * MIB;

    fn put(buf: &mut [u8], at: u64, bytes: &[u8]) {
        let at = at as usize;
        buf[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn pattern(seed: u8, offset: usize) -> u8 {
        (usize::from(seed) * 31 + offset * 7 + 1) as u8
    }

    fn parent_byte(pos: usize) -> u8 {
        (pos * 13 + 5) as u8
    }

    fn seal(buf: &mut [u8]) {
        let crc = crc32c_zeroed(buf, 4);
        buf[4..8].copy_from_slice(&crc.to_le_bytes());
    }

    fn header(seq: u64, log: bool) -> Vec<u8> {
        let mut h = vec![0u8; HEADER_LEN];
        h[..4].copy_from_slice(b"head");
        h[8..16].copy_from_slice(&seq.to_le_bytes());
        if log {
            h[48..64].copy_from_slice(&[7; 16]);
        }
        h[66..68].copy_from_slice(&1u16.to_le_bytes());
        seal(&mut h);
        h
    }

    fn region_table(entries: &[([u8; 16], u64, u32)]) -> Vec<u8> {
        let mut t = vec![0u8; TABLE_LEN];
        t[..4].copy_from_slice(b"regi");
        t[8..12].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        for (i, (id, offset, length)) in entries.iter().enumerate() {
            let at = 16 + i * 32;
            t[at..at + 16].copy_from_slice(id);
            t[at + 16..at + 24].copy_from_slice(&offset.to_le_bytes());
            t[at + 24..at + 28].copy_from_slice(&length.to_le_bytes());
            t[at + 28..at + 32].copy_from_slice(&1u32.to_le_bytes());
        }
        seal(&mut t);
        t
    }

    /// A parent locator item with `pairs` of key and value.
    fn locator(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut out = vec![0u8; 20 + pairs.len() * 12];
        out[18..20].copy_from_slice(&(pairs.len() as u16).to_le_bytes());
        for (i, (k, v)) in pairs.iter().enumerate() {
            let ke: Vec<u8> = k.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let ve: Vec<u8> = v.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let at = 20 + i * 12;
            let ko = out.len();
            out.extend(&ke);
            let vo = out.len();
            out.extend(&ve);
            out[at..at + 4].copy_from_slice(&(ko as u32).to_le_bytes());
            out[at + 4..at + 8].copy_from_slice(&(vo as u32).to_le_bytes());
            out[at + 8..at + 10].copy_from_slice(&(ke.len() as u16).to_le_bytes());
            out[at + 10..at + 12].copy_from_slice(&(ve.len() as u16).to_le_bytes());
        }
        out
    }

    struct Spec {
        size: u64,
        sector: u32,
        parent: Option<Vec<(&'static str, String)>>,
        /// BAT entries by index.
        bat: Vec<(usize, u64)>,
        /// Payload bytes: file offset and content.
        blobs: Vec<(u64, Vec<u8>)>,
        file_len: u64,
    }

    impl Spec {
        fn new(size: u64) -> Self {
            Self {
                size,
                sector: 512,
                parent: None,
                bat: Vec::new(),
                blobs: Vec::new(),
                file_len: DATA_AT + 2 * MIB,
            }
        }
    }

    fn entry(state: u64, offset: u64) -> u64 {
        state | ((offset / MIB) << 20)
    }

    fn build(spec: &Spec) -> Vec<u8> {
        let mut f = vec![0u8; spec.file_len as usize];
        put(&mut f, 0, &FILE_ID);
        put(&mut f, HEADER_AT[0], &header(1, false));
        put(&mut f, HEADER_AT[1], &header(2, false));
        let regions = [
            (REGION_BAT, BAT_AT, MIB as u32),
            (REGION_METADATA, META_AT, MIB as u32),
        ];
        for at in REGION_AT {
            put(&mut f, at, &region_table(&regions));
        }
        // Metadata items: (id, bytes).
        let mut params = Vec::new();
        params.extend((BS as u32).to_le_bytes());
        params.extend(
            u32::from(spec.parent.is_some())
                .wrapping_mul(2)
                .to_le_bytes(),
        );
        let mut items: Vec<([u8; 16], Vec<u8>)> = vec![
            (ITEM_FILE_PARAMETERS, params),
            (ITEM_DISK_SIZE, spec.size.to_le_bytes().to_vec()),
            (ITEM_LOGICAL_SECTOR, spec.sector.to_le_bytes().to_vec()),
        ];
        if let Some(pairs) = &spec.parent {
            let pairs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
            items.push((ITEM_PARENT_LOCATOR, locator(&pairs)));
        }
        let mut table = vec![0u8; 32];
        table[..8].copy_from_slice(b"metadata");
        table[10..12].copy_from_slice(&(items.len() as u16).to_le_bytes());
        let mut body_at = TABLE_LEN;
        let mut body = Vec::new();
        for (id, bytes) in &items {
            let mut e = vec![0u8; 32];
            e[..16].copy_from_slice(id);
            e[16..20].copy_from_slice(&(body_at as u32).to_le_bytes());
            e[20..24].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
            e[24..28].copy_from_slice(&4u32.to_le_bytes());
            table.extend(e);
            body.extend(bytes);
            body_at += bytes.len();
        }
        table.resize(TABLE_LEN, 0);
        put(&mut f, META_AT, &table);
        put(&mut f, META_AT + TABLE_LEN as u64, &body);
        for (index, value) in &spec.bat {
            put(&mut f, BAT_AT + *index as u64 * 8, &value.to_le_bytes());
        }
        for (at, bytes) in &spec.blobs {
            let room = (spec.file_len - at) as usize;
            let n = bytes.len().min(room);
            put(&mut f, *at, &bytes[..n]);
        }
        f
    }

    fn block_data(seed: u8) -> Vec<u8> {
        (0..BS as usize).map(|o| pattern(seed, o)).collect()
    }

    fn read_all(src: &VhdxSource) -> Vec<u8> {
        let mut buf = vec![0u8; src.len() as usize];
        src.read_at(0, &mut buf).unwrap();
        buf
    }

    fn open_bytes(bytes: Vec<u8>, parent: Option<Vec<u8>>) -> Result<VhdxSource> {
        let parent: Option<Arc<dyn BlockSource>> =
            parent.map(|p| Arc::new(MemSource::new(p)) as Arc<dyn BlockSource>);
        VhdxSource::new(Arc::new(MemSource::new(bytes)), parent)
    }

    #[test]
    fn crc32c_known_vector() {
        assert_eq!(!crc_update(!0, b"123456789"), 0xE306_9283);
    }

    #[test]
    fn dynamic_disk_with_zero_and_present_blocks() {
        let size = 3 * BS + 100;
        let mut spec = Spec::new(size);
        spec.bat = vec![
            (0, entry(STATE_ZERO, 0)),
            (1, entry(STATE_FULLY_PRESENT, DATA_AT)),
            (2, entry(STATE_NOT_PRESENT, 0)),
            (3, entry(STATE_FULLY_PRESENT, DATA_AT + BS)),
        ];
        spec.blobs = vec![(DATA_AT, block_data(1)), (DATA_AT + BS, block_data(2))];
        spec.file_len = DATA_AT + BS + 40; // the last block is cut short
        let src = open_bytes(build(&spec), None).unwrap();
        assert_eq!(src.len(), size);
        assert_eq!(src.sector_size(), 512);
        assert!(!src.has_log());
        let all = read_all(&src);
        assert!(all[..BS as usize].iter().all(|b| *b == 0));
        assert_eq!(all[BS as usize..2 * BS as usize], block_data(1)[..]);
        assert!(
            all[2 * BS as usize..3 * BS as usize]
                .iter()
                .all(|b| *b == 0)
        );
        // The last block holds 40 bytes in the file and 100 in the disk.
        assert_eq!(
            all[3 * BS as usize..3 * BS as usize + 40],
            block_data(2)[..40]
        );
        assert!(all[3 * BS as usize + 40..].iter().all(|b| *b == 0));
        // Across a block boundary, bulk and plain.
        let mut buf = vec![0u8; 600];
        src.read_bulk(BS - 300, &mut buf).unwrap();
        assert!(buf[..300].iter().all(|b| *b == 0));
        assert_eq!(buf[300..], block_data(1)[..300]);
        assert!(src.read_at(size, &mut [0u8; 1]).is_err());
    }

    #[test]
    fn differencing_disk_reads_bitmap_and_parent() {
        let size = 2 * BS;
        let mut spec = Spec::new(size);
        spec.parent = Some(vec![("relative_path", ".\\parent.vhdx".to_string())]);
        // Chunk ratio 4096 at 1 MiB blocks and 512-byte sectors: the bitmap
        // entry is index 4096.
        let bitmap_at = DATA_AT + BS;
        let mut bitmap = vec![0u8; 16];
        bitmap[0] = 0b0000_0101; // sectors 0 and 2
        bitmap[1] = 0b1000_0000; // sector 15
        spec.bat = vec![
            (0, entry(STATE_PARTIALLY_PRESENT, DATA_AT)),
            (1, entry(STATE_NOT_PRESENT, 0)),
            (4096, entry(BITMAP_PRESENT, bitmap_at)),
        ];
        spec.blobs = vec![(DATA_AT, block_data(3)), (bitmap_at, bitmap)];
        let parent: Vec<u8> = (0..size as usize).map(parent_byte).collect();
        // Without the parent the disk cannot be read.
        let err = open_bytes(build(&spec), None).err().unwrap();
        assert!(matches!(err, Error::Unsupported(_)), "{err}");
        let src = open_bytes(build(&spec), Some(parent.clone())).unwrap();
        let all = read_all(&src);
        for sector in 0..8usize {
            let range = sector * 512..(sector + 1) * 512;
            let from_file = matches!(sector, 0 | 2);
            if from_file {
                assert_eq!(all[range.clone()], block_data(3)[range], "sector {sector}");
            } else {
                assert_eq!(all[range.clone()], parent[range], "sector {sector}");
            }
        }
        assert_eq!(all[15 * 512..16 * 512], block_data(3)[15 * 512..16 * 512]);
        assert_eq!(all[14 * 512..15 * 512], parent[14 * 512..15 * 512]);
        assert_eq!(all[BS as usize..], parent[BS as usize..]);
        // A read that starts inside sector 1 and ends inside sector 3.
        let mut buf = vec![0u8; 1000];
        src.read_at(700, &mut buf).unwrap();
        assert_eq!(buf[..324], parent[700..1024]);
        assert_eq!(buf[324..836], block_data(3)[1024..1536]);
        assert_eq!(buf[836..], parent[1536..1700]);
    }

    #[test]
    fn sector_size_4096_is_reported() {
        let mut spec = Spec::new(BS);
        spec.sector = 4096;
        spec.bat = vec![(0, entry(STATE_FULLY_PRESENT, DATA_AT))];
        spec.blobs = vec![(DATA_AT, block_data(4))];
        let src = open_bytes(build(&spec), None).unwrap();
        assert_eq!(src.sector_size(), 4096);
        assert_eq!(read_all(&src), block_data(4));
    }

    #[test]
    fn newer_valid_header_wins_and_one_bad_header_is_enough() {
        let mut spec = Spec::new(BS);
        spec.bat = vec![(0, entry(STATE_FULLY_PRESENT, DATA_AT))];
        let mut bytes = build(&spec);
        // Header 2 (sequence 2) names a log; header 1 does not.
        put(&mut bytes, HEADER_AT[1], &header(2, true));
        assert!(open_bytes(bytes.clone(), None).unwrap().has_log());
        // Break header 2: header 1 takes over.
        bytes[HEADER_AT[1] as usize + 100] ^= 0xFF;
        assert!(!open_bytes(bytes.clone(), None).unwrap().has_log());
        // Both broken.
        bytes[HEADER_AT[0] as usize + 100] ^= 0xFF;
        assert!(open_bytes(bytes, None).is_err());
    }

    #[test]
    fn hostile_files_are_errors() {
        let mut spec = Spec::new(2 * BS);
        spec.bat = vec![
            (0, entry(STATE_FULLY_PRESENT, DATA_AT)),
            (1, entry(STATE_FULLY_PRESENT, DATA_AT + BS)),
        ];
        let good = build(&spec);
        assert!(open_bytes(good.clone(), None).is_ok());

        // Bad file type identifier.
        let mut bad = good.clone();
        bad[0] = b'x';
        assert!(open_bytes(bad, None).is_err());
        // Both region tables fail their CRC.
        let mut bad = good.clone();
        for at in REGION_AT {
            bad[at as usize + 40] ^= 1;
        }
        assert!(open_bytes(bad, None).is_err());
        // A BAT entry past the end of the file.
        let mut bad = good.clone();
        let past = entry(STATE_FULLY_PRESENT, 100 * MIB);
        bad[BAT_AT as usize..BAT_AT as usize + 8].copy_from_slice(&past.to_le_bytes());
        assert!(open_bytes(bad, None).is_err());
        // A present entry with offset zero, and an unknown state.
        let mut bad = good.clone();
        bad[BAT_AT as usize..BAT_AT as usize + 8]
            .copy_from_slice(&STATE_FULLY_PRESENT.to_le_bytes());
        assert!(open_bytes(bad, None).is_err());
        let mut bad = good.clone();
        bad[BAT_AT as usize..BAT_AT as usize + 8].copy_from_slice(&5u64.to_le_bytes());
        assert!(open_bytes(bad, None).is_err());
        // A partially present block in a disk without a parent.
        let mut bad = good.clone();
        let partial = entry(STATE_PARTIALLY_PRESENT, DATA_AT);
        bad[BAT_AT as usize..BAT_AT as usize + 8].copy_from_slice(&partial.to_le_bytes());
        assert!(open_bytes(bad, None).is_err());
        // Truncated at every length that cuts a structure: never a panic.
        for len in [
            0usize,
            7,
            8,
            65_536,
            70_000,
            200_000,
            1 << 20,
            (2 << 20) + 5,
        ] {
            let _ = open_bytes(good[..len.min(good.len())].to_vec(), None);
        }
        // A huge claimed disk size: the BAT would not fit.
        let mut huge = Spec::new(MAX_DISK);
        huge.bat = vec![];
        let err = open_bytes(build(&huge), None).err().unwrap();
        assert!(
            matches!(err, Error::Corrupt(_) | Error::Unsupported(_)),
            "{err}"
        );
    }

    #[test]
    fn differencing_without_a_bitmap_is_corrupt_on_read() {
        let mut spec = Spec::new(BS);
        spec.parent = Some(vec![("relative_path", "p.vhdx".to_string())]);
        spec.bat = vec![(0, entry(STATE_PARTIALLY_PRESENT, DATA_AT))];
        let src = open_bytes(build(&spec), Some(vec![0u8; BS as usize])).unwrap();
        assert!(src.read_at(0, &mut [0u8; 16]).is_err());
    }

    #[test]
    fn open_finds_the_parent_next_to_the_child() {
        let dir = std::env::temp_dir().join(format!("disk-atlas-vhdx-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut parent = Spec::new(2 * BS);
        parent.bat = vec![(0, entry(STATE_FULLY_PRESENT, DATA_AT))];
        parent.blobs = vec![(DATA_AT, block_data(9))];
        std::fs::write(dir.join("parent.vhdx"), build(&parent)).unwrap();
        let mut child = Spec::new(2 * BS);
        child.parent = Some(vec![
            ("relative_path", ".\\parent.vhdx".to_string()),
            (
                "absolute_win32_path",
                "C:\\nowhere\\parent.vhdx".to_string(),
            ),
        ]);
        child.bat = vec![(0, entry(STATE_NOT_PRESENT, 0)), (1, entry(STATE_ZERO, 0))];
        std::fs::write(dir.join("child.vhdx"), build(&child)).unwrap();
        let src = open(&dir.join("child.vhdx")).unwrap();
        let mut buf = vec![0u8; 64];
        src.read_at(10, &mut buf).unwrap();
        assert_eq!(buf, block_data(9)[10..74]);
        // Delete the parent: Unsupported, naming the child.
        std::fs::remove_file(dir.join("parent.vhdx")).unwrap();
        let err = open(&dir.join("child.vhdx")).err().unwrap();
        assert!(
            matches!(&err, Error::Unsupported(text) if text.contains("child.vhdx")),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
