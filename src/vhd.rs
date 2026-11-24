// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Microsoft Virtual Hard Disk (`.vhd`): fixed, dynamic and differencing.
//!
//! # Layout
//!
//! Source: "Virtual Hard Disk Image Format Specification", version 1.0,
//! Microsoft, 2006. All integers are big-endian.
//!
//! The 512-byte footer ends every VHD; dynamic and differencing disks also
//! keep a copy at the start of the file. Fields used here:
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 8 | cookie `conectix` |
//! | 12 | 4 | file format version (major 1) |
//! | 16 | 8 | data offset: the dynamic header, or all ones when fixed |
//! | 48 | 8 | current size of the disk in bytes |
//! | 60 | 4 | disk type: 2 fixed, 3 dynamic, 4 differencing |
//! | 64 | 4 | checksum: the one's complement of the sum of every other byte |
//! | 68 | 16 | unique id |
//!
//! A fixed disk is the bytes before its footer. A dynamic or differencing
//! disk has a 1024-byte header at the data offset: cookie `cxsparse`, the
//! table offset (8 at byte 16), the header version (4 at 24), the maximum
//! table entries (4 at 28), the block size (4 at 32), its own checksum (4 at
//! 36), the parent's name as UTF-16BE (512 bytes at 64) and eight parent
//! locators of 24 bytes from byte 576 (platform code, data space, data
//! length, reserved, data offset).
//!
//! The block allocation table (BAT) holds one `u32` per block: the sector
//! number of the block, or `0xFFFFFFFF` when it was never written. A block
//! is a sector bitmap, padded to a whole number of sectors, then the data.
//! Bit 7 of the first bitmap byte is the first sector. A sector whose bit is
//! clear holds nothing: a differencing disk reads it from the parent, a
//! dynamic disk reads zeros.
//!
//! # Choices where the specification is silent
//!
//! - The footer is read from the last 512 bytes of the file, falling back to
//!   the copy at the start. A footer a few bytes short (some old producers
//!   wrote 511 bytes) is not handled.
//! - Disk types other than 2, 3 and 4 and format versions other than 1.x are
//!   `Unsupported`.
//! - A fixed disk whose current size exceeds the data in the file is corrupt.
//! - The block size must be a power of two of at least 512; above 256 MiB it
//!   is `Unsupported`. A BAT larger than 64 MiB is `Unsupported`.
//! - The BAT must hold at least `ceil(size / block size)` entries (entries
//!   past that are ignored) and lie inside the file.
//! - A BAT entry pointing at or past the end of the file is corrupt. A block
//!   cut short by the end of the file reads its missing part as zeros, and a
//!   missing bitmap byte reads as clear.
//! - A parent disk shorter than the child reads zeros past its end.
//! - The parent's unique id and timestamp are not compared.
//! - [`open`] looks for the parent through the `W2ru` (relative) and `W2ku`
//!   (absolute) locators, then the parent name in the header, relative to
//!   the child's folder. `Mac ` and `MacX` locators are ignored. A chain of
//!   more than 8 disks is `Unsupported`, which also stops a loop.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use atlas_fs_core::error::{CorruptKind, Corruption, Error, Location, Result};
use atlas_fs_core::io::block::{BlockSource, check_range};
use atlas_fs_core::io::file::FileSource;

/// Size of the footer.
const FOOTER_LEN: usize = 512;
/// Size of the dynamic disk header.
const HEADER_LEN: usize = 1024;
/// `conectix`.
const FOOTER_COOKIE: [u8; 8] = *b"conectix";
/// `cxsparse`.
const HEADER_COOKIE: [u8; 8] = *b"cxsparse";
/// Bytes per sector.
const SECTOR: u64 = 512;
/// BAT entry of a block that was never written.
const UNALLOCATED: u32 = 0xFFFF_FFFF;
/// Largest block size read.
const MAX_BLOCK: u64 = 256 << 20;
/// Most BAT bytes held in memory.
const MAX_TABLE_BYTES: u64 = 64 << 20;
/// Most parent disks followed by [`open`].
const MAX_PARENT_DEPTH: usize = 8;
/// Longest locator path read, in bytes.
const MAX_LOCATOR_BYTES: u32 = 4096;
/// Offset of the first parent locator in the dynamic header.
const LOCATORS_OFFSET: usize = 576;

const FOOTER: &str = "VHD footer";
const HEADER: &str = "VHD dynamic header";
const TABLE: &str = "VHD block allocation table";

fn corrupt(what: &'static str, offset: u64, kind: CorruptKind) -> Error {
    Error::Corrupt(Corruption::new(what, Location::Byte(offset), kind))
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

fn be32(buf: &[u8], offset: usize, what: &'static str) -> Result<u32> {
    field(buf, offset)
        .map(u32::from_be_bytes)
        .ok_or_else(|| truncated(what, offset, 4))
}

fn be64(buf: &[u8], offset: usize, what: &'static str) -> Result<u64> {
    field(buf, offset)
        .map(u64::from_be_bytes)
        .ok_or_else(|| truncated(what, offset, 8))
}

/// The one's complement of the sum of the bytes of `buf`, leaving out the
/// four checksum bytes at `skip`.
fn checksum(buf: &[u8], skip: usize) -> u32 {
    let mut sum = 0u32;
    for (i, b) in buf.iter().enumerate() {
        if i < skip || i >= skip.saturating_add(4) {
            sum = sum.wrapping_add(u32::from(*b));
        }
    }
    !sum
}

fn check_cookie(buf: &[u8], cookie: [u8; 8], what: &'static str) -> Result<()> {
    let found: [u8; 8] = field(buf, 0).ok_or_else(|| truncated(what, 0, 8))?;
    if found != cookie {
        return Err(corrupt(
            what,
            0,
            CorruptKind::BadSignature {
                expected: u64::from_be_bytes(cookie),
                found: u64::from_be_bytes(found),
            },
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiskType {
    Fixed,
    Dynamic,
    Differencing,
}

struct Footer {
    data_offset: u64,
    current_size: u64,
    disk_type: DiskType,
}

fn parse_footer(buf: &[u8]) -> Result<Footer> {
    check_cookie(buf, FOOTER_COOKIE, FOOTER)?;
    let stored = be32(buf, 64, FOOTER)?;
    let computed = checksum(buf, 64);
    if stored != computed {
        return Err(corrupt(
            FOOTER,
            64,
            CorruptKind::InvalidValue {
                field: "checksum",
                value: u64::from(stored),
            },
        ));
    }
    let version = be32(buf, 12, FOOTER)?;
    if version >> 16 != 1 {
        return Err(Error::unsupported(format!(
            "VHD format version {version:#x}"
        )));
    }
    let disk_type = match be32(buf, 60, FOOTER)? {
        2 => DiskType::Fixed,
        3 => DiskType::Dynamic,
        4 => DiskType::Differencing,
        other => return Err(Error::unsupported(format!("VHD disk type {other}"))),
    };
    Ok(Footer {
        data_offset: be64(buf, 16, FOOTER)?,
        current_size: be64(buf, 48, FOOTER)?,
        disk_type,
    })
}

/// The footer, and for a dynamic or differencing disk its header bytes.
struct Layout {
    footer: Footer,
    /// True when the footer came from the end of the file.
    at_end: bool,
    header: Option<Vec<u8>>,
}

fn read_layout(file: &dyn BlockSource) -> Result<Layout> {
    let file_len = file.len();
    let end = file_len.checked_sub(FOOTER_LEN as u64).ok_or_else(|| {
        corrupt(
            FOOTER,
            0,
            CorruptKind::Truncated {
                needed: FOOTER_LEN as u64,
                available: file_len,
            },
        )
    })?;
    let mut buf = [0u8; FOOTER_LEN];
    file.read_at(end, &mut buf)?;
    let (footer, at_end) = match parse_footer(&buf) {
        Ok(footer) => (footer, true),
        Err(first) => {
            file.read_at(0, &mut buf)?;
            match parse_footer(&buf) {
                Ok(footer) => (footer, false),
                Err(_) => return Err(first),
            }
        }
    };
    let header = match footer.disk_type {
        DiskType::Fixed => None,
        DiskType::Dynamic | DiskType::Differencing => Some(read_header(file, &footer)?),
    };
    Ok(Layout {
        footer,
        at_end,
        header,
    })
}

fn read_header(file: &dyn BlockSource, footer: &Footer) -> Result<Vec<u8>> {
    let file_len = file.len();
    let offset = footer.data_offset;
    let in_file = offset != u64::MAX
        && offset
            .checked_add(HEADER_LEN as u64)
            .is_some_and(|end| end <= file_len);
    if !in_file {
        return Err(corrupt(
            FOOTER,
            16,
            CorruptKind::OutOfRange {
                field: "data offset",
                value: offset,
                limit_name: "file size",
                limit: file_len,
            },
        ));
    }
    let mut header = vec![0u8; HEADER_LEN];
    file.read_at(offset, &mut header)?;
    check_cookie(&header, HEADER_COOKIE, HEADER)?;
    let stored = be32(&header, 36, HEADER)?;
    if stored != checksum(&header, 36) {
        return Err(corrupt(
            HEADER,
            36,
            CorruptKind::InvalidValue {
                field: "checksum",
                value: u64::from(stored),
            },
        ));
    }
    let version = be32(&header, 24, HEADER)?;
    if version >> 16 != 1 {
        return Err(Error::unsupported(format!(
            "VHD dynamic header version {version:#x}"
        )));
    }
    Ok(header)
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

/// Opens the VHD at `path` read-only. A differencing disk's parent is
/// found next to it (see the module docs).
pub fn open(path: &Path) -> Result<Arc<dyn BlockSource>> {
    open_depth(path, 0)
}

fn open_depth(path: &Path, depth: usize) -> Result<Arc<dyn BlockSource>> {
    if depth > MAX_PARENT_DEPTH {
        return Err(Error::unsupported(format!(
            "VHD parent chain longer than {MAX_PARENT_DEPTH} disks at {}",
            path.display()
        )));
    }
    let file: Arc<dyn BlockSource> = Arc::new(FileSource::open(path)?);
    let layout = read_layout(&*file)?;
    let parent = match (layout.footer.disk_type, &layout.header) {
        (DiskType::Differencing, Some(header)) => Some(open_parent(path, &*file, header, depth)?),
        _ => None,
    };
    Ok(Arc::new(VhdSource::new(file, parent)?))
}

fn open_parent(
    child: &Path,
    file: &dyn BlockSource,
    header: &[u8],
    depth: usize,
) -> Result<Arc<dyn BlockSource>> {
    let names = parent_names(file, header);
    let folder = child.parent().unwrap_or_else(|| Path::new("."));
    for name in &names {
        let name = if cfg!(windows) {
            name.clone()
        } else {
            name.replace('\\', "/")
        };
        let candidate = Path::new(&name);
        let resolved: PathBuf = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            folder.join(candidate)
        };
        if resolved.is_file() {
            return open_depth(&resolved, depth.saturating_add(1));
        }
    }
    Err(Error::unsupported(format!(
        "VHD parent disk not found for {} (looked for: {})",
        child.display(),
        if names.is_empty() {
            "no parent name".to_string()
        } else {
            names.join(", ")
        }
    )))
}

fn utf16_name(bytes: &[u8], big_endian: bool) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|a| {
            if big_endian {
                u16::from_be_bytes(*a)
            } else {
                u16::from_le_bytes(*a)
            }
        })
        .take_while(|unit| *unit != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Candidate parent paths in the order to try them: relative locators,
/// absolute locators, then the name in the header.
fn parent_names(file: &dyn BlockSource, header: &[u8]) -> Vec<String> {
    let mut relative = Vec::new();
    let mut absolute = Vec::new();
    for i in 0..8usize {
        let base = LOCATORS_OFFSET.saturating_add(i.saturating_mul(24));
        let Some(entry) = header.get(base..base.saturating_add(24)) else {
            break;
        };
        let Some(code) = field::<4>(entry, 0) else {
            continue;
        };
        let target = match &code {
            b"W2ru" => &mut relative,
            b"W2ku" => &mut absolute,
            _ => continue,
        };
        let (Ok(len), Ok(offset)) = (be32(entry, 8, HEADER), be64(entry, 16, HEADER)) else {
            continue;
        };
        if len == 0 || len > MAX_LOCATOR_BYTES {
            continue;
        }
        let in_file = offset
            .checked_add(u64::from(len))
            .is_some_and(|end| end <= file.len());
        let Ok(len) = usize::try_from(len) else {
            continue;
        };
        if !in_file {
            continue;
        }
        let mut data = vec![0u8; len];
        if file.read_at(offset, &mut data).is_err() {
            continue;
        }
        let text = utf16_name(&data, false);
        if !text.is_empty() {
            target.push(text);
        }
    }
    let mut names = relative;
    names.append(&mut absolute);
    if let Some(raw) = header.get(64..64 + 512) {
        let text = utf16_name(raw, true);
        if !text.is_empty() {
            names.push(text);
        }
    }
    names
}

/// A dynamic or differencing disk's block map.
struct Dynamic {
    block_size: u64,
    /// Bytes of the sector bitmap in front of each block's data, padded to
    /// whole sectors.
    bitmap_bytes: u64,
    /// The BAT as stored: big-endian `u32` entries.
    bat: Vec<u8>,
}

impl Dynamic {
    fn entry(&self, block: u64) -> Option<u32> {
        let at = usize::try_from(block).ok()?.checked_mul(4)?;
        field(&self.bat, at).map(u32::from_be_bytes)
    }
}

enum Kind {
    Fixed,
    Dynamic(Dynamic),
}

/// The disk a VHD presents.
pub struct VhdSource {
    file: Arc<dyn BlockSource>,
    /// The parent of a differencing disk.
    parent: Option<Arc<dyn BlockSource>>,
    len: u64,
    kind: Kind,
}

impl VhdSource {
    /// Parses the VHD stored in `file`.
    ///
    /// A differencing disk needs `parent`, the disk it was taken from; any
    /// other kind ignores it. Fails with [`Error::Corrupt`] on damage and
    /// [`Error::Unsupported`] for what the module docs list.
    pub fn new(file: Arc<dyn BlockSource>, parent: Option<Arc<dyn BlockSource>>) -> Result<Self> {
        let file_len = file.len();
        let layout = read_layout(&*file)?;
        let len = layout.footer.current_size;
        let disk_type = layout.footer.disk_type;
        let Some(header) = layout.header else {
            // Fixed: the data is everything before the footer.
            if !layout.at_end {
                return Err(corrupt(
                    FOOTER,
                    0,
                    CorruptKind::Other("fixed VHD without a footer at the end of the file"),
                ));
            }
            let data_len = file_len.saturating_sub(FOOTER_LEN as u64);
            if len > data_len {
                return Err(corrupt(
                    FOOTER,
                    48,
                    CorruptKind::OutOfRange {
                        field: "current size",
                        value: len,
                        limit_name: "data in file",
                        limit: data_len,
                    },
                ));
            }
            return Ok(Self {
                file,
                parent: None,
                len,
                kind: Kind::Fixed,
            });
        };
        let parent = if disk_type == DiskType::Differencing {
            Some(parent.ok_or_else(|| {
                Error::unsupported("a differencing VHD needs its parent disk to be read")
            })?)
        } else {
            None
        };

        let table_offset = be64(&header, 16, HEADER)?;
        let max_entries = be32(&header, 28, HEADER)?;
        let block_size = u64::from(be32(&header, 32, HEADER)?);
        if block_size < SECTOR || !block_size.is_power_of_two() {
            return Err(corrupt(
                HEADER,
                32,
                CorruptKind::InvalidValue {
                    field: "block size",
                    value: block_size,
                },
            ));
        }
        if block_size > MAX_BLOCK {
            return Err(Error::unsupported(format!(
                "VHD block size {block_size} (over {MAX_BLOCK})"
            )));
        }
        let entries = len.div_ceil(block_size);
        if entries > u64::from(max_entries) {
            return Err(corrupt(
                HEADER,
                28,
                CorruptKind::OutOfRange {
                    field: "blocks in the disk",
                    value: entries,
                    limit_name: "maximum table entries",
                    limit: u64::from(max_entries),
                },
            ));
        }
        // entries <= u32::MAX, so this cannot overflow.
        let table_bytes = entries.checked_mul(4).ok_or_else(|| {
            corrupt(
                HEADER,
                28,
                CorruptKind::Overflow {
                    field: "table size",
                },
            )
        })?;
        let in_file = table_offset
            .checked_add(table_bytes)
            .is_some_and(|end| end <= file_len);
        if !in_file {
            return Err(corrupt(
                HEADER,
                16,
                CorruptKind::OutOfRange {
                    field: "table offset",
                    value: table_offset,
                    limit_name: "file size",
                    limit: file_len,
                },
            ));
        }
        if table_bytes > MAX_TABLE_BYTES {
            return Err(Error::unsupported(format!(
                "VHD block table of {table_bytes} bytes (over {MAX_TABLE_BYTES})"
            )));
        }
        let table_len = usize::try_from(table_bytes).map_err(|_| {
            corrupt(
                HEADER,
                28,
                CorruptKind::Overflow {
                    field: "table size",
                },
            )
        })?;
        let mut bat = vec![0u8; table_len];
        file.read_at(table_offset, &mut bat)?;
        for (i, raw) in bat.as_chunks::<4>().0.iter().enumerate() {
            let entry = u32::from_be_bytes(*raw);
            if entry != UNALLOCATED && u64::from(entry) * SECTOR >= file_len {
                return Err(corrupt(
                    TABLE,
                    table_offset.saturating_add((i as u64).saturating_mul(4)),
                    CorruptKind::OutOfRange {
                        field: "block offset",
                        value: u64::from(entry) * SECTOR,
                        limit_name: "file size",
                        limit: file_len,
                    },
                ));
            }
        }
        // block_size is a power of two of at least 512, so there are at
        // least one sector and the bitmap is at least one byte.
        let bitmap_raw = (block_size / SECTOR).div_ceil(8);
        let bitmap_bytes = bitmap_raw.div_ceil(SECTOR).saturating_mul(SECTOR);
        Ok(Self {
            file,
            parent,
            len,
            kind: Kind::Dynamic(Dynamic {
                block_size,
                bitmap_bytes,
                bat,
            }),
        })
    }

    /// Fills `buf` from the parent at disk offset `pos`, or with zeros.
    fn read_parent(&self, pos: u64, buf: &mut [u8], bulk: bool) -> Result<()> {
        let Some(parent) = &self.parent else {
            buf.fill(0);
            return Ok(());
        };
        let avail = usize::try_from(parent.len().saturating_sub(pos))
            .map_or(buf.len(), |a| a.min(buf.len()));
        let want = u64::try_from(buf.len()).unwrap_or(u64::MAX);
        let (data, zeros) = buf.split_at_mut_checked(avail).ok_or(Error::OutOfBounds {
            offset: pos,
            len: want,
            size: parent.len(),
        })?;
        if !data.is_empty() {
            if bulk {
                parent.read_bulk(pos, data)?;
            } else {
                parent.read_at(pos, data)?;
            }
        }
        zeros.fill(0);
        Ok(())
    }

    /// Reads `chunk`, which starts `within` bytes into the allocated block
    /// at file offset `block_start` and at disk offset `pos`, and does not
    /// leave the block.
    fn read_block(
        &self,
        d: &Dynamic,
        block_start: u64,
        within: u64,
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
        let last = within.checked_add(n).ok_or_else(oob)?;
        let first_sector = within / SECTOR;
        let last_sector = last.saturating_sub(1) / SECTOR;
        let first_byte = first_sector / 8;
        let bitmap_len = usize::try_from(
            (last_sector / 8)
                .saturating_sub(first_byte)
                .saturating_add(1),
        )
        .map_err(|_| oob())?;
        let mut bitmap = vec![0u8; bitmap_len];
        read_clamped(
            &*self.file,
            block_start.checked_add(first_byte).ok_or_else(oob)?,
            &mut bitmap,
            false,
        )?;
        let data_start = block_start.checked_add(d.bitmap_bytes).ok_or_else(oob)?;
        let set = |sector: u64| -> Result<bool> {
            let index =
                usize::try_from((sector / 8).saturating_sub(first_byte)).map_err(|_| oob())?;
            let byte = bitmap.get(index).copied().ok_or_else(oob)?;
            Ok(byte & (0x80 >> (sector % 8)) != 0)
        };
        // Each pass takes at least one byte, so at most `chunk.len()` passes.
        let mut cur = 0u64;
        while cur < n {
            let state = set(within.saturating_add(cur) / SECTOR)?;
            let mut end = cur;
            while end < n {
                let sector = within.saturating_add(end) / SECTOR;
                if set(sector)? != state {
                    break;
                }
                end = sector
                    .saturating_add(1)
                    .saturating_mul(SECTOR)
                    .saturating_sub(within)
                    .min(n);
            }
            let a = usize::try_from(cur).map_err(|_| oob())?;
            let b = usize::try_from(end).map_err(|_| oob())?;
            let part = chunk.get_mut(a..b).ok_or_else(oob)?;
            if state {
                let at = data_start
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
        let d = match &self.kind {
            Kind::Fixed => return read_clamped(&*self.file, offset, buf, bulk),
            Kind::Dynamic(d) => d,
        };
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
                .checked_div(d.block_size)
                .ok_or_else(|| oob(pos, left))?;
            let within = pos
                .checked_rem(d.block_size)
                .ok_or_else(|| oob(pos, left))?;
            let in_block = d
                .block_size
                .checked_sub(within)
                .ok_or_else(|| oob(pos, left))?;
            let n = usize::try_from(in_block).map_or(left, |in_block| in_block.min(left));
            let (chunk, tail) = rest.split_at_mut_checked(n).ok_or_else(|| oob(pos, left))?;
            let entry = d.entry(block).ok_or_else(|| {
                corrupt(
                    TABLE,
                    block.saturating_mul(4),
                    CorruptKind::OutOfRange {
                        field: "block index",
                        value: block,
                        limit_name: "table entries",
                        limit: (d.bat.len() / 4) as u64,
                    },
                )
            })?;
            if entry == UNALLOCATED {
                self.read_parent(pos, chunk, bulk)?;
            } else {
                // A u32 times 512 fits in a u64.
                let block_start = u64::from(entry) * SECTOR;
                self.read_block(d, block_start, within, pos, chunk, bulk)?;
            }
            pos = pos
                .checked_add(u64::try_from(n).unwrap_or(u64::MAX))
                .ok_or_else(|| oob(pos, n))?;
            rest = tail;
        }
        Ok(())
    }
}

impl BlockSource for VhdSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        512
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

    /// Block size of the test disks: 8 sectors, so one bitmap byte.
    const BS: usize = 4096;
    const HEADER_AT: usize = FOOTER_LEN;
    const BAT_AT: usize = FOOTER_LEN + HEADER_LEN;

    /// What a stored block holds at `offset`, for fill `seed`.
    fn pattern(seed: u8, offset: usize) -> u8 {
        (seed as usize * 31 + offset * 7 + 1) as u8
    }

    /// What the parent disk holds at `pos`.
    fn parent_byte(pos: usize) -> u8 {
        (pos * 13 + 5) as u8
    }

    fn parent_disk(len: usize) -> Vec<u8> {
        (0..len).map(parent_byte).collect()
    }

    fn put32(buf: &mut [u8], at: usize, v: u32) {
        buf[at..at + 4].copy_from_slice(&v.to_be_bytes());
    }

    fn put64(buf: &mut [u8], at: usize, v: u64) {
        buf[at..at + 8].copy_from_slice(&v.to_be_bytes());
    }

    fn seal(buf: &mut [u8], skip: usize) {
        let sum = checksum(buf, skip);
        put32(buf, skip, sum);
    }

    fn footer(size: u64, disk_type: u32, data_offset: u64) -> Vec<u8> {
        let mut f = vec![0u8; FOOTER_LEN];
        f[..8].copy_from_slice(b"conectix");
        put32(&mut f, 8, 2);
        put32(&mut f, 12, 0x0001_0000);
        put64(&mut f, 16, data_offset);
        put64(&mut f, 40, size);
        put64(&mut f, 48, size);
        put32(&mut f, 60, disk_type);
        seal(&mut f, 64);
        f
    }

    /// A fixed disk: the data, then the footer.
    fn build_fixed(data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        out.extend(footer(data.len() as u64, 2, u64::MAX));
        out
    }

    /// A dynamic (3) or differencing (4) disk. `blocks[i]` is `None` for a
    /// block never written, or `(bitmap byte, seed)` for a stored one.
    fn build_dynamic(
        size: u64,
        disk_type: u32,
        blocks: &[Option<(u8, u8)>],
        parent_name: &str,
    ) -> Vec<u8> {
        let mut out = footer(size, disk_type, HEADER_AT as u64);
        let mut header = vec![0u8; HEADER_LEN];
        header[..8].copy_from_slice(b"cxsparse");
        put64(&mut header, 8, u64::MAX);
        put64(&mut header, 16, BAT_AT as u64);
        put32(&mut header, 24, 0x0001_0000);
        put32(&mut header, 28, blocks.len() as u32);
        put32(&mut header, 32, BS as u32);
        for (i, unit) in parent_name.encode_utf16().enumerate() {
            header[64 + i * 2..66 + i * 2].copy_from_slice(&unit.to_be_bytes());
        }
        seal(&mut header, 36);
        out.extend(header);
        let bat_len = (blocks.len() * 4).div_ceil(512) * 512;
        let mut bat = vec![0xFFu8; bat_len];
        let mut body = Vec::new();
        for (i, block) in blocks.iter().enumerate() {
            let Some((bits, seed)) = block else { continue };
            let at = BAT_AT + bat_len + body.len();
            put32(&mut bat, i * 4, (at / 512) as u32);
            let mut bitmap = vec![0u8; 512];
            bitmap[0] = *bits;
            body.extend(bitmap);
            body.extend((0..BS).map(|o| pattern(*seed, o)));
        }
        out.extend(bat);
        out.extend(body);
        out.extend(footer(size, disk_type, HEADER_AT as u64));
        out
    }

    fn expected(size: usize, blocks: &[Option<(u8, u8)>], with_parent: bool) -> Vec<u8> {
        let mut disk = vec![0u8; size];
        for (pos, byte) in disk.iter_mut().enumerate() {
            let (i, within) = (pos / BS, pos % BS);
            let sector = within / 512;
            let from_block = blocks
                .get(i)
                .copied()
                .flatten()
                .filter(|(bits, _)| bits & (0x80 >> sector) != 0);
            *byte = match from_block {
                Some((_, seed)) => pattern(seed, within),
                None if with_parent => parent_byte(pos),
                None => 0,
            };
        }
        disk
    }

    fn open_bytes(bytes: Vec<u8>, parent: Option<Vec<u8>>) -> Result<VhdSource> {
        let parent: Option<Arc<dyn BlockSource>> =
            parent.map(|p| Arc::new(MemSource::new(p)) as Arc<dyn BlockSource>);
        VhdSource::new(Arc::new(MemSource::new(bytes)), parent)
    }

    fn read_all(src: &VhdSource) -> Vec<u8> {
        let mut buf = vec![0u8; src.len() as usize];
        src.read_at(0, &mut buf).unwrap();
        buf
    }

    /// Rewrites both footer copies, then reseals them.
    fn patch_footers(bytes: &mut [u8], edit: impl Fn(&mut [u8])) {
        let end = bytes.len() - FOOTER_LEN;
        for at in [0, end] {
            let f = &mut bytes[at..at + FOOTER_LEN];
            edit(f);
            seal(f, 64);
        }
    }

    fn patch_header(bytes: &mut [u8], edit: impl Fn(&mut [u8])) {
        let h = &mut bytes[HEADER_AT..HEADER_AT + HEADER_LEN];
        edit(h);
        seal(h, 36);
    }

    #[test]
    fn fixed_disk_reads_its_data() {
        let data: Vec<u8> = (0..3000usize).map(|i| (i % 251) as u8).collect();
        let src = open_bytes(build_fixed(&data), None).unwrap();
        assert_eq!(src.len(), 3000);
        assert_eq!(src.sector_size(), 512);
        assert_eq!(read_all(&src), data);
        let mut buf = vec![0u8; 700];
        src.read_bulk(1234, &mut buf).unwrap();
        assert_eq!(buf, data[1234..1934]);
        assert!(matches!(
            src.read_at(2999, &mut [0u8; 2]),
            Err(Error::OutOfBounds { .. })
        ));
        // A fixed disk may be smaller than the data in the file.
        let mut bytes = build_fixed(&data);
        patch_footers(&mut bytes, |f| put64(f, 48, 2000));
        assert_eq!(open_bytes(bytes, None).unwrap().len(), 2000);
        // And may not be larger.
        let mut bytes = build_fixed(&data);
        patch_footers(&mut bytes, |f| put64(f, 48, 3001));
        assert!(matches!(open_bytes(bytes, None), Err(Error::Corrupt(_))));
    }

    #[test]
    fn dynamic_disk_with_a_hole_reads_across_blocks() {
        // Block 1 was never written; block 2 has sectors 0 and 7 only.
        let blocks = [
            Some((0xFF, 1)),
            None,
            Some((0b1000_0001, 2)),
            Some((0xFF, 3)),
        ];
        let size = 4 * BS - 100;
        let src = open_bytes(build_dynamic(size as u64, 3, &blocks, ""), None).unwrap();
        let want = expected(size, &blocks, false);
        assert_eq!(read_all(&src), want);
        for (offset, len) in [
            (4000, 300),
            (BS - 1, 2),
            (BS, BS),
            (2 * BS + 500, 3 * 512),
            (0, size),
        ] {
            let mut buf = vec![0u8; len];
            src.read_at(offset as u64, &mut buf).unwrap();
            assert_eq!(buf, want[offset..offset + len], "at {offset} len {len}");
            let mut bulk = vec![0u8; len];
            src.read_bulk(offset as u64, &mut bulk).unwrap();
            assert_eq!(bulk, buf);
        }
    }

    #[test]
    fn differencing_disk_reads_clear_sectors_from_the_parent() {
        let blocks = [Some((0b1111_0000, 5)), None, Some((0b0101_0101, 6))];
        let size = 3 * BS;
        let bytes = build_dynamic(size as u64, 4, &blocks, "parent.vhd");
        // Without a parent the disk cannot be read.
        assert!(matches!(
            open_bytes(bytes.clone(), None),
            Err(Error::Unsupported(_))
        ));
        let src = open_bytes(bytes, Some(parent_disk(size))).unwrap();
        assert_eq!(read_all(&src), expected(size, &blocks, true));
        // A short parent reads zeros past its end.
        let short = open_bytes(
            build_dynamic(size as u64, 4, &[None, None, None], ""),
            Some(parent_disk(BS)),
        )
        .unwrap();
        let got = read_all(&short);
        assert_eq!(got[..BS], parent_disk(BS)[..]);
        assert!(got[BS..].iter().all(|b| *b == 0));
    }

    #[test]
    fn footer_falls_back_to_the_start_copy() {
        let blocks = [Some((0xFF, 1))];
        let mut bytes = build_dynamic(BS as u64, 3, &blocks, "");
        let end = bytes.len() - FOOTER_LEN;
        bytes[end + 10] ^= 0xFF;
        let src = open_bytes(bytes, None).unwrap();
        assert_eq!(read_all(&src), expected(BS, &blocks, false));
    }

    #[test]
    fn hostile_headers_fail_without_panicking() {
        let blocks = [Some((0xFF, 1)), None];
        let good = build_dynamic(2 * BS as u64, 3, &blocks, "");
        assert!(open_bytes(good.clone(), None).is_ok());

        let is_err = |bytes: Vec<u8>| {
            assert!(open_bytes(bytes, None).is_err());
        };
        // Bad footer checksum and cookie, in both copies.
        let mut bytes = good.clone();
        let end = bytes.len() - FOOTER_LEN;
        bytes[20] ^= 1;
        bytes[end + 20] ^= 1;
        is_err(bytes);
        let mut bytes = good.clone();
        let end = bytes.len() - FOOTER_LEN;
        bytes[0] = b'x';
        bytes[end] = b'x';
        is_err(bytes);
        // Bad header checksum, cookie, block size 0, 3 and 512 * 2^20.
        let mut bytes = good.clone();
        bytes[HEADER_AT + 40] ^= 1;
        is_err(bytes);
        let mut bytes = good.clone();
        bytes[HEADER_AT] = b'x';
        is_err(bytes);
        for bad in [0u32, 3, 600, 1 << 29] {
            let mut bytes = good.clone();
            patch_header(&mut bytes, |h| put32(h, 32, bad));
            is_err(bytes);
        }
        // Table offset past the end, and u64::MAX.
        for bad in [good.len() as u64 - 4, u64::MAX] {
            let mut bytes = good.clone();
            patch_header(&mut bytes, |h| put64(h, 16, bad));
            is_err(bytes);
        }
        // Data offset past the end and all ones in a dynamic disk.
        for bad in [good.len() as u64, u64::MAX] {
            let mut bytes = good.clone();
            patch_footers(&mut bytes, |f| put64(f, 16, bad));
            is_err(bytes);
        }
        // Huge claimed sizes, with and without a matching entry count.
        for (size, max) in [(u64::MAX, u32::MAX), (u64::MAX, 2), (1 << 50, u32::MAX)] {
            let mut bytes = good.clone();
            patch_footers(&mut bytes, |f| put64(f, 48, size));
            patch_header(&mut bytes, |h| put32(h, 28, max));
            is_err(bytes);
        }
        // A block that starts past the end of the file.
        let mut bytes = good.clone();
        put32(&mut bytes, BAT_AT, 0x00FF_FFFF);
        is_err(bytes);
        // Too short for a footer, and a bare cookie.
        is_err(vec![0u8; 100]);
        is_err(Vec::new());
        let mut bare = vec![0u8; 1024];
        bare[..8].copy_from_slice(b"conectix");
        is_err(bare);
        // Truncated in the middle: the end footer is gone.
        let mut bytes = good.clone();
        bytes.truncate(BAT_AT + 100);
        is_err(bytes);
        // Unknown disk types and versions are Unsupported.
        let mut bytes = good.clone();
        patch_footers(&mut bytes, |f| put32(f, 60, 1));
        assert!(matches!(
            open_bytes(bytes, None),
            Err(Error::Unsupported(_))
        ));
        let mut bytes = good;
        patch_footers(&mut bytes, |f| put32(f, 12, 0x0002_0000));
        assert!(matches!(
            open_bytes(bytes, None),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn block_cut_short_reads_zeros() {
        let blocks = [Some((0xFF, 1))];
        let mut bytes = build_dynamic(BS as u64, 3, &blocks, "");
        // Drop the footer copy at the end and the last 300 bytes of data.
        bytes.truncate(bytes.len() - FOOTER_LEN - 300);
        // The start copy is still good.
        let src = open_bytes(bytes, None).unwrap();
        let mut want = expected(BS, &blocks, false);
        for b in &mut want[BS - 300..] {
            *b = 0;
        }
        assert_eq!(read_all(&src), want);
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("disk-atlas-vhd-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn open_finds_the_parent_next_to_the_child() {
        let dir = temp_dir("parent");
        let size = 2 * BS;
        let blocks = [Some((0b1000_0000, 4)), None];
        std::fs::write(dir.join("base.vhd"), build_fixed(&parent_disk(size))).unwrap();
        std::fs::write(
            dir.join("child.vhd"),
            build_dynamic(size as u64, 4, &blocks, "base.vhd"),
        )
        .unwrap();
        let src = open(&dir.join("child.vhd")).unwrap();
        let mut buf = vec![0u8; size];
        src.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, expected(size, &blocks, true));
        drop(src);

        // A missing parent is Unsupported and names the file.
        std::fs::write(
            dir.join("orphan.vhd"),
            build_dynamic(size as u64, 4, &blocks, "gone.vhd"),
        )
        .unwrap();
        match open(&dir.join("orphan.vhd")) {
            Err(Error::Unsupported(text)) => assert!(text.contains("gone.vhd"), "{text}"),
            other => panic!("expected Unsupported, got {:?}", other.err()),
        }
        // A disk that is its own parent stops at the depth limit.
        std::fs::write(
            dir.join("loop.vhd"),
            build_dynamic(size as u64, 4, &blocks, "loop.vhd"),
        )
        .unwrap();
        assert!(matches!(
            open(&dir.join("loop.vhd")),
            Err(Error::Unsupported(_))
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
