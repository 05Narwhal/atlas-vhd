// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Fuzzes the VHDX reader: the headers, region table, metadata table, the
//! block allocation table, sector bitmaps and reads across block boundaries. A
//! fixed in-memory parent stands in for the parent of a differencing disk.

#![no_main]

use std::sync::Arc;

use atlas_vhd::vhdx::VhdxSource;
use atlas_fs_core::io::block::{BlockSource, MemSource};
use libfuzzer_sys::fuzz_target;

/// Most disk bytes read per input, so a large claimed size costs little time.
const READ_LIMIT: u64 = 1 << 20;
/// Bytes per read: not a multiple of any block size, so reads straddle blocks.
const STEP: usize = 64 * 1024 + 1;

fuzz_target!(|data: &[u8]| {
    let file: Arc<dyn BlockSource> = Arc::new(MemSource::new(data));
    let parent: Arc<dyn BlockSource> = Arc::new(MemSource::new(vec![0xA5u8; 8192]));
    let Ok(disk) = VhdxSource::new(file, Some(parent)) else {
        return;
    };
    let end = disk.len().min(READ_LIMIT);
    let mut buf = vec![0u8; STEP];
    let mut pos = 0;
    while pos < end {
        let n = usize::try_from(end - pos).map_or(STEP, |left| left.min(STEP));
        if disk.read_at(pos, &mut buf[..n]).is_err() {
            break;
        }
        pos += n as u64;
    }
    // Read the start again, after the walk.
    if end > 0 {
        let _ = disk.read_bulk(0, &mut buf[..1]);
    }
    // And the last byte of the disk.
    if !disk.is_empty() {
        let _ = disk.read_at(disk.len() - 1, &mut buf[..1]);
    }
});
