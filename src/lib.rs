// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Microsoft virtual hard disks.
//!
//! [`vhd`] reads `.vhd` files (fixed, dynamic and differencing) and [`vhdx`]
//! reads Hyper-V `.vhdx` files. Both present the disk as a `BlockSource`;
//! blocks that were never written read as zeros, or from the parent disk
//! of a differencing image.
//!
//! ```no_run
//! use std::path::Path;
//!
//! use atlas_fs_core::io::block::BlockSource;
//!
//! # fn main() -> Result<(), atlas_fs_core::error::Error> {
//! let vhd = atlas_vhd::vhd::open(Path::new("disk.vhd"))?;
//! let vhdx = atlas_vhd::vhdx::open(Path::new("disk.vhdx"))?;
//! println!("{} and {} bytes of disk", vhd.len(), vhdx.len());
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
// On-disk bytes are hostile. These lints make the usual ways of trusting
// them (unchecked indexing, arithmetic and casts, panicking shortcuts) fail
// the clippy gate. Unit tests and the test fixtures are exempt.
#![warn(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::unwrap_used
)]
#![cfg_attr(
    test,
    allow(
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used
    )
)]

pub mod vhd;
pub mod vhdx;
