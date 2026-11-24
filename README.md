# atlas-vhd

Opens Microsoft virtual hard disks as a `BlockSource`: VHD (fixed, dynamic and differencing) in `vhd`, and Hyper-V VHDX in `vhdx`. Block allocation tables are bounds-checked and unallocated blocks read as zeros, or from the parent disk of a differencing image.

- Both formats are read-only. The VHDX log is never replayed; `VhdxSource::has_log` tells a caller whether the file names one.
- No `unsafe`. Every length, offset and count read from the disk is checked; damage is an error, not a panic.

## Licence

Licensed under either of Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or MIT license
([LICENSE-MIT](LICENSE-MIT)) at your option.
