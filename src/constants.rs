use crate::primitives::*;

/**
 * Various constants defined by both the ELF standard as well as various machine vendors used to parse ELF files
 */

pub const MAGIC_BYTES: [u8; 4] = [0x7F, 0x45, 0x4C, 0x46];
pub const SHN_UNDEF: Short = Short(0);

