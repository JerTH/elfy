use crate::primitives::*;

/**
 * Various constants defined by both the ELF standard as well as various machine vendors used to parse ELF files
 */

pub const MAGIC_BYTES: [u8; 4] = [0x7F, 0x45, 0x4C, 0x46];
pub const SHN_UNDEF: Short = Short(0);

pub const MACHINE_NONE: u16 = 0x0000;
pub const MACHINE_ARM: u16 = 0x0028;
pub const MACHINE_ATMELAVR: u16 = 0x0054;
pub const MACHINE_AMD64: u16 = 0x003E;
pub const MACHINE_ST200: u16 = 0x0064;
pub const MACHINE_RISCV: u16 = 0x00F3;
