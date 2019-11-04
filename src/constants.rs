use crate::primitives::*;

/**
 * Various constants defined by both the ELF standard or individual machine vendors used to parse ELF files
 */

pub const MAGIC_BYTES: [u8; 4] = [0x7F, 0x45, 0x4C, 0x46];
pub const SHN_UNDEF: Short = Short(0);

pub const MACHINE_NONE: u16 = 0x0000;
pub const MACHINE_ARM: u16 = 0x0028;
pub const MACHINE_ATMELAVR: u16 = 0x0054;
pub const MACHINE_AMD64: u16 = 0x003E;
pub const MACHINE_ST200: u16 = 0x0064;
pub const MACHINE_RISCV: u16 = 0x00F3;

pub mod section_types {
    pub const NULL: u32 = 0x00;
    pub const PROG_DATA: u32 = 0x01;
    pub const SYM_TABLE: u32 = 0x02;
    pub const STR_TABLE: u32 = 0x03;
    pub const REL_A: u32 = 0x04;
    pub const SYM_HASH: u32 = 0x05;
    pub const DYN_INFO: u32 = 0x06;
    pub const NOTE: u32 = 0x07;
    pub const NO_BITS: u32 = 0x08;
    pub const RELOCATION: u32 = 0x09;
    pub const SHLIB: u32 = 0x0A;
    pub const DYN_SYM_TAB: u32 = 0x0B;
    pub const INIT: u32 = 0x0E;
    pub const FINI: u32 = 0x0F;
    pub const PRE_INIT: u32 = 0x10;
    pub const GROUP: u32 = 0x11;
    pub const EXT_IDX: u32 = 0x12;
}
