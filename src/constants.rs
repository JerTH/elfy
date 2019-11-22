//! Constants defined by the ELF standard and vendors
//! 
//! The ELF standard uses many standard defined and vendor defined constants
//! to describe the contents of an ELF file. These constants are listed
//! here grouped in modules for clarity and correctness
//! 
//! These constants should not be modified, as they are critical to the correct
//! interpretation of ELF file data.

#![allow(missing_docs)]

use crate::numeric::*;

pub const CURRENT_IDENT_VERSION: u8 = 0x01;
pub const CURRENT_ELF_VERSION: u32 = 0x01;

pub const MAGIC_BYTES: [u8; 4] = [0x7F, 0x45, 0x4C, 0x46];
pub const SHN_UNDEF: Short = Short(0);

pub mod machines {
    pub const NONE: u16 = 0x0000;
    pub const ARM: u16 = 0x0028;
    pub const ATMELAVR: u16 = 0x0054;
    pub const AMD64: u16 = 0x003E;
    pub const ST200: u16 = 0x0064;
    pub const RISCV: u16 = 0x00F3;
}

pub mod data_formats {
    pub const LITTLE_ENDIAN: u8 = 0x01;
    pub const BIG_ENDIAN: u8 = 0x02;
}

pub mod data_classes {
    pub const ELF32: u8 = 0x01;
    pub const ELF64: u8 = 0x02;
}

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

pub mod program_flags {
    pub const READ: u32 = 0b100;
    pub const WRITE: u32 = 0b010;
    pub const EXEC: u32 = 0b001;
    pub const READ_WRITE: u32 = 0b110;
    pub const READ_EXEC: u32 = 0b101;
    pub const READ_WRITE_EXEC: u32 = 0b111;
}

pub mod section_flags {
    pub const NONE: u64 = 0b000;
    pub const WRITE: u64 = 0b001;
    pub const ALLOC: u64 = 0b010;
    pub const EXEC: u64 = 0b100;
    pub const WRITE_ALLOC: u64 = 0b011;
    pub const WRITE_EXEC: u64 = 0b101;
    pub const ALLOC_EXEC: u64 = 0b110;
    pub const WRITE_ALLOC_EXEC: u64 = 0b111;
}

pub mod elf_types {
    pub const NONE: u16 = 0x000;
    pub const RELOCATABLE: u16 = 0x001;
    pub const EXECUTABLE: u16 = 0x002;
    pub const SHARED: u16 = 0x003;
    pub const CORE: u16 = 0x004;
    pub const LO_PROC: u16 = 0xFF00;
    pub const HI_PROC: u16 = 0xFFFF;
}

pub mod abi_versions {
    pub const UNSPECIFIED: u8 = 0x00;
}

pub mod os_abis {
    pub const UNIX_SYSTEM_V: u8 = 0x00;
}

pub mod processor_specific_header_types {
    pub const ARM_EXIDX: u32 = 0x70000001;
}

pub mod os_specific_header_types {
    pub const GNU_STACK: u32 = 0x6474E551;
}
