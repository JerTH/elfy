# Elfy
![Build Status](https://travis-ci.org/JerTH/elfy.svg?branch=master)
![Docs](https://docs.rs/elfy/badge.svg)

[Documentation](https://docs.rs/elfy)

[Crates.io](https://crates.io/crates/elfy)

#### Description
Elfy is for loading and parsing [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) files. The project began as a simple binary loader for an ARMv7-M virtual machine, but quickly evolved into its own standalone crate. The goal of Elfy is to provide a simple and ergonomic interface for working with ELF files of all types.

Elfy is currently focused on reading data important to statically compiled ARM executables, in the future it will support more architectures and ELF features.

#### Usage
To use Elfy, first add it as a dependency in your projects `Cargo.toml`
```toml
[dependencies]
elfy = "0.1.7"
```

To load an ELF file, include Elfy as an external crate. Loading an ELF file from disk and parsing it is now as simple as calling `Elf::load(path)` where `path` is any valid `std::path::Path` to an ELF file. If the file doesn't exist, the file isn't valid ELF, or there is a problem parsing the file then `load()` will return `Err(ParseElfError)` with a description of what went wrong.
```rust
extern crate elfy;
use elfy::Elf;

fn main() {
    let elf = Elf::load("examples/example-binary").expect("Something went wrong!");

    // ...
}
```

Data inside of a loaded ELF file can be accessed using `Elf::try_get_section(&self, section_name) -> Option<&Section>`. If the section exists `Some(&Section)` will be returned, otherwise `None`.

The parsed data within a section can be accessed using `Section::data(&self) -> &SectionData`. The `SectionData` type is an enum representing the different formats of data that may be contained within an ELF file.
```rust
use elfy::{ Section, SectionData, SectionType, SectionFlags };

fn main() {
    // ...
    
    let text_section = elf.try_get_section(".text").expect("The section doesn't exist!");
    let header = text_section.header();


    // The .text section usually contains executable machine code and as such will be
    // parsed as raw binary data. Here we retrieve a vector of that data in `bytes` 
    if let SectionData::Bytes(bytes) = text_section.data() {
        // ...
    }

    // Sections containing executable code are of type `ProgramData`, and
    // are flagged as Alloc and Execute, meaning they take up space in a program
    // image and have execution permissions
    assert_eq!(SectionType::ProgramData, header.ty);
    assert_eq!(SectionFlags::AllocExecute, header.flags);
}
```
