use goblin::elf::Elf;
use std::fs::metadata;
use termimad::minimad::TextTemplate;

use crate::utils::{entropy::calc_entropy, style::init_skin};

pub fn display_elf_info(filepath: &str, filebuf: &Vec<u8>, elf: &Elf) {
    let i_filesize = match metadata(filepath) {
        Ok(meta) => format!("0x{:X}", meta.len()),
        Err(_) => "???".to_string(),
    };
    let i_magic = format!("0x{}", elf.header.e_ident[0..4]
        .iter()
        .map(|&x| format!("{:X}", x))
        .collect::<Vec<String>>()
        .join(""));
    let i_type = if elf.is_lib {
        "Elf shared object".to_string()
    } else {
        "Elf executable".to_string()
    };
    let i_class = if elf.is_64 {
        "64-bit".to_string()
    } else {
        "32-bit".to_string()
    };
    let i_endian = if elf.little_endian {
        "Little-endian (LSB)".to_string()
    } else {
        "Big-endian (MSB)".to_string()
    };
    // let i_version = get_version_str(self.fileobj.header.e_ident[6] as u32).to_string();
    let i_version = if elf.header.e_ident[6] == 0 {
        "Invalid Version"
    } else if elf.header.e_ident[6] == 1 {
        "Current Version"
    } else {
        "???"
    };
    // let i_osabi = get_osabi_str(self.fileobj.header.e_ident[7]).to_string();
    let i_osabi = match elf.header.e_ident[7] {
        0x00 => "System V",
        0x01 => "HP-UX",
        0x02 => "NetBSD",
        0x03 => "Linux",
        0x04 => "GNU Hard",
        0x06 => "Solaris",
        0x07 => "AIX",
        0x08 => "IRIX",
        0x09 => "FreeBSD",
        0x0A => "Tru64",
        0x0B => "Novell Modesto",
        0x0C => "OpenBSD",
        0x0D => "OpenVMS",
        0x0E => "NonStop Kernel",
        0x0F => "AROS",
        0x10 => "FenixOS",
        0x11 => "Nuxi CloudABI",
        0x12 => "Stratus Technologies OpenVOS",
        _ => "???",
    };
    // let i_machine = get_machine_str(self.fileobj.header.e_machine).to_string();
    let i_arch = match elf.header.e_machine {
        0x00 => "No specific instruction set",
        0x01 => "AT&T WE 32100",
        0x02 => "SPARC",
        0x03 => "x86",
        0x04 => "Motorola 68000",
        0x05 => "Motorola 88000",
        0x07 => "Intel 80860",
        0x08 => "MIPS I Architecture",
        0x09 => "IBM System/370 Processor",
        0x0A => "PowerPC",
        0x0F => "Hewlett-Packard PA-RISC",
        0x13 => "Intel 80960",
        0x14 => "PowerPC",
        0x15 => "PowerPC (64-bit)",
        0x16 => "S390, S390x",
        0x20 => "NEC v800",
        0x28 => "Arm",
        0x3E => "AMD x86-64",
        0x64 => "Arm 64-bits (Armv8/AArch64)",
        0xDC => "Zilog Z80",
        0xF3 => "RISC-V",
        _ => "???",
    };
    let i_entry = format!("0x{:X}", elf.entry).to_string();
    let i_phoff = format!("0x{:X}", elf.header.e_phoff);
    let i_shoff = format!("0x{:X}", elf.header.e_shoff);
    let i_flags= format!("0x{:X}", elf.header.e_flags);
    let i_ehsize = format!("0x{:X}", elf.header.e_ehsize);
    let i_phentsize = format!("0x{:X}", elf.header.e_phentsize);
    let i_phnum = format!("0x{:X}", elf.header.e_phnum);
    let i_shentsize = format!("0x{:X}", elf.header.e_shentsize);
    let i_shnum = format!("0x{:X}", elf.header.e_shnum);
    let i_shstrndx = format!("0x{:X}", elf.header.e_shstrndx);

    let i_entropy = format!("{}", calc_entropy(filebuf));

    let text_template = TextTemplate::from(r#"
# File Information
|:-|:-|
|**File Path**|`${filepath}`|
|-
|**File Size**|${filesize}|
|-
|**Magic**|${magic}|
|-
|**Type**|${type}|
|-
|**Class**|${class}|
|-
|**Data Encoding**|${endian}|
|-
|**Version**|${version}|
|-
|**OS/ABI**|${osabi}|
|-
|**Architecture**|${arch}|
|-
|**Entry Point Address**|${entry}|
|-
|**Program Headers Offset**|${phoff}|
|-
|**Section Headers Offset**|${shoff}|
|-
|**Flags**|${flags}|
|-
|**Size of This Header**|${ehsize}|
|-
|**Size of Program Headers**|${phentsize}|
|-
|**Number of Program Headers**|${phnum}|
|
|**Size of Section Headers**|${shentsize}|
|-
|**Number of Section Headers**|${shnum}|
|-
|**Section Header String Table Index**|${shstrndx}|
|-
|**Entropy**|${entropy}|
|-
"#);

    let mut expander = text_template.expander();
    expander
        // File Information
        .set("filepath", filepath)
        .set("filesize", &i_filesize)
        .set("magic", &i_magic)
        .set("type", &i_type)
        .set("class", &i_class)
        .set("endian", &i_endian)
        .set("version", &i_version)
        .set("osabi", &i_osabi)
        .set("arch", &i_arch)
        .set("entry", &i_entry)
        .set("phoff", &i_phoff)
        .set("shoff", &i_shoff)
        .set("flags", &i_flags)
        .set("ehsize", &i_ehsize)
        .set("phentsize", &i_phentsize)
        .set("phnum", &i_phnum)
        .set("shentsize", &i_shentsize)
        .set("shnum", &i_shnum)
        .set("shstrndx", &i_shstrndx)
        .set("entropy", &i_entropy);

    let skin = init_skin();
    println!();
    skin.print_expander(expander);
    println!();
}
