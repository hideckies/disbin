use goblin::elf::Elf;
use std::collections::HashMap;
use termimad::minimad::TextTemplate;

use crate::utils::{math::find_exponent_of_two, style::init_skin};

pub fn display_elf_program_headers(elf: &Elf) {
    let mut phs: Vec<HashMap<String, String>> = Vec::new();
    
    for ph in elf.program_headers.iter() {
        let mut phmap: HashMap<String, String> = HashMap::new();
        phmap.insert("name".to_string(), match ph.p_type {
            0x00000000 => "NULL".to_string(),
            0x00000001 => "LOAD".to_string(),
            0x00000002 => "DYNAMIC".to_string(),
            0x00000003 => "INTERP".to_string(),
            0x00000004 => "NOTE".to_string(),
            0x00000005 => "SHLIB".to_string(),
            0x00000006 => "PHDR".to_string(),
            0x00000007 => "TLS".to_string(),
            0x60000000 => "LOOS".to_string(),
            0x6FFFFFFF => "HIOS".to_string(),
            0x70000000 => "LOPROC".to_string(),
            0x7FFFFFFF => "HIPROC".to_string(),
            _ => format!("0x{:X}", ph.p_type),
        });
        phmap.insert("offset".to_string(), format!("0x{:016X}", ph.p_offset));
        phmap.insert("vaddr".to_string(), format!("0x{:016X}", ph.p_vaddr));
        phmap.insert("paddr".to_string(), format!("0x{:016X}", ph.p_paddr));
        phmap.insert("align".to_string(), if let Some(exponent) = find_exponent_of_two(ph.p_align) {
            format!("2**{}", exponent)
        } else {
            "???".to_string()
        });
        phmap.insert("filesz".to_string(), format!("0x{:016X}", ph.p_filesz));
        phmap.insert("memsz".to_string(), format!("0x{:016X}", ph.p_memsz));
        phmap.insert("flags".to_string(), match ph.p_flags {
            0x1 => "--x".to_string(),
            0x2 => "-w-".to_string(),
            0x3 => "-wx".to_string(),
            0x4 => "r--".to_string(),
            0x5 => "r-x".to_string(),
            0x6 => "rw-".to_string(),
            0x7 => "rwx".to_string(),
            _ => "---".to_string(),

        });

        phs.push(phmap);
    }

    let text_template = TextTemplate::from(r#"
# Program Headers
${rows
|:-|:-|:-|:-|:-|
|**${name}**|**offset**|**vaddr**|**paddr**|**align**|
||${offset}|${vaddr}|${paddr}|${align}
|:-|:-|:-|:-|:-|
||**filesz**|**memsz**||**flags**|
||${filesz}|${memsz}||${flags}|
}
|-
    "#);

    let mut expander = text_template.expander();
    for ph in phs.iter() {
        expander.sub("rows")
            .set("name", &ph.get("name").unwrap())
            .set("offset", &ph.get("offset").unwrap())
            .set("vaddr", &ph.get("vaddr").unwrap())
            .set("paddr", &ph.get("paddr").unwrap())
            .set("align", &ph.get("align").unwrap())
            .set("filesz", &ph.get("filesz").unwrap())
            .set("memsz", &ph.get("memsz").unwrap())
            .set("flags", &ph.get("flags").unwrap());
    }

    let skin = init_skin();
    println!();
    skin.print_expander(expander);
    println!();
}

fn get_flags(flags: u64) -> Vec<&'static str> {
    let mut f = Vec::new();
    if flags & 0x1 != 0 {
        f.push("WRITE");
    }
    if flags & 0x2 != 0 {
        f.push("ALLOC");
    }
    if flags & 0x4 != 0 {
        f.push("EXECINSTR");
    }
    if flags & 0x10 != 0 {
        f.push("MERGE");
    }
    if flags & 0x20 != 0 {
        f.push("STRINGS");
    }
    if flags & 0x40 != 0 {
        f.push("INFO_LINK");
    }
    if flags & 0x80 != 0 {
        f.push("LINK_ORDER");
    }
    if flags & 0x100 != 0 {
        f.push("OS_NONCONFORMING");
    }
    if flags & 0x200 != 0 {
        f.push("GROUP");
    }
    if flags & 0x400 != 0 {
        f.push("TLS");
    }
    if flags & 0x0FF00000 != 0 {
        f.push("MASKOS"); // OS specific
    }
    if flags & 0xF0000000 != 0 {
        f.push("MASKPROC"); // Processor specific
    }
    if flags & 0x4000000 != 0 {
        f.push("ORDERED"); // Special ordering requirement (Solaris)
    }
    if flags & 0x8000000 != 0 {
        f.push("EXCLUDE"); // Section is excluded unless referenced or allocated
    }
    f
}

pub fn display_elf_section_headers(elf: &Elf) {
    let mut shs: Vec<HashMap<String, String>> = Vec::new();

    let mut idx: usize = 0;
    for sh in elf.section_headers.iter() {
        if sh.sh_name == 0 {
            continue;
        }

        let mut shmap: HashMap<String, String> = HashMap::new();

        shmap.insert("idx".to_string(), idx.to_string());
        shmap.insert("name".to_string(), if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            name.to_string()
        } else {
            "???".to_string()
        });
        shmap.insert("addr".to_string(), format!("0x{:016x}", sh.sh_addr));
        shmap.insert("offset".to_string(), format!("0x{:08x}", sh.sh_offset));
        shmap.insert("size".to_string(), format!("0x{:X}", sh.sh_size));
        shmap.insert("type".to_string(), match sh.sh_type {
            0x00 => "NULL".to_string(),
            0x01 => "PROGBITS".to_string(),
            0x02 => "SYMTAB".to_string(),
            0x03 => "STRTAB".to_string(),
            0x04 => "RELA".to_string(),
            0x05 => "HASH".to_string(),
            0x06 => "DYNAMIC".to_string(),
            0x07 => "NOTE".to_string(),
            0x08 => "NOBITS".to_string(),
            0x09 => "REL".to_string(),
            0x0A => "SHLIB".to_string(),
            0x0B => "DYNSYM".to_string(),
            0x0E => "INIT_ARRAY".to_string(),
            0x0F => "FINI_ARRAY".to_string(),
            0x10 => "PREINIT_ARRAY".to_string(),
            0x11 => "GROUP".to_string(),
            0x12 => "SYMTAB_SHNDX".to_string(),
            0x13 => "NUM".to_string(),
            0x60000000 => "LOOS".to_string(),
            _ => "???".to_string(),
        });
        shmap.insert(
            "flags".to_string(),
            get_flags(sh.sh_flags)
                .iter()
                .map(|&x| x)
                .collect::<Vec<&str>>()
                .join(", "),
        );
        shmap.insert("align".to_string(), if let Some(exponent) = find_exponent_of_two(sh.sh_addralign) {
            format!("2**{}", exponent)
        } else {
            "???".to_string()
        });

        shs.push(shmap);

        idx += 1;
    }

    let text_template = TextTemplate::from(r#"
# Sections
|:-|:-|:-|:-|:-|:-|:-|:-|
|**Idx**|**Name**|**Addr**|**Offset**|**Size**|**Type**|**Flags**|**Align**|
${rows
|:-|:-|:-|:-|-:|:-|:-|
|${idx}|${name}|${addr}|${offset}|${size}|${type}|${flags}|${align}|
}
|-
    "#);

    let mut expander = text_template.expander();
    for sh in shs.iter() {
        expander.sub("rows")
            .set("idx", &sh.get("idx").unwrap())
            .set("name", &sh.get("name").unwrap())
            .set("addr", &sh.get("addr").unwrap())
            .set("offset", &sh.get("offset").unwrap())
            .set("type", &sh.get("type").unwrap())
            .set("size", &sh.get("size").unwrap())
            .set("flags", &sh.get("flags").unwrap())
            .set("align", &sh.get("align").unwrap());
    }

    let skin = init_skin();
    println!();
    skin.print_expander(expander);
    println!();
}

pub fn display_elf_symbol_table(elf: &Elf) {
    if elf.syms.len() == 0 {
        let text_template = TextTemplate::from(r#"
# Symbol Table

no symbols
        "#);
        let expander = text_template.expander();
        let skin = init_skin();
        println!();
        skin.print_expander(expander);
        println!();
        return;
    }

    // If symbols exist...
    let mut symbols: Vec<HashMap<String, String>> = Vec::new();
    for sym in elf.syms.iter() {
        let mut symmap: HashMap<String, String> = HashMap::new();

        let addr = format!("0x{:016X}", sym.st_value);
        let bind = match sym.st_bind() {
            goblin::elf::sym::STB_LOCAL => "LOCAL",
            goblin::elf::sym::STB_GLOBAL => "GLOBAL",
            goblin::elf::sym::STB_WEAK => "WEAK",
            goblin::elf::sym::STB_NUM => "NUM",
            goblin::elf::sym::STB_LOOS..=goblin::elf::sym::STB_HIOS => "OS-SPEC",
            goblin::elf::sym::STB_LOPROC..=goblin::elf::sym::STB_HIPROC => "PROC-SPEC",
            _ => "UNKNOWN",
        };
        let sym_type = match sym.st_type() {
            goblin::elf::sym::STT_NOTYPE => "NOTYPE",
            goblin::elf::sym::STT_OBJECT => "OBJECT",
            goblin::elf::sym::STT_FUNC => "FUNC",
            goblin::elf::sym::STT_SECTION => "SECTION",
            goblin::elf::sym::STT_FILE => "FILE",
            goblin::elf::sym::STT_COMMON => "COMMON",
            goblin::elf::sym::STT_TLS => "TLS",
            goblin::elf::sym::STT_GNU_IFUNC => "IFUNC",
            _ => "UNKNOWN",
        };
        let section_name = match sym.st_shndx as u32 {
            goblin::elf::section_header::SHN_UNDEF => "*UND*",
            goblin::elf::section_header::SHN_ABS => "*ABS*",
            goblin::elf::section_header::SHN_COMMON => "*COM*",
            goblin::elf::section_header::SHN_LORESERVE..=goblin::elf::section_header::SHN_HIRESERVE => "RESERVED",
            idx  if idx < elf.section_headers.len() as u32 => {
                elf.shdr_strtab
                    .get_at(elf.section_headers[idx as usize].sh_name)
                    .unwrap_or("")
            },
            _ => "UNKNOWN",
        };
        let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
        let size = format!("0x{:X}", sym.st_size);

        symmap.insert("addr".to_string(), addr);
        symmap.insert("bind".to_string(), bind.to_string());
        symmap.insert("type".to_string(), sym_type.to_string());
        symmap.insert("section_name".to_string(), section_name.to_string());
        symmap.insert("name".to_string(), name.to_string());
        symmap.insert("size".to_string(), size);
        
        symbols.push(symmap);
    }

    let text_template = TextTemplate::from(r#"
# Symbol Table
|:-|:-|:-|:-|
|**Addr**|**Bind**|**Type**|**Section**|**Name**|**Size**|
${rows
|:-|:-|:-|::-|:-|
|${addr}|${bind}|${type}|${section_name}|${name}|${size}|
}
|-
    "#);
    let mut expander = text_template.expander();
    for sym in symbols.iter() {
        expander.sub("rows")
            .set("addr", sym.get("addr").unwrap())
            .set("bind", sym.get("bind").unwrap())
            .set("type", sym.get("type").unwrap())
            .set("section_name", sym.get("section_name").unwrap())
            .set("name", sym.get("name").unwrap())
            .set("size", sym.get("size").unwrap());
    }
    let skin = init_skin();
    println!();
    skin.print_expander(expander);
    println!();
}