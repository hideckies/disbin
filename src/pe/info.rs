use goblin::pe::PE;
use std::fs::metadata;
use termimad::minimad::TextTemplate;

use crate::utils::style::init_skin;

fn get_characteristics(characteristics: u16) -> Vec<&'static str> {
    let mut flags = Vec::new();
    if characteristics & 0x0001 != 0 {
        flags.push("RELOCS_STRIPPED");
    }
    if characteristics & 0x0002 != 0 {
        flags.push("EXECUTABLE");
    }
    if characteristics & 0x0004 != 0 {
        flags.push("LINE_NUMS_STRIPPED");
    }
    if characteristics & 0x0008 != 0 {
        flags.push("LOCAL_SYMS_STRIPPED");
    }
    if characteristics & 0x0010 != 0 {
        flags.push("AGGRESSIVE_WS_TRIM");
    }
    if characteristics & 0x0020 != 0 {
        flags.push("LARGE_ADDRESS_AWARE");
    }
    if characteristics & 0x0080 != 0 {
        flags.push("BYTES_REVERSED_LO");
    }
    if characteristics & 0x0100 != 0 {
        flags.push("32BIT_MACHINE");
    }
    if characteristics & 0x0200 != 0 {
        flags.push("DEBUG_STRIPPED");
    }
    if characteristics & 0x0400 != 0 {
        flags.push("REMOVABLE_RUN_FROM_SWAP");
    }
    if characteristics & 0x0800 != 0 {
        flags.push("NET_RUN_FROM_SWAP");
    }
    if characteristics & 0x1000 != 0 {
        flags.push("SYSTEM");
    }
    if characteristics & 0x2000 != 0 {
        flags.push("DLL");
    }
    if characteristics & 0x4000 != 0 {
        flags.push("UP_SYSTEM_ONLY");
    }
    if characteristics & 0x8000 != 0 {
        flags.push("BYTES_REVERSED_HI");
    }
    flags
}

fn get_dll_characteristics(characteristic: u16) -> Vec<&'static str> {
    let mut flags = Vec::new();
    if characteristic & 0x0020 != 0 {
        flags.push("HIGH_ENTROPY_VA");
    }
    if characteristic & 0x0040 != 0 {
        flags.push("DYNAMIC_BASE");
    }
    if characteristic & 0x0080 != 0 {
        flags.push("FORCE_INTEGRITY");
    }
    if characteristic & 0x0100 != 0 {
        flags.push("NX_COMPAT");
    }
    if characteristic & 0x0200 != 0 {
        flags.push("NO_ISOLATION");
    }
    if characteristic & 0x0400 != 0 {
        flags.push("NO_SEH");
    }
    if characteristic & 0x0800 != 0 {
        flags.push("NO_BIND");
    }
    if characteristic & 0x1000 != 0 {
        flags.push("APPCONTAINER");
    }
    if characteristic & 0x2000 != 0 {
        flags.push("WDM_DRIVER");
    }
    if characteristic & 0x4000 != 0 {
        flags.push("GUARD_CF");
    }
    if characteristic & 0x8000 != 0 {
        flags.push("TERMINAL_SERVER_AWARE");
    }
    flags
}

pub fn display_pe_info(filepath: &str, pe: &PE) {
    let i_filesize = match metadata(filepath) {
        Ok(meta) => format!("0x{:X}", meta.len()),
        Err(_) => "???".to_string(),
    };
    let i_type = if pe.is_64 {
        if pe.is_lib {
            "PE32+ executable (DLL)".to_string()
        } else {
            "PE32+ executable".to_string()
        }
    } else {
        if pe.is_lib {
            "PE32 executable (DLL)".to_string()
        } else {
            "PE32 executable".to_string()
        }
    };

    // Optional header
    let mut i_magic = "???".to_string();
    let mut i_entry = "???".to_string();
    let mut i_image_base = "???".to_string();
    let mut i_section_alignment = "???".to_string();
    let mut i_file_alignment = "???".to_string();
    let mut i_subsystem = "???".to_string();
    let mut i_dll_characteristics = "???".to_string();

    if let Some(optional_header) = pe.header.optional_header {
        i_magic = match optional_header.standard_fields.magic {
            0x10b => "0x10b (PE32)".to_string(),
            0x20b => "0x20b (PE32+)".to_string(),
            _ => "???".to_string(),
        };
        i_entry = format!("0x{:X}", optional_header.standard_fields.address_of_entry_point);
        i_image_base = format!("0x{:X}", optional_header.windows_fields.image_base);
        i_section_alignment = format!("0x{:X}", optional_header.windows_fields.section_alignment);
        i_file_alignment = format!("0x{:X}", optional_header.windows_fields.file_alignment);
        i_subsystem = match optional_header.windows_fields.subsystem {
            0 => "???".to_string(),
            1 => "Native".to_string(),
            2 => "Windows GUI".to_string(),
            3 => "Windows CUI".to_string(),
            5 => "OS/2 CUI".to_string(),
            7 => "POSIX CUI".to_string(),
            8 => "Native Win9x driver".to_string(),
            9 => "Windows CE".to_string(),
            10 => "EFI application".to_string(),
            11 => "EFI boot service driver".to_string(),
            12 => "EFI runtime driver".to_string(),
            13 => "EFI ROM".to_string(),
            14 => "XBOX".to_string(),
            16 => "Windows boot application".to_string(),
            _ => "???".to_string(),
        };
        i_dll_characteristics = get_dll_characteristics(optional_header.windows_fields.dll_characteristics)
            .iter()
            .map(|&x| x)
            .collect::<Vec<&str>>()
            .join(" ");
    }

    // COFF header
    let i_machine = match pe.header.coff_header.machine {
        0x0000 => "???",
        0x014c => "Intel 386",
        0x0166 => "MIPS",
        0x01c0 => "ARM",
        0x01c4 => "ARM Thumb-2",
        0x01f0 => "PowerPC",
        0x01f1 => "PowerPC with floating point support",
        0x0200 => "Intel Itanium",
        0x0266 => "MIPS16",
        0x0366 => "MIPS with FPU",
        0x0466 => "MIPS16 with FPU",
        0x5032 => "RISC-V 32-bit",
        0x5064 => "RISC-V 64-bit",
        0x5128 => "RISC-V 128-bit",
        0x8664 => "x64",
        0xaa64 => "ARM64",
        _ => "???",
    };
    let i_num_of_sections = format!("0x{:X}", pe.header.coff_header.number_of_sections);
    let i_num_of_symtab = format!("0x{:X}", pe.header.coff_header.number_of_symbol_table);
    let i_timestamp = format!("0x{:X}", pe.header.coff_header.time_date_stamp);
    let i_characteristics = get_characteristics(pe.header.coff_header.characteristics)
        .iter()
        .map(|&x| x)
        .collect::<Vec<&str>>()
        .join(" ");

    let text_template = TextTemplate::from(r#"
# File Information
|:-|:-|
|**File Path**|${filepath}|
|-
|**File Size**|${filesize}|
|-
|**Magic**|${magic}|
|-
|**Type**|${type}|
|-
|**Subsystem**|${subsystem}|
|-
|**Machine**|${machine}|
|-
|**Entry Point**|${entry}|
|-
|**Image Base**|${image_base}|
|
|**Section Alignment**|${section_alignment}|
|-
|**File Alignment**|${file_alignment}|
|-
|**Number of Sections**|${num_of_sections}|
|-
|**Number of Symbol Table**|${num_of_symtab}|
|
|**Timestamp**|${timestamp}|
|-
|**Characteristics**|${characteristics}|
|-
|**DLL Characteristics**|${dll_characteristics}|
|-
    "#);

    let mut expander = text_template.expander();
    expander
        .set("filepath", &filepath)
        .set("filesize", &i_filesize)
        .set("magic", &i_magic)
        .set("type", &i_type)
        .set("subsystem", &i_subsystem)
        .set("machine", &i_machine)
        .set("entry", &i_entry)
        .set("image_base", &i_image_base)
        .set("section_alignment", &i_section_alignment)
        .set("file_alignment", &i_file_alignment)
        .set("num_of_sections", &i_num_of_sections)
        .set("num_of_symtab", &i_num_of_symtab)
        .set("timestamp", &i_timestamp)
        .set("characteristics", &i_characteristics)
        .set("dll_characteristics", &i_dll_characteristics);

        let skin = init_skin();
        println!();
        skin.print_expander(expander);
        println!();
}