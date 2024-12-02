use capstone::{
    arch::{
        x86::{
            ArchMode::Mode64,
            ArchSyntax::Intel,
        },
        BuildsCapstone, BuildsCapstoneSyntax,
    },
    Capstone,
};
use colored::Colorize;
use goblin::pe::PE;

use crate::utils::color::{
    highlight_mnemonic, highlight_operand, CUSTOM_COLOR_ORANGE,
};

pub fn display_pe_disasm(
    filebuf: &Vec<u8>,
    pe: &PE,
    start_section: Option<String>,
    end_section: Option<String>,
) {
    let cs = Capstone::new()
        .x86()
        .mode(Mode64)
        .syntax(Intel)
        .detail(true)
        .build()
        .unwrap();

    // Disassemble from start_section to end_section.
    let start_section = match start_section {
        Some(s) => s,
        None => ".text".to_string(),
    };
    let end_section = match end_section {
        Some(s) => s,
        None => ".text".to_string(),
    };

    let mut should_disasm = false;
    for section in pe.sections.iter() {
        // Get the section name.
        let section_name_tmp = String::from_utf8_lossy(&section.name);
        // Delete null-bytes at the end of the name.
        let section_name_cleaned_bytes: Vec<u8> = section_name_tmp.as_bytes().iter().cloned().filter(|&b| b != 0).collect();
        let section_name = match String::from_utf8(section_name_cleaned_bytes) {
            Ok(s) => s,
            Err(_) => "???".to_string(),
        };
        if section_name == start_section {
            should_disasm = true;
        }
        if !should_disasm {
            continue;
        }

        let section_start = section.pointer_to_raw_data as usize;
        let section_end = section_start + section.size_of_raw_data as usize;
        let section_data = &filebuf[section_start..section_end];

        let insns = cs.disasm_all(section_data, section_start as u64).unwrap();

        // Display section names for each section.
        println!("{}", format!("{}", section_name).custom_color(CUSTOM_COLOR_ORANGE));

        for insn in insns.iter() {
            // Address
            let insn_addr = format!("{:016X}", insn.address());
            print!("{}{} ", insn_addr.yellow(), ":".magenta());

            // Bytes
            for byte in insn.bytes() {
                // Colorize
                let color = match *byte {
                    0x00 => "green",
                    0x01..=0x4F => "blue",
                    0x50..=0x9F => "purple",
                    0xA0..=0xFF => "red",
                };
                print!("{}", format!("{:02X}", byte).color(color));
                print!(" ");
            }
            // Adjust spaces
            if insn.bytes().len() < 12 {
                for _ in 0..(12 - insn.bytes().len()) {
                    print!("   ");
                }
            }

            // Mnemonic
            let mnemonic = match insn.mnemonic() {
                Some(m) => highlight_mnemonic(m),
                None => "???".green().to_string(),
            };
            print!("{}\t", mnemonic);

            // Operand
            let insn_op = match insn.op_str() {
                Some(o) => highlight_operand(o),
                None => "???".green().to_string(),
            };
            print!("{}", insn_op);

            println!();
        }

        println!();

        // When reached the end_section, finish to disassemble.
        if section_name == end_section {
            break;
        }
    }
}