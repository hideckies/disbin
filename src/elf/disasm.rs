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
use goblin::elf::Elf;

use crate::utils::color::{
    highlight_mnemonic, highlight_operand, CUSTOM_COLOR_ORANGE,
};

pub fn display_elf_disasm(
    filebuf: &Vec<u8>,
    elf: &Elf,
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
        None => ".init".to_string(),
    };
    let end_section = match end_section {
        Some(s) => s,
        None => ".fini".to_string(),
    };

    let mut should_disasm = false;
    for section in elf.section_headers.iter() {
        let section_name = match elf.shdr_strtab.get_at(section.sh_name) {
            Some(n) => n.to_string(),
            None => "???".to_string(),
        };
        if section_name == start_section {
            should_disasm = true;
        }
        if !should_disasm {
            continue;
        }

        let section_start = section.sh_offset as usize;
        let section_end = (section.sh_offset + section.sh_size) as usize;
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