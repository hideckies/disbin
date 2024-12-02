use clap::{value_parser, Arg, ArgAction, Command};
use goblin::Object;
use std::path::PathBuf;

mod common;
mod elf;
mod pe;
mod utils;
use elf::ElfInfo;
use pe::PeInfo;

use crate::utils::convert::convert_option_string_to_option_usize;

fn main() -> Result<(), goblin::error::Error> {
    let app_name = env!("APP_NAME");
    let app_version = env!("APP_VERSION");
    let app_description = env!("APP_DESCRIPTION");
    let _app_homepage = env!("APP_HOMEPAGE");

    // Parse command-line arguments.
    let matches = Command::new(app_name)
        .version(app_version)
        .about(app_description)
        .args([
            // Positional arguments
            Arg::new("file")
                .value_parser(clap::value_parser!(PathBuf))
                .help("File path to analyze"),
            // General Options
            Arg::new("all-headers")
                .short('a')
                .long("all-headers")
                .help("Display all headers")
                .help_heading("General Options")
                .action(ArgAction::SetTrue),
            Arg::new("disasm")
                .short('d')
                .long("disasm")
                .help("Disassemble the binary")
                .help_heading("General Options")
                .action(ArgAction::SetTrue),
            Arg::new("hash")
                .short('H')
                .long("hash")
                .help("Display file hashes")
                .help_heading("General Options")
                .action(ArgAction::SetTrue),
            Arg::new("hex")
                .short('x')
                .long("hex")
                .help("Display Hex dump")
                .help_heading("General Options")
                .action(ArgAction::SetTrue),
            Arg::new("info")
                .short('i')
                .long("info")
                .help("Display file information")
                .help_heading("General Options")
                .action(ArgAction::SetTrue),
            Arg::new("sections")
                .short('s')
                .long("sections")
                .help("Display sections")
                .help_heading("General Options")
                .action(ArgAction::SetTrue),
            Arg::new("strings")
                .short('S')
                .long("strings")
                .help("Display strings")
                .help_heading("General Options")
                .action(ArgAction::SetTrue),
            // Elf Options
            Arg::new("dynamic")
                .long("dynamic")
                .help("Display Dynamic Section")
                .help_heading("Elf Options")
                .action(ArgAction::SetTrue),
            Arg::new("program-headers")
                .long("program-headers")
                .help("Display Program Headers")
                .help_heading("Elf Options")
                .action(ArgAction::SetTrue),
            Arg::new("symbols")
                .long("symbols")
                .help("Display symbol table")
                .help_heading("Elf Options")
                .action(ArgAction::SetTrue),
            Arg::new("version-info")
                .long("version-info")
                .help("Display Version information")
                .help_heading("Elf Options")
                .action(ArgAction::SetTrue),
            // PE Options
            Arg::new("coff-header")
                .long("coff-header")
                .help("Display COFF Header")
                .help_heading("PE Options")
                .action(ArgAction::SetTrue),
            Arg::new("debug-info")
                .long("debug-info")
                .help("Display Debug information")
                .help_heading("PE Options")
                .action(ArgAction::SetTrue),
            Arg::new("dos-header")
                .long("dos-header")
                .help("Display DOS Header")
                .help_heading("PE Options")
                .action(ArgAction::SetTrue),
            Arg::new("exceptions")
                .long("exceptions")
                .help("Display Exceptions")
                .help_heading("PE Options")
                .action(ArgAction::SetTrue),
            Arg::new("exports")
                .long("exports")
                .help("Display exported symbols in the binary")
                .help_heading("PE Options")
                .action(ArgAction::SetTrue),
            Arg::new("imports")
                .long("imports")
                .help("Display imported symbols from other DLLs")
                .help_heading("PE Options")
                .action(ArgAction::SetTrue),
            Arg::new("optional-header")
                .long("optional-header")
                .help("Display Optional Header")
                .help_heading("PE Options")
                .action(ArgAction::SetTrue),
            Arg::new("rich-header")
                .long("rich-header")
                .help("Display Rich Header")
                .help_heading("PE Options")
                .action(ArgAction::SetTrue),
            Arg::new("tls")
                .long("tls")
                .help("Display TLS information")
                .help_heading("PE Options")
                .action(ArgAction::SetTrue),
            // Parameters
            Arg::new("start")
                .long("start")
                .help("Position to start displaying")
                .help_heading("Parameters")
                .value_parser(value_parser!(String)),
            Arg::new("end")
                .long("end")
                .help("Position to finish displaying")
                .help_heading("Parameters")
                .value_parser(value_parser!(String)),

        ])
        .get_matches();

    let filepath = match matches.get_one::<PathBuf>("file") {
        Some(f) => f,
        None => {
            println!("[x] file path is not set. Run `disbin --help` for usage.");
            return Ok(());
        }
    };
    let flag_all_headers = matches.get_flag("all-headers");
    let flag_coff_header = matches.get_flag("coff-header");
    let flag_debug_info = matches.get_flag("debug-info");
    let flag_disasm = matches.get_flag("disasm");
    let flag_dos_header = matches.get_flag("dos-header");
    let flag_dynamic = matches.get_flag("dynamic");
    let flag_exceptions = matches.get_flag("exceptions");
    let flag_exports = matches.get_flag("exports");
    let flag_hash = matches.get_flag("hash");
    let flag_hex = matches.get_flag("hex");
    let flag_imports = matches.get_flag("imports");
    let flag_info = matches.get_flag("info");
    let flag_optional_header = matches.get_flag("optional-header");
    let flag_program_headers = matches.get_flag("program-headers");
    let flag_rich_header = matches.get_flag("rich-header");
    let flag_sections = matches.get_flag("sections");
    let flag_strings = matches.get_flag("strings");
    let flag_symbols = matches.get_flag("symbols");
    let flag_tls = matches.get_flag("tls");
    let flag_version_info = matches.get_flag("version-info");

    let param_start = matches.get_one::<String>("start").map(|v| v.to_string());
    let param_end = matches.get_one::<String>("end").map(|v| v.to_string());

    // Read file and parse object.
    let filebuf = match std::fs::read(filepath) {
        Ok(b) => b,
        Err(e) => {
            println!("[x] Error reading `{}`: {}", filepath.to_string_lossy(), e);
            return Ok(());
        }
    };
    let fileobj = match Object::parse(&filebuf) {
        Ok(o) => o,
        Err(e) => {
            println!("[x] Parse error for `{}`: {}", filepath.to_string_lossy(), e);
            return Err(e);
        },
    };
    match fileobj {
        Object::Archive(_archive) => {
            println!("[!] Archive files are not supported.");
        },
        Object::COFF(_coff) => {
            println!("[!] COFF files are not supported.");
        },
        Object::Elf(elf) => {
            let elf_info = ElfInfo::new(&filepath.to_string_lossy(), filebuf.clone(), elf);
            if flag_all_headers {
                elf_info.display_program_headers();
                elf_info.display_dynamic_section();
                elf_info.display_version_info();
                elf_info.display_section_headers();
                elf_info.display_symbol_table();
            } else if flag_coff_header {
                println!("[x] Elf does not have COFF Header.");
            } else if flag_debug_info {
                println!("[x] Elf does not have Debug information field.");
            } else if flag_disasm {
                elf_info.display_disasm(param_start, param_end);
            } else if flag_dos_header {
                println!("[x] Elf does not have DOS Header.");
            } else if flag_dynamic {
                elf_info.display_dynamic_section();
            } else if flag_exceptions {
                println!("[x] Elf does not have Exceptions field.");
            } else if flag_exports {
                println!("[x] Elf does not have Exports field.");
            } else if flag_hash {
                elf_info.display_hashes();
            } else if flag_hex {
                let param_start = convert_option_string_to_option_usize(param_start);
                let param_end = convert_option_string_to_option_usize(param_end);
                elf_info.display_hex(param_start, param_end);
            } else if flag_imports {
                println!("[x] Elf does not have Imports field.");
            } else if flag_info {
                elf_info.display_info();
            } else if flag_optional_header {
                println!("[x] Elf does not have Optional Header.");
            } else if flag_program_headers {
                elf_info.display_program_headers();
            } else if flag_rich_header {
                println!("[x] Elf does not have Rich Header.");
            } else if flag_sections {
                elf_info.display_section_headers();
            } else if flag_strings {
                elf_info.display_strings();   
            } else if flag_symbols {
                elf_info.display_symbol_table();
            } else if flag_tls {
                println!("[x] Elf does not have TLS field.");
            } else if flag_version_info {
                elf_info.display_version_info();
            } else {
                // Display by default
                elf_info.display_info();
            }
        },
        Object::Mach(_mach) => {
            println!("Mach-o files are not supported.");
        },
        Object::PE(pe) => {
            let pe_info = PeInfo::new(&filepath.to_string_lossy(), filebuf.clone(), pe);
            if flag_all_headers {
                pe_info.display_dos_header();
                pe_info.display_rich_header();
                pe_info.display_coff_header();
                pe_info.display_optional_header();
                pe_info.display_sections();
            } else if flag_coff_header {
                pe_info.display_coff_header();
            } else if flag_debug_info {
                pe_info.display_debug();
            } else if flag_disasm {
                pe_info.display_disasm(param_start, param_end);
            } else if flag_dos_header {
                pe_info.display_dos_header();
            } else if flag_dynamic {
                println!("[x] PE does not have Dynamic Section.");
            } else if flag_exceptions {
                pe_info.display_exceptions();
            } else if flag_exports {
                pe_info.display_exports();
            } else if flag_hash {
                pe_info.display_hashes();
            } else if flag_hex {
                let param_start = convert_option_string_to_option_usize(param_start);
                let param_end = convert_option_string_to_option_usize(param_end);
                pe_info.display_hex(param_start, param_end);
            } else if flag_imports {
                pe_info.display_imports();
            } else if flag_info {
                pe_info.display_info();
            } else if flag_optional_header {
                pe_info.display_optional_header();
            } else if flag_program_headers {
                println!("[x] PE does not have Program Headers.");
            } else if flag_rich_header {
                pe_info.display_rich_header();
            } else if flag_sections {
                pe_info.display_sections();
            } else if flag_strings {
                pe_info.display_strings();
            } else if flag_symbols {
                println!("[x] PE does not have Symbol Table field.");
            } else if flag_tls {
                pe_info.display_tls();
            } else if flag_version_info {
                println!("[x] PE does not have Version information.");
            } else {
                // Display by default
                pe_info.display_info();
            }
        },
        Object::Unknown(magic) => {
            println!("Unknown file type (magic: 0x{})", magic);
        },
        _ => {
            println!("Unknown file type");
        }
    }

    Ok(())
}
