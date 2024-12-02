use goblin::elf::Elf;

mod disasm;
mod dynamic;
mod headers;
mod info;
mod strings;
mod version;

use crate::{
    common::{hashes::display_common_hashes, hex::display_hex},
    elf::{
        disasm::display_elf_disasm,
        dynamic::display_elf_dynamic_section,
        headers::{
            display_elf_program_headers,
            display_elf_section_headers,
            display_elf_symbol_table,
        },
        info::display_elf_info,
        strings::display_elf_strings,
        version::display_elf_version_info,
    },
};

pub struct ElfInfo<'a> {
    pub filepath: String,
    pub filebuf: Vec<u8>,
    pub fileobj: Elf<'a>,
}

impl<'a> ElfInfo<'a> {
    pub fn new(filepath: &str, filebuf: Vec<u8>, elf: Elf<'a>) -> Self {
        Self {
            filepath: filepath.to_string(),
            filebuf,
            fileobj: elf,
        }
    }

    pub fn display_info(&self) {
        display_elf_info(&self.filepath, &self.fileobj);
    }

    pub fn display_hashes(&self) {
        display_common_hashes(&self.filebuf);
    }

    pub fn display_strings(&self) {
        display_elf_strings(&self.filebuf, &self.fileobj);
    }

    pub fn display_program_headers(&self) {
        display_elf_program_headers(&self.fileobj);
    }

    pub fn display_section_headers(&self) {
        display_elf_section_headers(&self.fileobj);
    }

    pub fn display_dynamic_section(&self) {
        display_elf_dynamic_section(&self.fileobj);
    }

    pub fn display_symbol_table(&self) {
        display_elf_symbol_table(&self.fileobj);
    }

    pub fn display_version_info(&self) {
        display_elf_version_info(&self.fileobj);
    }

    pub fn display_hex(&self, start_offset: Option<usize>, end_offset: Option<usize>) {
        display_hex(&self.filebuf, start_offset, end_offset);
    }

    pub fn display_disasm(&self, start_section: Option<String>, end_section: Option<String>) {
        display_elf_disasm(&self.filebuf, &self.fileobj, start_section, end_section);
    }
}