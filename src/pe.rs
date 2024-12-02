use goblin::pe::PE;

mod debug;
mod disasm;
mod exceptions;
mod exports;
mod headers;
mod imports;
mod info;
mod strings;
mod tls;

use debug::display_pe_debug;
use disasm::display_pe_disasm;
use exceptions::display_pe_exceptions;
use exports::display_pe_exports;
use headers::{
    display_pe_coff_header,
    display_pe_dos_header,
    display_pe_optional_header,
    display_pe_rich_header,
    display_pe_sections,
};
use imports::display_pe_imports;
use info::display_pe_info;
use strings::display_pe_strings;
use tls::display_pe_tls;

use crate::common::{hashes::display_common_hashes, hex::display_hex};

pub struct PeInfo<'a> {
    pub filepath: String,
    pub filebuf: Vec<u8>,
    pub fileobj: PE<'a>,
}

impl<'a> PeInfo<'a> {
    pub fn new(filepath: &str, filebuf: Vec<u8>, pe: PE<'a>) -> Self {
        Self {
            filepath: filepath.to_string(),
            filebuf,
            fileobj: pe,
        }
    }

    pub fn display_info(&self) {
        display_pe_info(&self.filepath, &self.fileobj);
    }

    pub fn display_hashes(&self) {
        display_common_hashes(&self.filebuf);
    }

    pub fn display_strings(&self) {
        display_pe_strings(&self.filebuf, &self.fileobj);
    }

    pub fn display_dos_header(&self) {
        display_pe_dos_header(&self.fileobj);
    }

    pub fn display_rich_header(&self) {
        display_pe_rich_header(&self.filebuf, &self.fileobj);
    }

    pub fn display_coff_header(&self) {
        display_pe_coff_header(&self.fileobj);
    }

    pub fn display_optional_header(&self) {
        display_pe_optional_header(&self.fileobj);
    }

    pub fn display_sections(&self) {
        display_pe_sections(&self.fileobj);
    }

    pub fn display_imports(&self) {
        display_pe_imports(&self.fileobj);
    }

    pub fn display_exports(&self) {
        display_pe_exports(&self.fileobj);
    }

    pub fn display_exceptions(&self) {
        display_pe_exceptions(&self.fileobj);
    }

    pub fn display_tls(&self) {
        display_pe_tls(&self.fileobj);
    }

    pub fn display_debug(&self) {
        display_pe_debug(&self.fileobj);
    }

    pub fn display_hex(&self, start_offset: Option<usize>, end_offset: Option<usize>) {
        display_hex(&self.filebuf, start_offset, end_offset);
    }

    pub fn display_disasm(&self, start_section: Option<String>, end_section: Option<String>) {
        // TODO: This function does not work correctly so should be fixed.
        display_pe_disasm(&self.filebuf, &self.fileobj, start_section, end_section);
    }
}