use goblin::elf::Elf;
use termimad::minimad::TextTemplate;

use crate::utils::{string::extract_strings_from_buffer, style::init_skin};

pub fn display_elf_strings(filebuf: &Vec<u8>, elf: &Elf) {
    // Extract strings from each section.
    let mut all_strings = Vec::new();
    for section in elf.section_headers.iter() {
        let section_offset = section.sh_offset as usize;
        let section_size = section.sh_size as usize;

        // Get section name
        let section_name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("???");

        if section_offset + section_size <= filebuf.len() {
            let data = &filebuf[section_offset..section_offset + section_size];
            let strings = extract_strings_from_buffer(data, section_offset, 4);
            all_strings.extend(strings);
        }
    }
    
    let text_template = TextTemplate::from(r#"
    # Strings
    |:-|:-|:-|
    |**Offset**|**Length**|**String**|
    |-
    ${rows
    |${offset}|${length}|${string}|
    |-
    }
        "#);
    
        let mut expander = text_template.expander();
        for string in all_strings.iter() {
            expander.sub("rows")
                .set("offset", string.get("offset").unwrap())
                .set("length", string.get("length").unwrap())
                .set("string", string.get("string").unwrap());
        }
    
        let skin = init_skin();
        println!();
        skin.print_expander(expander);
        println!();
}