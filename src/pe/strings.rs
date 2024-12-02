use goblin::pe::PE;
use termimad::minimad::TextTemplate;

use crate::utils::{string::extract_strings_from_buffer, style::init_skin};

pub fn display_pe_strings(filebuf: &Vec<u8>, pe: &PE) {
    // Extract strings from each section.
    let mut all_strings = Vec::new();
    for section in pe.sections.iter() {
        let section_name = match section.name() {
            Ok(n) => n,
            Err(_) => "???",
        };
        let section_offset = section.pointer_to_raw_data as usize;
        let section_size = section.size_of_raw_data as usize;
        let section_rva = section.virtual_address as usize;

        if let Ok(data) = section.data(filebuf) {
            let section_data = data.unwrap();
            let strings = extract_strings_from_buffer(&section_data, section_offset, 4);
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