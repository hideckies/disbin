use goblin::pe::PE;
use termimad::minimad::TextTemplate;

use crate::utils::style::init_skin;

struct Export {
    offset: usize,
    offset_string: String,
    name: String,
    rva: usize,
    rva_string: String,
    size: usize,
    size_string: String,
}

pub fn display_pe_exports(pe: &PE) {
    let mut exports_list: Vec<Export> = Vec::new();

    if pe.exports.len() == 0 {
        let text_template = TextTemplate::from(r#"
# Exports

no exports
        "#);
        let expander = text_template.expander();
        let skin = init_skin();
        println!();
        skin.print_expander(expander);
        println!();
        return;
    }

    for export in pe.exports.iter() {
        let offset = match export.offset {
            Some(o) => o,
            None => 0,
        };
        let offset_string = format!("0x{:X}", offset);
        let name = match export.name {
            Some(n) => n.to_string(),
            None => "???".to_string(),
        };
        let rva = export.rva;
        let rva_string = format!("0x{:X}", rva);
        let size = export.size;
        let size_string = format!("0x{:X}", size);

        exports_list.push(Export {
            offset,
            offset_string,
            name,
            rva,
            rva_string,
            size,
            size_string,
        });
    }

    // Sort by offset
    exports_list.sort_by_key(|import| import.offset);

    let text_template = TextTemplate::from(r#"
# Exports
|:-|:-|:-|
|**Offset**|**Name**|**RVA**|**Size**|
|-
${rows
|${offset}|${name}|${rva}|${size}|
|-
}
    "#);
    let mut expander = text_template.expander();
    for export in exports_list.iter() {
        expander.sub("rows")
            .set("offset", &export.offset_string)
            .set("name", &export.name)
            .set("rva", &export.rva_string)
            .set("size", &export.size_string);
    }

    let skin = init_skin();
    println!();
    skin.print_expander(expander);
    println!();
}