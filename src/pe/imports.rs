use goblin::pe::PE;
use termimad::minimad::TextTemplate;
use std::collections::HashMap;

use crate::utils::{
    map::{MAP_COMCTL32_ORDINAL, MAP_OLEAUT32_ORDINAL, MAP_WS2_32_ORDINAL, MAP_WSOCK32_ORDINAL},
    style::init_skin,
};

struct Imports {
    offset: usize,
    offset_string: String,
    dll: String,
    function: String,
    rva: usize,
    rva_string: String,
    size: usize,
    size_string: String,
}

pub fn display_pe_imports(pe: &PE) {
    let mut imports_list: Vec<Imports> = Vec::new();

    if pe.imports.len() == 0 {
        let text_template = TextTemplate::from(r#"
# Imports

no imports
        "#);
        let expander = text_template.expander();
        let skin = init_skin();
        println!();
        skin.print_expander(expander);
        println!();
    }

    for import in pe.imports.iter() {
        let offset = import.offset;
        let offset_string = format!("0x{:X}", offset);
        let dll_name = import.dll.to_string();
        let mut func_name = import.name.to_string();
        let rva = import.rva;
        let rva_string = format!("0x{:X}", rva);
        let size = import.size;
        let size_string = format!("0x{:X}", size);

        // Resolve some function names from ordinals
        if dll_name.to_lowercase() == "comctl32.dll" && func_name.to_lowercase().starts_with("ordinal ") {
            func_name = MAP_COMCTL32_ORDINAL.get(&import.ordinal).unwrap().to_ascii_lowercase();
        } else if dll_name.to_lowercase() == "oleaut32.dll" && func_name.to_lowercase().starts_with("ordinal ") {
            func_name = MAP_OLEAUT32_ORDINAL.get(&import.ordinal).unwrap().to_ascii_lowercase();
        } else if dll_name.to_lowercase() == "ws2_32.dll" && func_name.to_lowercase().starts_with("ordinal ") {
            func_name = MAP_WS2_32_ORDINAL.get(&import.ordinal).unwrap().to_ascii_lowercase();
        } else if dll_name.to_lowercase() == "wsock32.dll" && func_name.to_lowercase().starts_with("ordinal ") {
            func_name = MAP_WSOCK32_ORDINAL.get(&import.ordinal).unwrap().to_ascii_lowercase();
        }
        // If the function name could not be resolved, round it with `[]` for user experience.
        if func_name.to_lowercase().starts_with("ordinal ") {
            func_name = format!("[{}]", func_name);
        }

        imports_list.push(Imports {
            offset,
            offset_string,
            dll: dll_name,
            function: func_name,
            rva,
            rva_string,
            size,
            size_string,
        });
    }

    // Sort by offset
    imports_list.sort_by_key(|import| import.offset);

    let text_template = TextTemplate::from(r#"
# Imports
|:-|:-|:-|:-|:-|
|**Offset**|**DLL**|**Function**|**RVA**|**Size**|
|-
${rows
|${offset}|${dll}|${func}|${rva}|${size}|
|-
}
    "#);
    let mut expander = text_template.expander();
    for import in imports_list.iter() {
        expander.sub("rows")
            .set("offset", &import.offset_string)
            .set("dll", &import.dll)
            .set("func", &import.function)
            .set("rva", &import.rva_string)
            .set("size", &import.size_string);
    }

    let skin = init_skin();
    println!();
    skin.print_expander(expander);
    println!();
}