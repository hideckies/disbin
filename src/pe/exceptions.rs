use goblin::pe::PE;
use std::collections::HashMap;
use termimad::minimad::TextTemplate;

use crate::utils::style::init_skin;

pub fn display_pe_exceptions(pe: &PE) {
    if let Some(exception_data) = &pe.exception_data {
        let mut excep_maps: Vec<HashMap<String, String>> = Vec::new();

        for func in exception_data.functions() {
            let mut excep_map: HashMap<String, String> = HashMap::new();

            if let Ok(f) = func {
                let begin_addr = format!("0x{:X}", f.begin_address);
                let end_addr = format!("0x{:X}", f.end_address);
                let unwind_info_addr = format!("0x{:X}", f.unwind_info_address);

                excep_map.insert("begin_addr".to_string(), begin_addr);
                excep_map.insert("end_addr".to_string(), end_addr);
                excep_map.insert("unwind_info_addr".to_string(), unwind_info_addr);
            }

            excep_maps.push(excep_map);
        }

        let text_template = TextTemplate::from(r#"
# Exceptions
|:-|:-|:-|
|**Begin Addr**|**End Addr**|**Unwind Info Addr**|
|-
${rows
|${begin_addr}|${end_addr}|${unwind_info_addr}|
|-
}
        "#);
        let mut expander = text_template.expander();
        for excep in excep_maps.iter() {
            expander.sub("rows")
                .set("begin_addr", excep.get("begin_addr").unwrap())
                .set("end_addr", excep.get("end_addr").unwrap())
                .set("unwind_info_addr", excep.get("unwind_info_addr").unwrap());
        }

        let skin = init_skin();
        println!();
        skin.print_expander(expander);
        println!();
        return;
    } else {
        let text_template = TextTemplate::from(r#"
# Exceptions

no exceptions
        "#);
        let expander = text_template.expander();
        let skin = init_skin();
        println!();
        skin.print_expander(expander);
        println!();
        return;
    }
}