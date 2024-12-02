use goblin::pe::PE;
use termimad::minimad::TextTemplate;

use crate::utils::{map::MAP_DEBUG_TYPE, style::init_skin};

pub fn display_pe_debug(pe: &PE) {
    if let Some(debug_data) = &pe.debug_data {
        let debug_dir = debug_data.image_debug_directory;

        // Resolve debug type name
        let type_name = match MAP_DEBUG_TYPE.get(&debug_dir.data_type) {
            Some(t) => t.to_string(),
            None => "???".to_string(),
        };
        let characteristic = format!("0x{:X}", debug_dir.characteristics);
        let major_version = format!("0x{:X}", debug_dir.major_version);
        let minor_version = format!("0x{:X}", debug_dir.minor_version);
        let data_type = format!("0x{:X}", debug_dir.data_type);
        let size_of_data = format!("0x{:X}", debug_dir.size_of_data);
        let address_of_raw_data = format!("0x{:X}", debug_dir.address_of_raw_data);
        let pointer_to_raw_data = format!("0x{:X}", debug_dir.pointer_to_raw_data);
        let time_date_stamp = format!("0x{:X}", debug_dir.time_date_stamp);

        // let guid = match debug_data.guid() {
        //     Some(g) => g,
        //     None => "???".to_string(),
        // };

        // if let Some(c) = debug_data.codeview_pdb20_debug_info {
        //     let age = c.age;
        //     let codeview_offset = c.codeview_offset;
        //     let codeview_signature = c.codeview_signature;
        //     let filename = c.filename;
        //     let signature = c.signature;
        // }
        // if let Some(c) = debug_data.codeview_pdb70_debug_info {
        //     let age = c.age;
        //     let codeview_signature = c.codeview_signature;
        //     let filename = c.filename;
        //     let signature = c.signature;
        // }

        let text_template = TextTemplate::from(r#"
# Debug Information
|:-|:-|
|**Type Name**|${type_name}|
|-
|**Characteristics**|${characteristics}|
|-
|**Major Version**|${major_version}|
|-
|**Minor Version**|${minor_version}|
|-
|**Type**|${type}|
|-
|**Size of Data**|${size_of_data}|
|-
|**Address of Raw Data**|${address_of_raw_data}|
|-
|**Pointer to Raw Data**|${pointer_to_raw_data}|
|-
|**Time Date Stamp**|${time_date_stamp}|
|-
        "#);
        let mut expander = text_template.expander();
        expander
            .set("type_name", &type_name)
            .set("characteristics", &characteristic)
            .set("major_version", &major_version)
            .set("minor_version", &minor_version)
            .set("type", &data_type)
            .set("size_of_data", &size_of_data)
            .set("address_of_raw_data", &address_of_raw_data)
            .set("pointer_to_raw_data", &pointer_to_raw_data)
            .set("time_date_stamp", &time_date_stamp);

        let skin = init_skin();
        println!();
        skin.print_expander(expander);
        println!();
    } else {
        let text_template = TextTemplate::from(r#"
# Debug Information

no debug information
        "#);
        let expander = text_template.expander();
        let skin = init_skin();
        println!();
        skin.print_expander(expander);
        println!();
    }
}