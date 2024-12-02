use goblin::pe::PE;
use termimad::minimad::TextTemplate;

use crate::utils::style::init_skin;

pub fn display_pe_tls(pe: &PE) {
    if let Some(tls_data) = &pe.tls_data {
        // for callbacks in tls_data.callbacks.iter() {
        // }

        let tls_dir = tls_data.image_tls_directory;

        let start_address_of_raw_data = format!("0x{:X}", tls_dir.start_address_of_raw_data);
        let end_address_of_raw_data = format!("0x{:X}", tls_dir.end_address_of_raw_data);
        let address_of_index = format!("0x{:X}", tls_dir.address_of_index);
        let address_of_callbacks = format!("0x{:X}", tls_dir.address_of_callbacks);
        let size_of_zero_fill = format!("0x{:X}", tls_dir.size_of_zero_fill);
        let characteristics = format!("0x{:X}", tls_dir.characteristics);

        let text_template = TextTemplate::from(r#"
# TLS Information
|:-|:-|
|**Start Address of Raw Data**|${start_address_of_raw_data}|
|-
|**End Address of Raw Data**|${end_address_of_raw_data}|
|-
|**Address of Index**|${address_of_index}|
|-
|**Address of Callbacks**|${address_of_callbacks}|
|-
|**Size of Zero Fill**|${size_of_zero_fill}|
|-
|**Characteristics**|${characteristics}|
|-
        "#);
        let mut expander = text_template.expander();
        expander
            .set("start_address_of_raw_data", &start_address_of_raw_data)
            .set("end_address_of_raw_data", &end_address_of_raw_data)
            .set("address_of_index", &address_of_index)
            .set("address_of_callbacks", &address_of_callbacks)
            .set("size_of_zero_fill", &size_of_zero_fill)
            .set("characteristics", &characteristics);

        let skin = init_skin();
        println!();
        skin.print_expander(expander);
        println!();
    } else {
        let text_template = TextTemplate::from(r#"
# TLS Information

no tls information
        "#);
        let expander = text_template.expander();
        let skin = init_skin();
        println!();
        skin.print_expander(expander);
        println!();   
    }
}