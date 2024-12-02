use goblin::pe::PE;
use std::collections::HashMap;
use termimad::minimad::TextTemplate;

use crate::utils::{map::MAP_PRODUCT_ID_AND_VS_VERSION, style::init_skin};

pub fn display_pe_dos_header(pe: &PE) {
    let dos_header = &pe.header.dos_header;

    let i_magic = format!("0x{:X}", dos_header.signature);
    let i_bytes_on_last_page = format!("0x{:X}", dos_header.bytes_on_last_page);
    let i_pages_in_file = format!("0x{:X}", dos_header.pages_in_file);
    let i_relocations = format!("0x{:X}", dos_header.relocations);
    let i_size_of_header_in_paragraph = format!("0x{:X}", dos_header.size_of_header_in_paragraphs);
    let i_minimum_extra_paragraphs_needed = format!("0x{:X}", dos_header.minimum_extra_paragraphs_needed);
    let i_maximum_extra_paragraphs_needed = format!("0x{:X}", dos_header.maximum_extra_paragraphs_needed);
    let i_initial_relative_ss = format!("0x{:X}", dos_header.initial_relative_ss);
    let i_initial_sp = format!("0x{:X}", dos_header.initial_sp);
    let i_checksum = format!("0x{:X}", dos_header.checksum);
    let i_initial_ip = format!("0x{:X}", dos_header.initial_ip);
    let i_initial_relative_cs = format!("0x{:X}", dos_header.initial_relative_cs);
    let i_file_address_of_relocation_table = format!("0x{:X}", dos_header.file_address_of_relocation_table);
    let i_overlay_number = format!("0x{:X}", dos_header.overlay_number);
    let i_oem_id = format!("0x{:X}", dos_header.oem_id);
    let i_oem_info = format!("0x{:X}", dos_header.oem_info);

    let text_template = TextTemplate::from(r#"
# DOS Header
|:-|:-|
|**Magic**|${magic}|
|-
|**Bytes on Last Page**|${bytes_on_last_page}|
|-
|**Pages in File**|${pages_in_file}|
|-
|**Relocations**|${relocations}|
|-
|**Size of Header in Paragraph**|${size_of_header_in_paragraph}|
|-
|**Minimum Extra Paragraphs Needed**|${minimum_extra_paragraphs_needed}|
|-
|**Maximum Extra Paragraphs Needed**|${maximum_extra_paragraphs_needed}|
|-
|**Initial Relative SS Value**|${initial_relative_ss}|
|-
|**Initial SP Value**|${initial_sp}|
|-
|**Checksum**|${checksum}|
|-
|**Initial IP Value**|${initial_ip}|
|-
|**Initial Relative CS Value**|${initial_relative_cs}|
|-
|**File Address of Relocation Table**|${file_address_of_relocation_table}|
|-
|**Overlay Number**|${overlay_number}|
|-
|**OEM Identifier**|${oem_id}|
|-
|**OEM Info**|${oem_info}|
|-
    "#);

    let mut expander = text_template.expander();
    expander
        .set("magic", &i_magic)
        .set("bytes_on_last_page", &i_bytes_on_last_page)
        .set("pages_in_file", &i_pages_in_file)
        .set("relocations", &i_relocations)
        .set("size_of_header_in_paragraph", &i_size_of_header_in_paragraph)
        .set("minimum_extra_paragraphs_needed", &i_minimum_extra_paragraphs_needed)
        .set("maximum_extra_paragraphs_needed", &i_maximum_extra_paragraphs_needed)
        .set("initial_relative_ss", &i_initial_relative_ss)
        .set("initial_sp", &i_initial_sp)
        .set("checksum", &i_checksum)
        .set("initial_ip", &i_initial_ip)
        .set("initial_relative_cs", &i_initial_relative_cs)
        .set("file_address_of_relocation_table", &i_file_address_of_relocation_table)
        .set("overlay_number", &i_overlay_number)
        .set("oem_id", &i_oem_id)
        .set("oem_info", &i_oem_info);

    let skin = init_skin();
    println!();
    skin.print_expander(expander);
    println!();
}

// Rich Header exists in PE files generates with the link.exe of Visual Studio.
// Resources:
//  - https://www.ntcore.com/files/richsign.htm
//  - https://securelist.com/the-devils-in-the-rich-header/84348/
//  - http://ropgadget.com/posts/richheader_hunting.html
pub fn display_pe_rich_header(filebuf: &Vec<u8>, pe: &PE) {
    let rich_signature = &[0x52, 0x69, 0x63, 0x68]; // "Rich"
    if let Some(end_offset) = filebuf
        .windows(rich_signature.len())
        .position(|window| window == rich_signature) {

        let mut offset = end_offset + 8;

        // XOR key (DWORD) exists after "Rich" signature
        let mut xor_key = filebuf[end_offset + rich_signature.len()..end_offset + rich_signature.len() + 4].to_vec();

        // It stores file buffers for Rich header
        let mut rich_bufs: Vec<u8> = Vec::new();

        // For loop in backwards to get XOR key and stop when reached "DanS"
        let chunk_size = 4;
        let target_buf = &filebuf[..offset];
        let mut target_buf_rev: Vec<u8> = target_buf.iter().rev().cloned().collect();
        for chunk in target_buf_rev.chunks_mut(chunk_size) {
            offset -= std::mem::size_of::<u8>() * 4;

            rich_bufs.extend(chunk.to_vec());

            // XOR
            let mut chunk_xor = Vec::new();
            for (i, byte) in chunk.iter().rev().enumerate() {
                chunk_xor.push(*byte ^ xor_key[i]);
            }

            // Represent as string if it can
            if chunk_xor.iter().all(|&byte| byte.is_ascii_graphic() || byte == b' ') {
                let chunk_string: String = chunk_xor.iter().map(|&byte| byte as char).collect();
                // Break if it reached "DanS"
                if chunk_string == "DanS" {
                    break;
                }
            }
        }

        // The following buffers need to be reversed for the next operations.
        xor_key.reverse();
        rich_bufs.reverse();

        // Get value, unmasked value, meaning
        let mut rich_maps: Vec<HashMap<String, String>> = Vec::new();
        let mut current_idx = 0;
        let mut proceed_size = 0;
        while current_idx < rich_bufs.len() {
            let mut rich_map: HashMap<String, String> = HashMap::new();

            let mut name = String::new();
            let mut value: Vec<u8> = Vec::new();
            let mut unmasked_value: Vec<u8> = Vec::new();
            let mut meaning = String::new();
            let mut product_id = String::new();
            let mut vs_version = String::new();

            if current_idx == 0 {
                // "DanS"

                name = "DanS ID".to_string();

                value = rich_bufs[current_idx..current_idx + 4].to_vec();
                value.reverse();

                // XOR
                for (i, byte) in value.iter().enumerate() {
                    unmasked_value.push(*byte ^ xor_key[i]);
                }

                // Represent in string if can
                meaning = if unmasked_value.iter().rev().all(|&byte| byte.is_ascii_graphic() || byte == b' ') {
                    unmasked_value.iter().rev().map(|&byte| byte as char).collect()
                } else {
                    "".to_string()
                };

                proceed_size = 4;
            } else if 4 <= current_idx && current_idx <= 15 {
                // Null bytes

                name = "Padding".to_string();

                value = rich_bufs[current_idx..current_idx + 4].to_vec();
                value.reverse();

                // XOR
                for (i, byte) in value.iter().enumerate() {
                    unmasked_value.push(*byte ^ xor_key[i]);
                }

                proceed_size = 4;
            } else if current_idx < rich_bufs.len() - 8 {
                // Comp IDs

                name = "Comp ID".to_string();

                let mut value1 = rich_bufs[current_idx..current_idx + 4].to_vec();
                value1.reverse();
                let mut value2 = rich_bufs[current_idx + 4..current_idx + 8].to_vec();
                value2.reverse();
                value = [value2.clone(), value1.clone()].concat();

                // XOR
                let mut unmasked_value1: Vec<u8> = Vec::new();
                for (i, byte) in value1.iter().enumerate() {
                    unmasked_value1.push(*byte ^ xor_key[i]);
                }
                let mut unmasked_value2: Vec<u8> = Vec::new();
                for (i, byte) in value2.iter().enumerate() {
                    unmasked_value2.push(*byte ^ xor_key[i]);
                }
                // Trim leading zeros for unmasked_value2.
                if let Some(pos) = unmasked_value2.iter().position(|&x| x != 0) {
                    unmasked_value2 = unmasked_value2[pos..].to_vec();
                }
                unmasked_value = [unmasked_value2.clone(), unmasked_value1.clone()].concat();

                // Resolve Comp ID
                // Ref: https://github.com/dishather/richprint/blob/master/comp_id.txt
                let compiler_version_tmp = &unmasked_value[unmasked_value.len() - 2..unmasked_value.len()];
                let compiler_version_hex: String = compiler_version_tmp.iter().map(|b| format!("{:02x}", b)).collect();
                let compiler_version = u32::from_str_radix(&compiler_version_hex, 16).unwrap();
                let build_version_tmp = &unmasked_value[unmasked_value.len() - 4..unmasked_value.len() - 2];
                let build_version_hex: String = build_version_tmp.iter().map(|b| format!("{:02x}", b)).collect();
                let build_version = u32::from_str_radix(&build_version_hex, 16).unwrap();
                let minor_version_tmp = &unmasked_value[0..unmasked_value.len() - 4];
                let minor_version_hex: String = minor_version_tmp.iter().map(|b| format!("{:02x}", b)).collect();
                let minor_version = u32::from_str_radix(&minor_version_hex, 16).unwrap();

                meaning = format!("{}.{}.{}", compiler_version, build_version, minor_version);

                // Resolve Product ID
                match MAP_PRODUCT_ID_AND_VS_VERSION.get(&build_version_hex) {
                    Some(p) => {
                        product_id = p.0.to_string();
                        vs_version = p.1.to_string();
                    },
                    None => {
                        product_id = "???".to_string();
                        vs_version = "???".to_string();
                    },
                };

                proceed_size = 8;
            } else {
                // Rich ID, Checksum

                if current_idx == rich_bufs.len() - 8 {
                    name = "Rich ID".to_string();
                } else {
                    name = "XOR Key".to_string();
                }

                value = rich_bufs[current_idx..current_idx + 4].to_vec();
                value.reverse();

                // XOR is not required.
                unmasked_value = vec![0];

                // Represent in string if can
                meaning = if value.iter().rev().all(|&byte| byte.is_ascii_graphic() || byte == b' ') {
                    value.iter().rev().map(|&byte| byte as char).collect()
                } else {
                    "".to_string()
                };

                proceed_size = 4;
            }

            // Represent in hex
            let value_hex: String = format!("0x{}", value.iter().map(|byte| format!("{:02X}", byte)).collect::<Vec<_>>().join(""));
            let unmasked_value_hex: String = format!("0x{}", unmasked_value.iter().map(|byte| format!("{:02X}", byte)).collect::<Vec<_>>().join(""));

            rich_map.insert("offset".to_string(), format!("0x{:X}", offset));
            rich_map.insert("name".to_string(), name);
            rich_map.insert("value".to_string(), value_hex);
            rich_map.insert("value_xored".to_string(), unmasked_value_hex);
            rich_map.insert("meaning".to_string(), meaning);
            rich_map.insert("product_id".to_string(), product_id);
            rich_map.insert("vs_version".to_string(), vs_version);

            rich_maps.push(rich_map);

            // Proceed
            current_idx += proceed_size;
            offset += std::mem::size_of::<u8>() * proceed_size;
        }

        // Display
        let text_template = TextTemplate::from(r#"
# Rich Header
|:-|:-|:-|:-|:-|:-|:-|
|**Offset**|**Name**|**Value**|**Value (XORed)**|**Meaning**|**Product ID**|**VS Version**|
|-
${rows
|${offset}|${name}|${value}|${value_xored}|${meaning}|${product_id}|${vs_version}|
|-
}
            "#);
            let mut expander = text_template.expander();
            for rich_map in rich_maps.iter() {
                expander.sub("rows")
                    .set("offset", &rich_map.get("offset").unwrap())
                    .set("name", &rich_map.get("name").unwrap())
                    .set("value", &rich_map.get("value").unwrap())
                    .set("value_xored", &rich_map.get("value_xored").unwrap())
                    .set("meaning", &rich_map.get("meaning").unwrap())
                    .set("product_id", &rich_map.get("product_id").unwrap())
                    .set("vs_version", &rich_map.get("vs_version").unwrap());
            }

            let skin = init_skin();
            println!();
            skin.print_expander(expander);
            println!();
    } else {
        let text_template = TextTemplate::from(r#"
# Rich Header

Not found
        "#);
        let expander = text_template.expander();
        let skin = init_skin();
        println!();
        skin.print_expander(expander);
        println!();
    };
}

pub fn display_pe_coff_header(pe: &PE) {
    let coff_header = &pe.header.coff_header;

    let i_machine = format!("0x{:X}", coff_header.machine);
    let i_number_of_sections = format!("0x{:X}", coff_header.number_of_sections);
    let i_time_date_stamp = format!("0x{:X}", coff_header.time_date_stamp);
    let i_pointer_to_symbol_table = format!("0x{:08X}", coff_header.pointer_to_symbol_table);
    let i_number_of_symbols = format!("0x{:X}", coff_header.number_of_symbol_table);
    let i_size_of_optional_header = format!("0x{:X}", coff_header.size_of_optional_header);
    let i_characteristics = format!("0x{:X}", coff_header.characteristics);

    let text_template = TextTemplate::from(r#"
# COFF Header
|:-|:-|
|**Machine**|${machine}|
|-
|**Number of Sections**|${number_of_sections}|
|-
|**Time Date Stamp**|${time_date_stamp}|
|-
|**Pointer to Symbol Table**|${pointer_to_symbol_table}|
|-
|**Number of Symbols**|${number_of_symbols}|
|-
|**Size of Optional Header**|${size_of_optional_header}|
|-
|**Characteristics**|${characteristics}|
|-
    "#);

    let mut expander = text_template.expander();
    expander
        .set("machine", &i_machine)
        .set("number_of_sections", &i_number_of_sections)
        .set("time_date_stamp", &i_time_date_stamp)
        .set("pointer_to_symbol_table", &i_pointer_to_symbol_table)
        .set("number_of_symbols", &i_number_of_symbols)
        .set("size_of_optional_header", &i_size_of_optional_header)
        .set("characteristics", &i_characteristics);

    let skin = init_skin();
    println!();
    skin.print_expander(expander);
    println!();
}

pub fn display_pe_optional_header(pe: &PE) {
    let optional_header = match pe.header.optional_header {
        Some(o) => o,
        None => {
            let text_template = TextTemplate::from(r#"
# Optional Header

no optional header
            "#);
            let expander = text_template.expander();
            let skin = init_skin();
            println!();
            skin.print_expander(expander);
            println!();
            return;
        },
    };

    let i_magic = format!("0x{:X}", optional_header.standard_fields.magic);
    let i_major_linker_version = format!("0x{:X}", optional_header.standard_fields.major_linker_version);
    let i_minor_linker_version = format!("0x{:X}", optional_header.standard_fields.minor_linker_version);
    let i_size_of_code = format!("0x{:X}", optional_header.standard_fields.size_of_code);
    let i_size_of_initialized_data = format!("0x{:X}", optional_header.standard_fields.size_of_initialized_data);
    let i_size_of_uninitialized_data = format!("0x{:X}", optional_header.standard_fields.size_of_uninitialized_data);
    let i_address_of_entry_point = format!("0x{:X}", optional_header.standard_fields.address_of_entry_point);
    let i_base_of_code = format!("0x{:X}", optional_header.standard_fields.base_of_code);
    let i_base_of_data = format!("0x{:X}", optional_header.standard_fields.base_of_data);
    
    let i_image_base = format!("0x{:X}", optional_header.windows_fields.image_base);
    let i_section_alignment = format!("0x{:X}", optional_header.windows_fields.section_alignment);
    let i_file_alignment = format!("0x{:X}", optional_header.windows_fields.file_alignment);
    let i_major_os_version = format!("0x{:X}", optional_header.windows_fields.major_operating_system_version);
    let i_minor_os_version = format!("0x{:X}", optional_header.windows_fields.minor_operating_system_version);
    let i_major_image_version = format!("0x{:X}", optional_header.windows_fields.major_image_version);
    let i_minor_image_version = format!("0x{:X}", optional_header.windows_fields.minor_image_version);
    let i_major_subsystem_version = format!("0x{:X}", optional_header.windows_fields.major_subsystem_version);
    let i_minor_subsystem_version = format!("0x{:X}", optional_header.windows_fields.minor_subsystem_version);
    let i_win32_version_value = format!("0x{:X}", optional_header.windows_fields.win32_version_value);
    let i_size_of_image = format!("0x{:X}", optional_header.windows_fields.size_of_image);
    let i_size_of_headers = format!("0x{:X}", optional_header.windows_fields.size_of_headers);
    let i_checksum = format!("0x{:X}", optional_header.windows_fields.check_sum);
    let i_subsystem = format!("0x{:X}", optional_header.windows_fields.subsystem);
    let i_dll_characteristics = format!("0x{:X}", optional_header.windows_fields.dll_characteristics);
    let i_size_of_stack_reserve = format!("0x{:X}", optional_header.windows_fields.size_of_stack_reserve);
    let i_size_of_stack_commit = format!("0x{:X}", optional_header.windows_fields.size_of_stack_commit);
    let i_size_of_heap_reserve = format!("0x{:X}", optional_header.windows_fields.size_of_heap_reserve);
    let i_size_of_heap_commit = format!("0x{:X}", optional_header.windows_fields.size_of_heap_commit);
    let i_loader_flags = format!("0x{:X}", optional_header.windows_fields.loader_flags);
    let i_number_of_rva_and_sizes = format!("0x{:X}", optional_header.windows_fields.number_of_rva_and_sizes);

    let data_directories = &optional_header.data_directories;
    
    let mut i_export_table_address = "???".to_string();
    let mut i_export_table_size = "???".to_string();
    if let Some(export_table) = data_directories.get_export_table() {
        i_export_table_address = format!("0x{:X}", export_table.virtual_address);
        i_export_table_size = format!("0x{:X}", export_table.size);
    };
    let mut i_import_table_address = "???".to_string();
    let mut i_import_table_size = "???".to_string();
    if let Some(import_table) = data_directories.get_import_table() {
        i_import_table_address = format!("0x{:X}", import_table.virtual_address);
        i_import_table_size = format!("0x{:X}", import_table.size);
    }
    let mut i_resource_table_address = "???".to_string();
    let mut i_resource_table_size = "???".to_string();
    if let Some(resource_table) = data_directories.get_resource_table() {
        i_resource_table_address = format!("0x{:X}", resource_table.virtual_address);
        i_resource_table_size = format!("0x{:X}", resource_table.size);
    }
    let mut i_exception_table_address = "???".to_string();
    let mut i_exception_table_size = "???".to_string();
    if let Some(exception_table) = data_directories.get_exception_table() {
        i_exception_table_address = format!("0x{:X}", exception_table.virtual_address);
        i_exception_table_size = format!("0x{:X}", exception_table.size);
    };
    let mut i_certificate_table_address = "???".to_string();
    let mut i_certificate_table_size = "???".to_string();
    if let Some(certificate_table) = data_directories.get_certificate_table() {
        i_certificate_table_address = format!("0x{:X}", certificate_table.virtual_address);
        i_certificate_table_size = format!("0x{:X}", certificate_table.size);
    }
    let mut i_base_relocation_table_address = "???".to_string();
    let mut i_base_relocation_table_size = "???".to_string();
    if let Some(base_relocation_table) = data_directories.get_base_relocation_table() {
        i_base_relocation_table_address = format!("0x{:X}", base_relocation_table.virtual_address);
        i_base_relocation_table_size = format!("0x{:X}", base_relocation_table.size);
    }
    let mut i_debug_table_address = "???".to_string();
    let mut i_debug_table_size = "???".to_string();
    if let Some(debug_table) = data_directories.get_debug_table() {
        i_debug_table_address = format!("0x{:X}", debug_table.virtual_address);
        i_debug_table_size = format!("0x{:X}", debug_table.size);
    }
    let mut i_architecture_address = "???".to_string();
    let mut i_architecture_size = "???".to_string();
    if let Some(architecture) = data_directories.get_architecture() {
        i_architecture_address = format!("0x{:X}", architecture.virtual_address);
        i_architecture_size = format!("0x{:X}", architecture.size);
    }
    let mut i_global_ptr_address = "???".to_string();
    let mut i_global_ptr_size = "???".to_string();
    if let Some(global_ptr) = data_directories.get_global_ptr() {
        i_global_ptr_address = format!("0x{:X}", global_ptr.virtual_address);
        i_global_ptr_size = format!("0x{:X}", global_ptr.size);
    }
    let mut i_tls_table_address = "???".to_string();
    let mut i_tls_table_size = "???".to_string();
    if let Some(tls_table) = data_directories.get_tls_table() {
        i_tls_table_address = format!("0x{:X}", tls_table.virtual_address);
        i_tls_table_size = format!("0x{:X}", tls_table.size);
    }
    let mut i_load_config_table_address = "???".to_string();
    let mut i_load_config_table_size = "???".to_string();
    if let Some(load_config_table) = data_directories.get_load_config_table() {
        i_load_config_table_address = format!("0x{:X}", load_config_table.virtual_address);
        i_load_config_table_size = format!("0x{:X}", load_config_table.size);
    }
    let mut i_bound_import_table_address = "???".to_string();
    let mut i_bound_import_table_size = "???".to_string();
    if let Some(bound_import_table) = data_directories.get_bound_import_table() {
        i_bound_import_table_address = format!("0x{:X}", bound_import_table.virtual_address);
        i_bound_import_table_size = format!("0x{:X}", bound_import_table.size);
    }
    let mut i_iat_address = "???".to_string();
    let mut i_iat_size = "???".to_string();
    if let Some(iat) = data_directories.get_import_address_table() {
        i_iat_address = format!("0x{:X}", iat.virtual_address);
        i_iat_size = format!("0x{:X}", iat.size);
    }
    let mut i_delay_import_descriptor_address = "???".to_string();
    let mut i_delay_import_descriptor_size = "???".to_string();
    if let Some(d) = data_directories.get_delay_import_descriptor() {
        i_delay_import_descriptor_address = format!("0x{:X}", d.virtual_address);
        i_delay_import_descriptor_size = format!("0x{:X}", d.size);
    }
    let mut i_clr_runtime_header_address = "???".to_string();
    let mut i_clr_runtime_header_size = "???".to_string();
    if let Some(c) = data_directories.get_clr_runtime_header() {
        i_clr_runtime_header_address = format!("0x{:X}", c.virtual_address);
        i_clr_runtime_header_size = format!("0x{:X}", c.size);
    }

    let text_template = TextTemplate::from(r#"
# Optional Header
|:-|:-|
|**Magic**|${magic}|
|-
|**Major Linker Version**|${major_linker_version}|
|-
|**Minor Linker Version**|${minor_linker_version}|
|-
|**Size of Code**|${size_of_code}|
|-
|**Size of Initialized Data**|${size_of_initialized_data}|
|-
|**Size of Uninitialized Data**|${size_of_uninitialized_data}|
|-
|**Entry Point**|${address_of_entry_point}|
|-
|**Base of Code**|${base_of_code}|
|-
|**Base of Data**|${base_of_data}|
|-
|-
|**Image Base**|${image_base}|
|-
|**Section Alignment**|${section_alignment}|
|-
|**File Alignment**|${file_alignment}|
|-
|**Major OS Version**|${major_os_version}|
|-
|**Minor OS Version**|${minor_os_version}|
|-
|**Major Image Version**|${major_image_version}|
|-
|**Minor Image Version**|${minor_image_version}|
|-
|**Major Subsystem Version**|${major_subsystem_version}|
|-
|**Minor Subsystem Version**|${minor_subsystem_version}|
|-
|**Win32 Version Value**|${win32_version_value}|
|-
|**Size of Image**|${size_of_image}|
|-
|**Size of Headers**|${size_of_headers}|
|-
|**Checksum**|${checksum}|
|-
|**Subsystem**|${subsystem}|
|-
|**DLL Characteristics**|${dll_characteristics}|
|-
|**Size of Stack Reserve**|${size_of_stack_reserve}|
|-
|**Size of Stack Commit**|${size_of_stack_commit}|
|-
|**Size of Heap Reserve**|${size_of_heap_reserve}|
|-
|**Size of Heap Commit**|${size_of_heap_commit}|
|-
|**Loader Flags**|${loader_flags}|
|-
|**Number of RVA and Sizes**|${number_of_rva_and_sizes}|
|-

|:-|:-|:-|
|**Data Directories**|**Address**|**Size**|
|-
|**Export Table**|${export_table_address}|${export_table_size}|
|-
|**Import Table**|${import_table_address}|${import_table_size}|
|-
|**Resource Table**|${resource_table_address}|${resource_table_size}|
|-
|**Exception Table**|${exception_table_address}|${exception_table_size}|
|-
|**Certificate Table**|${certificate_table_address}|${certificate_table_size}|
|-
|**Base Relocation Table**|${base_relocation_table_address}|${base_relocation_table_size}|
|-
|**Debug Table**|${debug_table_address}|${debug_table_size}|
|-
|**Architecture**|${architecture_address}|${architecture_size}|
|-
|**Global Ptr**|${global_ptr_address}|${global_ptr_size}|
|-
|**TLS Table**|${tls_table_address}|${tls_table_size}|
|-
|**Load Config Table**|${load_config_table_address}|${load_config_table_size}|
|-
|**Bound Import Table**|${bound_import_table_address}|${bound_import_table_size}|
|-
|**Import Address Table**|${iat_address}|${iat_size}|
|-
|**Delay Import Descriptor**|${delay_import_descriptor_address}|${delay_import_descriptor_size}|
|-
|**CLR Runtime Header**|${clr_runtime_header_address}|${clr_runtime_header_size}|
|-
            "#);
            let mut expander = text_template.expander();
            expander
                .set("magic", &i_magic)
                .set("major_linker_version", &i_major_linker_version)
                .set("minor_linker_version", &i_minor_linker_version)
                .set("size_of_code", &i_size_of_code)
                .set("size_of_initialized_data", &i_size_of_initialized_data)
                .set("size_of_uninitialized_data", &i_size_of_uninitialized_data)
                .set("address_of_entry_point", &i_address_of_entry_point)
                .set("base_of_code", &i_base_of_code)
                .set("base_of_data", &i_base_of_data)
                
                .set("image_base", &i_image_base)
                .set("section_alignment", &i_section_alignment)
                .set("file_alignment", &i_file_alignment)
                .set("major_os_version", &i_major_os_version)
                .set("minor_os_version", &i_minor_os_version)
                .set("major_image_version", &i_major_image_version)
                .set("minor_image_version", &i_minor_image_version)
                .set("major_subsystem_version", &i_major_subsystem_version)
                .set("minor_subsystem_version", &i_minor_subsystem_version)
                .set("win32_version_value", &i_win32_version_value)
                .set("size_of_image", &i_size_of_image)
                .set("size_of_headers", &i_size_of_headers)
                .set("checksum", &i_checksum)
                .set("subsystem", &i_subsystem)
                .set("dll_characteristics", &i_dll_characteristics)
                .set("size_of_stack_reserve", &i_size_of_stack_reserve)
                .set("size_of_stack_commit", &i_size_of_stack_commit)
                .set("size_of_heap_reserve", &i_size_of_heap_reserve)
                .set("size_of_heap_commit", &i_size_of_heap_commit)
                .set("loader_flags", &i_loader_flags)
                .set("number_of_rva_and_sizes", &i_number_of_rva_and_sizes)
                
                .set("export_table_address", &i_export_table_address)
                .set("export_table_size", &i_export_table_size)
                .set("import_table_address", &i_import_table_address)
                .set("import_table_size", &i_import_table_size)
                .set("resource_table_address", &i_resource_table_address)
                .set("resource_table_size", &i_resource_table_size)
                .set("exception_table_address", &i_exception_table_address)
                .set("exception_table_size", &i_exception_table_size)
                .set("certificate_table_address", &i_certificate_table_address)
                .set("certificate_table_size", &i_certificate_table_size)
                .set("base_relocation_table_address", &i_base_relocation_table_address)
                .set("base_relocation_table_size", &i_base_relocation_table_size)
                .set("debug_table_address", &i_debug_table_address)
                .set("debug_table_size", &i_debug_table_size)
                .set("architecture_address", &i_architecture_address)
                .set("architecture_size", &i_architecture_size)
                .set("global_ptr_address", &i_global_ptr_address)
                .set("global_ptr_size", &i_global_ptr_size)
                .set("tls_table_address", &i_tls_table_address)
                .set("tls_table_size", &i_tls_table_size)
                .set("load_config_table_address", &i_load_config_table_address)
                .set("load_config_table_size", &i_load_config_table_size)
                .set("bound_import_table_address", &i_bound_import_table_address)
                .set("bound_import_table_size", &i_bound_import_table_size)
                .set("iat_address", &i_iat_address)
                .set("iat_size", &i_iat_size)
                .set("delay_import_descriptor_address", &i_delay_import_descriptor_address)
                .set("delay_import_descriptor_size", &i_delay_import_descriptor_size)
                .set("clr_runtime_header_address", &i_clr_runtime_header_address)
                .set("clr_runtime_header_size", &i_clr_runtime_header_size);

            let skin = init_skin();
            println!();
            skin.print_expander(expander);
            println!();
}

pub fn display_pe_sections(pe: &PE) {
    let mut secmaps: Vec<HashMap<String, String>> = Vec::new();

    let mut idx = 0;
    for section in pe.sections.iter() {
        let mut secmap: HashMap<String, String> = HashMap::new();

        let sec_name_tmp = String::from_utf8_lossy(&section.name);
        // Delete null-bytes at the end of the name.
        let sec_name_cleaned_bytes: Vec<u8> = sec_name_tmp.as_bytes().iter().cloned().filter(|&b| b != 0).collect();
        let sec_name = match String::from_utf8(sec_name_cleaned_bytes) {
            Ok(s) => s,
            Err(_) => "???".to_string(),
        };
        let sec_raw_addr = format!("0x{:X}", section.pointer_to_raw_data);
        let sec_raw_size = format!("0x{:X}", section.size_of_raw_data);
        let sec_virtual_addr = format!("0x{:X}", section.virtual_address);
        let sec_virtual_size = format!("0x{:X}", section.virtual_size);
        let sec_characteristics = format!("0x{:X}", section.characteristics);
        let sec_ptr_to_relocations = format!("0x{:X}", section.pointer_to_relocations);
        let sec_num_of_relocations= format!("0x{:X}", section.number_of_relocations);
        let sec_ptr_to_linenumbers = format!("0x{:X}", section.pointer_to_linenumbers);
        let sec_num_of_linenumbers = format!("0x{:X}", section.number_of_linenumbers);

        secmap.insert("idx".to_string(), idx.to_string());
        secmap.insert("name".to_string(), sec_name);
        secmap.insert("raw_addr".to_string(), sec_raw_addr);
        secmap.insert("raw_size".to_string(), sec_raw_size);
        secmap.insert("virtual_addr".to_string(), sec_virtual_addr);
        secmap.insert("virtual_size".to_string(), sec_virtual_size);
        secmap.insert("characteristics".to_string(), sec_characteristics);
        secmap.insert("ptr_to_relocations".to_string(), sec_ptr_to_relocations);
        secmap.insert("num_of_relocations".to_string(), sec_num_of_relocations);
        secmap.insert("ptr_to_linenumbers".to_string(), sec_ptr_to_linenumbers);
        secmap.insert("num_of_linenumbers".to_string(), sec_num_of_linenumbers);

        secmaps.push(secmap);

        idx += 1;
    }

    let text_template = TextTemplate::from(r#"
# Sections
|:-|:-|:-|:-|:-|:-|:-|:-|:-|:-|:-|
|**Idx**|**Name**|**Raw Addr**|**Raw Size**|**Virtual Addr**|**Virtual Size**|**Characteristics**|**Ptr to Relocations**|**Num of Relocations**|**Ptr to Linenumbers**|**Num of Linenumbers**|
|-
${rows
|${idx}|${name}|${raw_addr}|${raw_size}|${virtual_addr}|${virtual_size}|${characteristics}|${ptr_to_relocations}|${num_of_relocations}|${ptr_to_linenumbers}|${num_of_linenumbers}|
|-
}
    "#);
    let mut expander = text_template.expander();
    for secmap in secmaps.iter() {
        expander.sub("rows")
            .set("idx", secmap.get("idx").unwrap())
            .set("name", secmap.get("name").unwrap())
            .set("raw_addr", secmap.get("raw_addr").unwrap())
            .set("raw_size", secmap.get("raw_size").unwrap())
            .set("virtual_addr", secmap.get("virtual_addr").unwrap())
            .set("virtual_size", secmap.get("virtual_size").unwrap())
            .set("characteristics", secmap.get("characteristics").unwrap())
            .set("ptr_to_relocations", secmap.get("ptr_to_relocations").unwrap())
            .set("num_of_relocations", secmap.get("num_of_relocations").unwrap())
            .set("ptr_to_linenumbers", secmap.get("ptr_to_linenumbers").unwrap())
            .set("num_of_linenumbers", secmap.get("num_of_linenumbers").unwrap());
    }

    let skin = init_skin();
    println!();
    skin.print_expander(expander);
    println!();
}