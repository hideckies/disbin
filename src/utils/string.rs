use std::collections::HashMap;

pub fn truncate_string(s: &str, length: usize) -> String {
    if s.len() > length {
        format!("{}...", &s[0..length])
    } else {
        s.to_string()
    }
}

pub fn extract_strings_from_buffer(data: &[u8], section_offset: usize, min_length: usize) -> Vec<HashMap<String, String>> {
    let mut strings = Vec::new();
    let mut current_string = Vec::new();
    let mut start_offset = 0;

    let max_length_to_display = 60;

    for (i, &byte) in data.iter().enumerate() {
        if byte.is_ascii_graphic() || byte.is_ascii_whitespace() {

            if current_string.is_empty() {
                start_offset = i;
            }
            current_string.push(byte);
        } else if !current_string.is_empty() {
            if current_string.len() >= min_length {
                // Add the string
                let offset = format!("0x{:X}", section_offset + start_offset);
                let string_utf8 = String::from_utf8_lossy(&current_string).into_owned();
                let string_length = format!("0x{:X}", string_utf8.len());
                
                let mut strmap: HashMap<String, String> = HashMap::new();
                strmap.insert("offset".to_string(), offset);
                strmap.insert("length".to_string(), string_length);
                strmap.insert(
                    "string".to_string(),
                    truncate_string(
                        &string_utf8.replace("\n", " ").replace("\r", "").replace("\t", " "),
                        max_length_to_display,
                    ),
                );

                strings.push(strmap);
            }
            current_string.clear();
        }
    }

    // Add remaining string
    if current_string.len() >= min_length {
        let offset = format!("0x{:X}", section_offset + start_offset);
        let string_utf8 = String::from_utf8_lossy(&current_string).into_owned();
        let string_length = format!("0x{:X}", string_utf8.len());

        let mut strmap: HashMap<String, String> = HashMap::new();
        strmap.insert("offset".to_string(), offset);
        strmap.insert("length".to_string(), string_length);
        strmap.insert(
            "string".to_string(),
            truncate_string(
                &string_utf8.replace("\n", " ").replace("\r", "").replace("\t", " "),
            max_length_to_display,
            ),
        );

        strings.push(strmap);
    }

    strings
}
