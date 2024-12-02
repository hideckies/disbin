use goblin::pe::PE;
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use std::collections::HashMap;

use crate::utils::map::{MAP_COMCTL32_ORDINAL, MAP_OLEAUT32_ORDINAL, MAP_WS2_32_ORDINAL};

use super::map::MAP_WSOCK32_ORDINAL;

pub fn hash_md5(buf: &Vec<u8>) -> String {
    let mut hasher = Md5::new();
    hasher.update(buf);
    format!("0x{:X}", hasher.finalize())
}

pub fn hash_sha1(buf: &Vec<u8>) -> String {
    let mut hasher = Sha1::new();
    hasher.update(buf);
    format!("0x{:X}", hasher.finalize())
}

pub fn hash_sha2_256(buf: &Vec<u8>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(buf);
    format!("0x{:X}", hasher.finalize())
}

pub fn hash_sha2_512(buf: &Vec<u8>) -> String {
    let mut hasher = Sha512::new();
    hasher.update(buf);
    format!("0x{:X}", hasher.finalize())
}

pub fn hash_sha3_256(buf: &Vec<u8>) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(buf);
    format!("0x{:X}", hasher.finalize())
}

pub fn hash_sha3_512(buf: &Vec<u8>) -> String {
    let mut hasher = Sha3_512::new();
    hasher.update(buf);
    format!("0x{:X}", hasher.finalize())
}

pub fn hash_pe_imphash(pe: &PE) -> String {    
    let mut import_strings = Vec::new();

    for import in &pe.imports {
        let dll_name = import.dll.replace(".dll", "").replace(".sys", "").to_ascii_lowercase();
        let mut func_name = import.name.to_ascii_lowercase();
        // Resolve a correct function name for some DLLs.
        if dll_name == "comctl32" && func_name.starts_with("ordinal ") {
            func_name = MAP_COMCTL32_ORDINAL.get(&import.ordinal).unwrap().to_ascii_lowercase();
        } else if dll_name == "oleaut32" && func_name.starts_with("ordinal ") {
            func_name = MAP_OLEAUT32_ORDINAL.get(&import.ordinal).unwrap().to_ascii_lowercase();
        } else if dll_name == "ws2_32" && func_name.starts_with("ordinal ") {
            func_name = MAP_WS2_32_ORDINAL.get(&import.ordinal).unwrap().to_ascii_lowercase();
        } else if dll_name == "wsock32" && func_name.starts_with("ordinal ") {
            func_name = MAP_WSOCK32_ORDINAL.get(&import.ordinal).unwrap().to_ascii_lowercase();
        }
        // If the function name could not be resolved, it reluctantly return the '???' result.
        if func_name.starts_with("ordinal ") {
            return "???".to_string();
        }

        import_strings.push(format!("{}.{}", dll_name, func_name));
    }

    hash_md5(&import_strings.join(",").as_bytes().to_vec())
}

// It refers to the `display_pe_rich_header` function in `pe/headers.rs`.
// I think this is dirty code.
pub fn hash_pe_rich_header_hash(filebuf: &Vec<u8>) -> String {
    // Extract Rich Header from file buffer.
    let rich_signature = &[0x52, 0x69, 0x63, 0x68]; // "Rich"
    if let Some(end_offset) = filebuf
        .windows(rich_signature.len())
        .position(|window| window == rich_signature) {

        // XOR key (DWORD) exists after "Rich" signature
        let mut xor_key = filebuf[end_offset + rich_signature.len()..end_offset + rich_signature.len() + 4].to_vec();

        // Get the start offset by looping backwards and stop when reaches "DanS"
        let mut start_offset = end_offset + 8;
        let chunk_size = 4;
        let target_buf = &filebuf[..end_offset + 8];
        let mut target_buf_rev: Vec<u8> = target_buf.iter().rev().cloned().collect();
        for chunk in target_buf_rev.chunks_mut(chunk_size) {
            start_offset -= std::mem::size_of::<u8>() * 4;
            
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

        let rich_bufs = &filebuf[start_offset..end_offset + 8];

        xor_key.reverse();

        // Get XOR decoded values and clear data.
        let mut clear_data: Vec<u8> = Vec::new();
        let mut current_idx = 0;
        let mut proceed_size = 0;
        while current_idx < rich_bufs.len() {
            let mut value: Vec<u8> = Vec::new();
            let mut unmasked_value: Vec<u8> = Vec::new();

            if current_idx == 0 {
                // "DanS"

                value = rich_bufs[current_idx..current_idx + 4].to_vec();
                value.reverse();

                // XOR
                for (i, byte) in value.iter().enumerate() {
                    unmasked_value.push(*byte ^ xor_key[i]);
                }
                unmasked_value.reverse();

                proceed_size = 4;

                clear_data.extend(unmasked_value);
            } else if 4 <= current_idx && current_idx <= 15 {
                // Null bytes

                value = rich_bufs[current_idx..current_idx + 4].to_vec();
                value.reverse();

                // XOR
                for (i, byte) in value.iter().enumerate() {
                    unmasked_value.push(*byte ^ xor_key[i]);
                }

                proceed_size = 4;

                clear_data.extend(unmasked_value);
            } else if current_idx < rich_bufs.len() - 8 {
                // Comp IDs

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
                unmasked_value1.reverse();
                clear_data.extend(unmasked_value1);

                let mut unmasked_value2: Vec<u8> = Vec::new();
                for (i, byte) in value2.iter().enumerate() {
                    unmasked_value2.push(*byte ^ xor_key[i]);
                }
                unmasked_value2.reverse();
                clear_data.extend(unmasked_value2);

                proceed_size = 8;
            } else {
                // Rich ID, Checksum
                proceed_size = 4;
            }

            // Proceed
            current_idx += proceed_size;
        }

        hash_md5(&clear_data)
    } else {
        "???".to_string()
    }
}