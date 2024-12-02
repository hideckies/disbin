use goblin::Object;
use termimad::minimad::TextTemplate;

use crate::utils::{
    hash::{
        hash_md5,
        hash_sha1,
        hash_sha2_256, hash_sha2_512,
        hash_sha3_256, hash_sha3_512,
        hash_pe_imphash,
        hash_pe_rich_header_hash,
    },
    style::init_skin,
};

enum ObjType {
    Elf,
    PE,
}

pub fn display_common_hashes(filebuf: &Vec<u8>) {
    // Calculate hashes
    let i_md5 = hash_md5(filebuf);
    let i_sha1 = hash_sha1(filebuf);
    let i_sha2_256 = hash_sha2_256(filebuf);
    let i_sha2_512 = hash_sha2_512(filebuf);
    let i_sha3_256 = hash_sha3_256(filebuf);
    let i_sha3_512 = hash_sha3_512(filebuf);
    let mut i_imphash = "???".to_string();
    let mut i_rich_header_hash = "???".to_string();

    // Calculate format-specific hashes.
    match Object::parse(filebuf) {
        Ok(obj) => {
            match obj {
                Object::Elf(elf) => {},
                Object::PE(pe) => {
                    i_imphash = hash_pe_imphash(&pe);
                    i_rich_header_hash = hash_pe_rich_header_hash(filebuf);
                },
                _ => {},
            }
        },
        Err(e) => {},

    };

    let text_template = TextTemplate::from(r#"
# File Hashes
|:-|:-|
|**MD5**|${md5}|
|-
|**SHA1**|${sha1}|
|-
|**SHA2-256**|${sha2_256}|
|-
|**SHA2-512**|${sha2_512}|
|-
|**SHA3-256**|${sha3_256}|
|-
|**SHA3-512**|${sha3_512}|
|-
|**ImpHash**|${imphash}|
|-
|**Rich Header Hash**|${rich_header_hash}|
|-
    "#);

    let mut expander = text_template.expander();
    expander
        .set("md5", &i_md5)
        .set("sha1", &i_sha1)
        .set("sha2_256", &i_sha2_256)
        .set("sha2_512", &i_sha2_512)
        .set("sha3_256", &i_sha3_256)
        .set("sha3_512", &i_sha3_512)
        .set("imphash", &i_imphash)
        .set("rich_header_hash", &i_rich_header_hash);

    let skin = init_skin();
    println!();
    skin.print_expander(expander);
    println!();
}