use goblin::elf::Elf;
use std::collections::HashMap;
use termimad::minimad::TextTemplate;

use crate::utils::style::init_skin;

struct VersionAuxiliary {
    name: String,
    hash: u32,
    hash_string: String,
    flags: u16,
    flags_string: String,
    version: u16,
    version_string: String,
}

struct VersionInfo {
    file_name: String,
    cnt: u16,
    cnt_string: String,
    auxiliaries: Vec<VersionAuxiliary>,
}

pub fn display_elf_version_info(elf: &Elf) {
    if let Some(verneed) = &elf.verneed {
        let mut version_infos: Vec<VersionInfo> = Vec::new();

        for v in verneed.iter() {
            let file_name = match elf.dynstrtab.get_at(v.vn_file) {
                Some(n) => n.to_string(),
                None => "???".to_string(),
            };

            let cnt = v.vn_cnt;
            let cnt_string = format!("0x{:X}", cnt);

            let mut auxiliaries: Vec<VersionAuxiliary> = Vec::new();

            for vernaux in v.iter() {
                let mut name = "???".to_string();
                if let Some(aux_name) = elf.dynstrtab.get_at(vernaux.vna_name as usize) {
                    name = aux_name.to_string();
                }
                
                let hash = vernaux.vna_hash;
                let hash_string = format!("0x{:X}", hash);
                let flags = vernaux.vna_flags;
                let flags_string = format!("0x{:X}", flags);
                let version = vernaux.vna_other;
                let version_string = format!("0x{:X}", version);

                auxiliaries.push(VersionAuxiliary {
                    name,
                    hash,
                    hash_string,
                    flags,
                    flags_string,
                    version,
                    version_string,
                });
            }
            // let version = v.vn_version;

            version_infos.push(VersionInfo {
                file_name,
                cnt,
                cnt_string,
                auxiliaries,
            });
        }

        let text_template = TextTemplate::from(r#"
# Version References
|:-|:-|:-|:-|:-|
|**File**|**Name**|**Name Hash**|**Flags**|**Version**|
|-
${rows
|${file_name}|${aux_name}|${aux_hash}|${aux_flags}|${aux_version}|
|-
}
        "#);
        let mut expander = text_template.expander();
        for version_info in version_infos.iter() {
            for (i, aux) in version_info.auxiliaries.iter().enumerate() {
                if i == 0 {
                    expander.sub("rows")
                        .set("file_name", &version_info.file_name)
                        .set("aux_name", &aux.name)
                        .set("aux_hash", &aux.hash_string)
                        .set("aux_flags", &aux.flags_string)
                        .set("aux_version", &aux.version_string);
                } else {
                    expander.sub("rows")
                        .set("file_name", "")
                        .set("aux_name", &aux.name)
                        .set("aux_hash", &aux.hash_string)
                        .set("aux_flags", &aux.flags_string)
                        .set("aux_version", &aux.version_string);
                }
            }
        }
        let skin = init_skin();
        println!();
        skin.print_expander(expander);
        println!();  
    } else {
        let text_template = TextTemplate::from(r#"
# Version References

no version references
        "#);
        let expander = text_template.expander();
        let skin = init_skin();
        println!();
        skin.print_expander(expander);
        println!();  
    }
}