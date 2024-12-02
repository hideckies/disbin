use goblin::elf::Elf;
use termimad::minimad::TextTemplate;
use std::collections::HashMap;

use crate::utils::style::init_skin;

pub fn display_elf_dynamic_section(elf: &Elf) {
    // Dynamic Section
    if let Some(dynamic) = &elf.dynamic {
        let mut dynmaps: Vec<HashMap<String, String>> = Vec::new();

        for d in &dynamic.dyns {
            let mut dynmap: HashMap<String, String> = HashMap::new();

            let tag_name = match d.d_tag {
                goblin::elf::dynamic::DT_ADDRNUM => "ADDRNUM",
                goblin::elf::dynamic::DT_ADDRRNGHI => "ADDRRNGHI",
                goblin::elf::dynamic::DT_ADDRRNGLO => "ADDRRNGLO",
                goblin::elf::dynamic::DT_AUDIT => "AUDIT",
                goblin::elf::dynamic::DT_BIND_NOW => "BIND_NOW",
                goblin::elf::dynamic::DT_CONFIG => "CONFIG",
                goblin::elf::dynamic::DT_DEBUG => "DEBUG",
                goblin::elf::dynamic::DT_DEPAUDIT => "DEPAUDIT",
                goblin::elf::dynamic::DT_ENCODING => "ENCODING",
                goblin::elf::dynamic::DT_FINI => "FINI",
                goblin::elf::dynamic::DT_FINI_ARRAY => "FINI_ARRAY",
                goblin::elf::dynamic::DT_FINI_ARRAYSZ => "FINI_ARRAYSZ",
                goblin::elf::dynamic::DT_FLAGS => "FLAGS",
                goblin::elf::dynamic::DT_FLAGS_1 => "FLAGS_1",
                goblin::elf::dynamic::DT_GNU_CONFLICT => "CONFLICT",
                goblin::elf::dynamic::DT_GNU_HASH => "GNU_HASH",
                goblin::elf::dynamic::DT_GNU_LIBLIST => "GNU_LIBLIST",
                goblin::elf::dynamic::DT_HASH => "HASH",
                goblin::elf::dynamic::DT_HIOS => "HIOS",
                goblin::elf::dynamic::DT_HIPROC => "HIPROC",
                goblin::elf::dynamic::DT_INIT => "INIT",
                goblin::elf::dynamic::DT_INIT_ARRAY => "INIT_ARRAY",
                goblin::elf::dynamic::DT_INIT_ARRAYSZ => "INIT_ARRAYSZ",
                goblin::elf::dynamic::DT_JMPREL => "JMPREL",
                goblin::elf::dynamic::DT_LOOS => "LOOS",
                goblin::elf::dynamic::DT_LOPROC => "LOPROC",
                goblin::elf::dynamic::DT_MOVETAB => "MOVETAB",
                goblin::elf::dynamic::DT_NEEDED => "NEEDED",
                goblin::elf::dynamic::DT_NULL => "NULL",
                goblin::elf::dynamic::DT_NUM => "NUM",
                goblin::elf::dynamic::DT_PLTGOT => "PLTGOT",
                goblin::elf::dynamic::DT_PLTPAD => "PLTPAD",
                goblin::elf::dynamic::DT_PLTREL => "PLTREL",
                goblin::elf::dynamic::DT_PLTRELSZ => "PLTRELSZ",
                goblin::elf::dynamic::DT_PREINIT_ARRAY => "PREINIT_ARRAY",
                goblin::elf::dynamic::DT_PREINIT_ARRAYSZ => "PREINIT_ARRAYSZ",
                goblin::elf::dynamic::DT_REL => "REL",
                goblin::elf::dynamic::DT_RELA => "RELA",
                goblin::elf::dynamic::DT_RELACOUNT => "RELACOUNT",
                goblin::elf::dynamic::DT_RELAENT => "RELAENT",
                goblin::elf::dynamic::DT_RELASZ => "RELASZ",
                goblin::elf::dynamic::DT_RELCOUNT => "RELCOUNT",
                goblin::elf::dynamic::DT_RELENT => "RELENT",
                goblin::elf::dynamic::DT_RELSZ => "RELSZ",
                goblin::elf::dynamic::DT_RPATH => "RPATH",
                goblin::elf::dynamic::DT_RUNPATH => "RUNPATH",
                goblin::elf::dynamic::DT_SONAME => "SONAME",
                goblin::elf::dynamic::DT_STRSZ => "STRSZ",
                goblin::elf::dynamic::DT_STRTAB => "STRTAB",
                goblin::elf::dynamic::DT_SYMBOLIC => "SYMBOLIC",
                goblin::elf::dynamic::DT_SYMENT => "SYMENT",
                goblin::elf::dynamic::DT_SYMINFO => "SYMINFO",
                goblin::elf::dynamic::DT_SYMTAB => "SYMTAB",
                goblin::elf::dynamic::DT_TEXTREL => "TEXTREL",
                goblin::elf::dynamic::DT_TLSDESC_GOT => "TLSDESC_GOT",
                goblin::elf::dynamic::DT_TLSDESC_PLT => "TLSDESC_PLT",
                goblin::elf::dynamic::DT_VERDEF => "VERDEF",
                goblin::elf::dynamic::DT_VERDEFNUM => "VERDEFNUM",
                goblin::elf::dynamic::DT_VERNEED => "VERNEED",
                goblin::elf::dynamic::DT_VERNEEDNUM => "VERNEEDNUM",
                goblin::elf::dynamic::DT_VERSYM => "VERSYM",
                _ => "???",
            };

            let name = match elf.dynstrtab.get_at(d.d_val as usize) {
                Some(s) => {
                    if s == "" {
                        format!("0x{:X}", d.d_val)
                    } else {
                        s.to_string()
                    }
                },
                None => format!("0x{:X}", d.d_val),
            };

            dynmap.insert("tag".to_string(), tag_name.to_string());
            dynmap.insert("name".to_string(), name);

            dynmaps.push(dynmap);
        }

        let text_template = TextTemplate::from(r#"
# Dynamic Section
|:-|:-|
|**Tag**|**Name**|
|-
${rows
|${tag}|${name}|
|-
}
        "#);
        let mut expander = text_template.expander();
        for dynmap in dynmaps.iter() {
            expander.sub("rows")
                .set("tag", dynmap.get("tag").unwrap())
                .set("name", dynmap.get("name").unwrap());
        }
        let skin = init_skin();
        println!();
        skin.print_expander(expander);
        println!();
    } else {
        let text_template = TextTemplate::from(r#"
# Dynamic Section

no dynamic section
        "#);
        let expander = text_template.expander();
        let skin = init_skin();
        println!();
        skin.print_expander(expander);
        println!();   
    }
}