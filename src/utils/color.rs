use colored::{Colorize, CustomColor};

// These constants are used as parameters for the `custom_color()` of the `colored` crate.
pub const CUSTOM_COLOR_GREY: CustomColor = CustomColor {r: 150, g: 150, b: 150};
pub const CUSTOM_COLOR_ORANGE: CustomColor = CustomColor {r: 233, g: 163, b: 38};
pub const CUSTOM_COLOR_YELLOW_GREEN: CustomColor = CustomColor {r: 154, g: 205, b: 50};

// It is used in the `display_disasm` function for each platform.
pub fn highlight_mnemonic(m: &str) -> String {
    if m.starts_with("ad") || m.contains("div") || m.contains("mul") || m.contains("sub") {
        m.red().to_string()
    } else if m.starts_with("j") {
        m.cyan().to_string()
    } else if m.contains("mov") {
        m.green().to_string()
    } else if m == "call" || m == "ret" {
        m.yellow().to_string()
    } else {
        m.purple().to_string()
    }
}

fn highlight_helper(word: &str) -> String {
    let registers = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rip", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
        "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
        "al", "bl", "cl", "dl", "sil", "dil", "spl",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
        "ah", "bh", "ch", "dh",
        "cs", "ds", "es", "fs", "gs", "ss",
        "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7",
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
        "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
        "xmmword",
    ];
    let units = ["byte", "word", "dword", "qword"];
    let misc = ["ptr"];

    if word.starts_with("0x") && word[2..].chars().all(|c| c.is_ascii_hexdigit()) {
        word.green().to_string()
    } else if word.parse::<f64>().is_ok() { // Check if the word is numeric
        word.green().to_string()
    } else if registers.contains(&word) {
        word.red().to_string()
    } else if units.contains(&word) {
        word.blue().to_string()
    } else if misc.contains(&word) {
        word.yellow().to_string()
    } else {
        word.white().to_string()
    }
}

// It is used in the `display_disasm` function for each platform.
pub fn highlight_operand(op: &str) -> String {
    let mut highlighted = String::new();
    let mut word_buffer = String::new();

    for ch in op.chars() {
        match ch {
            ',' | '[' | ']' | ' ' | ';' | '+' | '-' | '*' => {
                if !word_buffer.is_empty() {
                    highlighted.push_str(&highlight_helper(&word_buffer));
                    word_buffer.clear();
                }
                highlighted.push(ch);
            }
            _ => {
                word_buffer.push(ch);
            }
        }
    }

    // Process the last buffer
    if !word_buffer.is_empty() {
        highlighted.push_str(&highlight_helper(&word_buffer));
    }

    highlighted
}