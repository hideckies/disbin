pub fn convert_option_string_to_option_usize(opt: Option<String>) -> Option<usize> {
    opt.and_then(|s| {
        let s = s.trim_start_matches("0x");
        usize::from_str_radix(s, 16).ok()
    })
}