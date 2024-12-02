pub fn find_exponent_of_two(mut num: u64) -> Option<u32> {
    if num == 0 {
        return None;
    }
    let mut exponent = 0;
    while num > 1 {
        if num % 2 != 0 {
            return None;
        }
        num /= 2;
        exponent += 1;
    }
    Some(exponent)
}
