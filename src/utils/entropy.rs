use std::collections::HashMap;

// Ref: https://gist.github.com/elij/2ba5865c8664f67cf36f
pub fn calc_entropy(data: &Vec<u8>) -> f32 {
    let len = data.len() as f32;
    let hist = data.iter().fold(
        HashMap::new(), |mut acc, e| {
            *acc.entry(e).or_insert(0) = *acc.entry(e).or_insert(0) + 1;
            acc
        }
    );
    let i = hist.values().fold(0f32, |ac, &x| {
        let f = x as f32 / len;
        ac - (f * f.log2())
    });
    i
}