pub fn shannon(span: &[u8]) -> f64 {
    if span.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in span {
        counts[b as usize] += 1;
    }
    let len = span.len() as f64;
    counts.iter().fold(0.0, |acc, &c| {
        if c == 0 {
            return acc;
        }
        let p = c as f64 / len;
        acc - p * p.log2()
    })
}
