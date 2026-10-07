//! Independently compare corrected Rayon ranges with Rust's standard iterator.
//! Compile against the locked Rayon 1.12 artifact; never run against known bad
//! versions that can construct invalid char values at the surrogate boundary.
#![forbid(unsafe_code)]

use rayon::prelude::*;

fn main() {
    let mut comparisons = 0;
    for (start, end) in [
        ('\u{d7f0}', '\u{e000}'),
        ('\u{d7ff}', '\u{e000}'),
        ('\u{d7f0}', '\u{e001}'),
        ('\u{e000}', '\u{e010}'),
        ('\u{d7f0}', '\u{d7ff}'),
        ('\u{e000}', '\u{e000}'),
    ] {
        let expected: Vec<char> = (start..end).collect();
        let expected_inclusive: Vec<char> = (start..=end).collect();
        for _ in 0..128 {
            let actual: Vec<char> = (start..end).into_par_iter().collect();
            let inclusive: Vec<char> = (start..=end).into_par_iter().collect();
            assert_eq!(actual, expected);
            assert_eq!(inclusive, expected_inclusive);
            comparisons += 2;
        }
    }
    println!("{comparisons} parallel/standard Unicode range comparisons passed");
}
