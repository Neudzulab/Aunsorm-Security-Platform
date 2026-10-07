//! Shared upper-tail chi-square calculation for RNG tests and benchmarks.
use statrs::distribution::{ChiSquared, ContinuousCDF};

pub fn chi_square_test(observed: &[u64], expected: f64) -> (f64, f64) {
    assert!(observed.len() >= 2);
    assert!(expected.is_finite() && expected > 0.0);
    let statistic = observed
        .iter()
        .map(|&count| {
            let difference = count as f64 - expected;
            difference * difference / expected
        })
        .sum();
    let distribution = ChiSquared::new((observed.len() - 1) as f64)
        .expect("chi-square degrees of freedom must be positive");
    (statistic, distribution.sf(statistic))
}
