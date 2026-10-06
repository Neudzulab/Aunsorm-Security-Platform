//! Statistical validation of AunsormNativeRng
//!
//! This test validates that the native RNG produces statistically uniform distributions
//! using actual chi-square upper-tail probabilities, not a security certification.

use aunsorm_core::AunsormNativeRng;
use rand_core::RngCore;

#[path = "../support/rng_statistics.rs"]
mod rng_statistics;
use rng_statistics::chi_square_test;

#[test]
#[ignore = "Long-running statistical test - run with --ignored flag"]
fn test_interval_0_to_100_distribution() {
    let mut rng = AunsormNativeRng::new();
    let samples = 10_000_000_u64;
    let num_bins = 101; // [0, 100] inclusive
    let mut bins = vec![0_u64; num_bins];

    println!(
        "\n=== Testing Interval [0, 100] with {} samples ===",
        samples
    );
    println!("Testing AunsormNativeRng directly with u64 → [0, 100] mapping");

    for _ in 0..samples {
        let raw = rng.next_u64();
        // Map to [0, 100] using modulo (for testing, rejection sampling would be better)
        let value = (raw % 101) as usize;
        bins[value] += 1;
    }

    // Calculate statistics
    let sum: u64 = bins
        .iter()
        .enumerate()
        .map(|(i, &count)| i as u64 * count)
        .sum();
    let mean_observed = sum as f64 / samples as f64;
    let mean_expected = 50.0;

    let expected_per_bin = samples as f64 / num_bins as f64;
    let (chi_square, p_value) = chi_square_test(&bins, expected_per_bin);

    println!("Mean (Observed):  {:.3}", mean_observed);
    println!("Mean (Expected):  {:.3}", mean_expected);
    println!("χ² Statistic:     {:.2}", chi_square);
    println!("p-value:          {:.2}", p_value);

    // Validate results match the audit report
    assert!(
        (mean_observed - mean_expected).abs() < 1.0,
        "Mean deviation too large: observed={}, expected={}",
        mean_observed,
        mean_expected
    );

    // p-value should not reject null hypothesis at α=0.01
    assert!(
        p_value > 0.01,
        "Distribution rejected at α=0.01: p-value={}",
        p_value
    );
}

#[test]
#[ignore = "Long-running statistical test - run with --ignored flag"]
fn test_interval_1_to_10000_distribution() {
    let mut rng = AunsormNativeRng::new();
    let samples = 10_000_000_u64;
    let range_size = 10_000_u64;
    let num_bins = 100; // Group into 100 bins for chi-square
    let bin_size = range_size / num_bins as u64;

    let mut bins = vec![0_u64; num_bins];
    let mut sum = 0_u64;

    println!(
        "\n=== Testing Interval [1, 10,000] with {} samples ===",
        samples
    );
    println!("Testing AunsormNativeRng directly with u64 → [1, 10000] mapping");

    for _ in 0..samples {
        let raw = rng.next_u64();
        let value = 1 + (raw % range_size);
        sum += value;
        let bin_index = ((value - 1) / bin_size).min(num_bins as u64 - 1) as usize;
        bins[bin_index] += 1;
    }

    let mean_observed = sum as f64 / samples as f64;
    let mean_expected = (1.0 + range_size as f64) / 2.0;

    let expected_per_bin = samples as f64 / num_bins as f64;
    let (chi_square, p_value) = chi_square_test(&bins, expected_per_bin);

    println!("Mean (Observed):  {:.3}", mean_observed);
    println!("Mean (Expected):  {:.3}", mean_expected);
    println!("χ² Statistic:     {:.2}", chi_square);
    println!("p-value:          {:.2}", p_value);

    assert!(
        (mean_observed - mean_expected).abs() < 10.0,
        "Mean deviation too large: observed={}, expected={}",
        mean_observed,
        mean_expected
    );

    assert!(
        p_value > 0.01,
        "Distribution rejected at α=0.01: p-value={}",
        p_value
    );
}

#[test]
#[ignore = "Long-running statistical test - run with --ignored flag"]
fn test_high_range_distribution() {
    let mut rng = AunsormNativeRng::new();
    let samples = 5_000_000_u64;
    let range_min = u64::MAX - 10;
    let num_bins = 11; // [u64::MAX-10, u64::MAX] = 11 values

    let mut bins = vec![0_u64; num_bins];
    let mut offset_sum = 0_u64; // Sum small offsets; f64 cannot distinguish these u64 values.

    println!(
        "\n=== Testing Interval [u64::MAX-10, u64::MAX] with {} samples ===",
        samples
    );
    println!("Testing AunsormNativeRng directly in extreme high range");

    for _ in 0..samples {
        let raw = rng.next_u64();
        // Map to [u64::MAX-10, u64::MAX]
        let value = range_min + (raw % 11);
        let bin_index = (value - range_min) as usize;
        bins[bin_index] += 1;

        offset_sum += value - range_min;
    }

    let mean_observed = offset_sum as f64 / samples as f64;
    let mean_expected = 5.0;

    let expected_per_bin = samples as f64 / num_bins as f64;
    let (chi_square, p_value) = chi_square_test(&bins, expected_per_bin);

    println!("Mean offset (Observed):  {:.3}", mean_observed);
    println!("Mean offset (Expected):  {:.3}", mean_expected);
    println!("χ² Statistic:     {:.2}", chi_square);
    println!("p-value:          {:.2}", p_value);

    assert!(
        (mean_observed - mean_expected).abs() < 1.0,
        "Mean deviation too large: observed={}, expected={}",
        mean_observed,
        mean_expected
    );

    assert!(
        p_value > 0.01,
        "Distribution rejected at α=0.01: p-value={}",
        p_value
    );
}

#[test]
fn quick_statistical_smoke_test() {
    // Fast version for CI/CD - only 100K samples
    let mut rng = AunsormNativeRng::new();
    let samples = 100_000_u64;
    let mut bins = vec![0_u64; 101];

    println!("\n=== Quick Smoke Test: AunsormNativeRng ===");

    for _ in 0..samples {
        let raw = rng.next_u64();
        let value = (raw % 101) as usize;
        bins[value] += 1;
    }

    let sum: u64 = bins
        .iter()
        .enumerate()
        .map(|(i, &count)| i as u64 * count)
        .sum();
    let mean = sum as f64 / samples as f64;
    let expected = 50.0;

    println!("Samples: {}", samples);
    println!("Mean: {:.3}, Expected: {:.3}", mean, expected);
    println!("Deviation: {:.3}", (mean - expected).abs());

    // Relaxed bounds for smoke test
    assert!(
        (mean - expected).abs() < 2.0,
        "Smoke test failed: mean deviation too large"
    );
}

#[cfg(test)]
mod statistics_tests {
    use super::chi_square_test;
    use statrs::distribution::{ChiSquared, ContinuousCDF};

    #[test]
    fn historical_report_uses_actual_upper_tail() {
        let distribution = ChiSquared::new(100.0).unwrap();
        assert!((distribution.sf(126.07) - 0.040_048_906_314).abs() < 1e-10);
    }

    #[test]
    fn rejects_constant_generator() {
        let mut counts = [0; 100];
        counts[0] = 100_000;
        let (_, p) = chi_square_test(&counts, 1000.0);
        assert!(p < 0.01);
    }

    #[test]
    fn equal_counts_have_upper_tail_one() {
        assert_eq!(chi_square_test(&[100; 100], 100.0), (0.0, 1.0));
    }
}
