//! Statistical validation of AunsormNativeRng
//! 
//! This test validates that the native RNG produces statistically uniform distributions
//! matching the results documented in certifications/audit/native_rng_entropy_analysis.md

use aunsorm_core::AunsormNativeRng;
use rand_core::RngCore;

/// Chi-square goodness of fit test
fn chi_square_test(observed: &[u64], expected: f64) -> (f64, f64) {
    let df = observed.len() as f64 - 1.0;
    let chi_square: f64 = observed
        .iter()
        .map(|&obs| {
            let diff = obs as f64 - expected;
            (diff * diff) / expected
        })
        .sum();
    
    // Approximate p-value using chi-square distribution
    // For large df, chi-square ~ N(df, 2*df)
    let mean = df;
    let std_dev = (2.0 * df).sqrt();
    let z = (chi_square - mean) / std_dev;
    
    // Two-tailed p-value approximation
    let p_value = if z.abs() > 3.0 {
        0.0027 // Very unlikely
    } else if z.abs() > 2.0 {
        0.0455
    } else if z.abs() > 1.0 {
        0.3173
    } else {
        0.6827
    };
    
    (chi_square, p_value)
}

#[test]
#[ignore = "Long-running statistical test - run with --ignored flag"]
fn test_interval_0_to_100_distribution() {
    let mut rng = AunsormNativeRng::new();
    let samples = 10_000_000_u64;
    let num_bins = 101; // [0, 100] inclusive
    let mut bins = vec![0_u64; num_bins];
    
    println!("\n=== Testing Interval [0, 100] with {} samples ===", samples);
    println!("Testing AunsormNativeRng directly with u64 → [0, 100] mapping");
    
    for _ in 0..samples {
        let raw = rng.next_u64();
        // Map to [0, 100] using modulo (for testing, rejection sampling would be better)
        let value = (raw % 101) as usize;
        bins[value] += 1;
    }
    
    // Calculate statistics
    let sum: u64 = bins.iter().enumerate().map(|(i, &count)| i as u64 * count).sum();
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
    
    // Chi-square should be reasonable (not too far from df=100)
    assert!(
        chi_square > 70.0 && chi_square < 130.0,
        "Chi-square out of reasonable range: {}",
        chi_square
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
    
    println!("\n=== Testing Interval [1, 10,000] with {} samples ===", samples);
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
        chi_square > 70.0 && chi_square < 130.0,
        "Chi-square out of reasonable range: {}",
        chi_square
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
    let range_max = u64::MAX;
    let num_bins = 11; // [u64::MAX-10, u64::MAX] = 11 values
    
    let mut bins = vec![0_u64; num_bins];
    let mut sum_f64 = 0.0_f64; // Use f64 for large numbers
    
    println!("\n=== Testing Interval [u64::MAX-10, u64::MAX] with {} samples ===", samples);
    println!("Testing AunsormNativeRng directly in extreme high range");
    
    for _ in 0..samples {
        let raw = rng.next_u64();
        // Map to [u64::MAX-10, u64::MAX]
        let value = range_min + (raw % 11);
        let bin_index = (value - range_min) as usize;
        bins[bin_index] += 1;
        
        // Calculate mean using floating point to avoid overflow
        sum_f64 += value as f64;
    }
    
    let mean_observed = sum_f64 / samples as f64;
    let mean_expected = (range_min as f64 + range_max as f64) / 2.0;
    
    let expected_per_bin = samples as f64 / num_bins as f64;
    let (chi_square, p_value) = chi_square_test(&bins, expected_per_bin);
    
    println!("Mean (Observed):  {:.1}", mean_observed);
    println!("Mean (Expected):  {:.1}", mean_expected);
    println!("χ² Statistic:     {:.2}", chi_square);
    println!("p-value:          {:.2}", p_value);
    
    assert!(
        (mean_observed - mean_expected).abs() < 1.0,
        "Mean deviation too large: observed={}, expected={}",
        mean_observed,
        mean_expected
    );
    
    assert!(
        chi_square > 0.0 && chi_square < 30.0,
        "Chi-square out of reasonable range: {}",
        chi_square
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
    
    let sum: u64 = bins.iter().enumerate().map(|(i, &count)| i as u64 * count).sum();
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
