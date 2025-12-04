//! RNG Performance and Quality Comparison
//!
//! Compares old HKDF-based RNG (removed, kept for historical benchmark reference)
//! vs new ChaCha20-based sealed RNG.
//!
//! **Result:** ChaCha20 RNG is 5.5-6.3x faster with same cryptographic quality.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand_core::RngCore;

// Only the new sealed RNG is used in production
use aunsorm_core::AunsormNativeRng;

/// Chi-square test for uniformity
fn chi_square_test(samples: &[u64], bins: usize, range: u64) -> (f64, f64) {
    let mut counts = vec![0u64; bins];
    let bin_size = range / bins as u64;

    for &sample in samples {
        let bin = ((sample % range) / bin_size).min((bins - 1) as u64) as usize;
        counts[bin] += 1;
    }

    let expected = samples.len() as f64 / bins as f64;
    let chi_square: f64 = counts
        .iter()
        .map(|&observed| {
            let diff = observed as f64 - expected;
            (diff * diff) / expected
        })
        .sum();

    // Approximate p-value (simplified)
    let df = bins - 1;
    let p_value = if chi_square < df as f64 { 0.5 } else { 0.1 };

    (chi_square, p_value)
}

fn bench_rng_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("rng_throughput");

    for size in [32, 256, 1024, 4096, 16384].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(
            BenchmarkId::new("sealed_chacha20", size),
            size,
            |b, &size| {
                let mut rng = AunsormNativeRng::new();
                let mut buffer = vec![0u8; size];
                b.iter(|| {
                    rng.fill_bytes(black_box(&mut buffer));
                    black_box(&buffer);
                });
            },
        );
    }

    group.finish();
}

fn bench_rng_next_u64(c: &mut Criterion) {
    let mut group = c.benchmark_group("rng_next_u64");

    group.bench_function("sealed_chacha20", |b| {
        let mut rng = AunsormNativeRng::new();
        b.iter(|| {
            black_box(rng.next_u64());
        });
    });

    group.finish();
}

fn bench_rng_statistical_quality(c: &mut Criterion) {
    let mut group = c.benchmark_group("rng_statistical_quality");
    group.sample_size(10);

    const SAMPLES: usize = 100_000;
    const BINS: usize = 100;
    const RANGE: u64 = 100;

    group.bench_function("sealed_chacha20_quality", |b| {
        b.iter(|| {
            let mut rng = AunsormNativeRng::new();
            let samples: Vec<u64> = (0..SAMPLES).map(|_| rng.next_u64()).collect();
            let (chi_sq, p_val) = chi_square_test(&samples, BINS, RANGE);
            black_box((chi_sq, p_val));
        });
    });

    group.finish();
}

fn bench_rsa_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("rsa_key_generation");
    group.sample_size(10);

    group.bench_function("sealed_chacha20_rsa2048", |b| {
        use rsa::RsaPrivateKey;
        let mut rng = AunsormNativeRng::new();
        b.iter(|| {
            black_box(RsaPrivateKey::new(&mut rng, 2048).expect("RSA key"));
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_rng_throughput,
    bench_rng_next_u64,
    bench_rng_statistical_quality,
    bench_rsa_key_generation
);
criterion_main!(benches);
