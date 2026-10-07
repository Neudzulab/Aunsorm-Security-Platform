//! RNG Performance and Quality Comparison
//!
//! Compares native fast-key-erasure RNG with standard ChaCha20Rng.
//! The external generator is used only as a benchmark reference.
//!
//! Results are hardware-dependent measurements, not security certifications.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

// Only the new sealed RNG is used in production
use aunsorm_core::AunsormNativeRng;

#[path = "../tests/support/rng_statistics.rs"]
mod rng_statistics;
use rng_statistics::chi_square_test;

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
        group.bench_with_input(
            BenchmarkId::new("standard_chacha20", size),
            size,
            |b, &size| {
                let mut rng = ChaCha20Rng::from_entropy();
                let mut buffer = vec![0_u8; size];
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

    group.bench_function("standard_chacha20", |b| {
        let mut rng = ChaCha20Rng::from_entropy();
        b.iter(|| black_box(rng.next_u64()));
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
            let mut counts = vec![0_u64; BINS];
            for sample in samples {
                counts[(sample % RANGE) as usize] += 1;
            }
            let (chi_sq, p_val) = chi_square_test(&counts, SAMPLES as f64 / BINS as f64);
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
