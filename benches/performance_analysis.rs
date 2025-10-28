use std::time::Instant;

use aunsorm_x509::ca::{
    generate_root_ca, KeyAlgorithm, RootCaParams,
};
use aunsorm_x509::optimizations::RsaPerformanceMetrics;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

/// Enhanced benchmark with performance monitoring
fn bench_root_generation_with_metrics(c: &mut Criterion) {
    let mut group = c.benchmark_group("x509_root_generation_optimized");
    
    // Set sample sizes for different key types
    group.sample_size(10); // Reduced for RSA-4096 due to long generation times
    
    group.bench_function("ed25519", |b| {
        b.iter(|| {
            let empty_strings: &[String] = &[];
            let params = RootCaParams {
                common_name: "Optimized Benchmark Root Ed25519",
                org_salt: b"opt-bench-root-ed25519",
                calibration_text: "Optimized Benchmark Root Calibration Ed25519",
                validity_days: 3650,
                cps_uris: empty_strings,
                policy_oids: empty_strings,
                key_algorithm: Some(KeyAlgorithm::Ed25519),
            };
            black_box(generate_root_ca(&params).expect("ed25519 root"));
        });
    });

    // RSA benchmarks with performance monitoring
    let algorithms = [
        (KeyAlgorithm::Rsa2048, 2048, "rsa2048"),
        (KeyAlgorithm::Rsa4096, 4096, "rsa4096"),
    ];
    
    for (algorithm, bits, name) in algorithms {
        group.bench_with_input(BenchmarkId::new("rsa_optimized", name), &bits, |b, &bits| {
            let mut metrics = RsaPerformanceMetrics::new();
            
            b.iter_custom(|iters| {
                let start = Instant::now();
                
                for _ in 0..iters {
                    let gen_start = Instant::now();
                    
                    let empty_strings: &[String] = &[];
                    let common_name = format!("Optimized Benchmark Root RSA {}", bits);
                    let org_salt = format!("opt-bench-root-rsa{}", bits);
                    let calibration_text = format!("Optimized Benchmark Root Calibration RSA {}", bits);
                    
                    let params = RootCaParams {
                        common_name: &common_name,
                        org_salt: org_salt.as_bytes(),
                        calibration_text: &calibration_text,
                        validity_days: 3650,
                        cps_uris: empty_strings,
                        policy_oids: empty_strings,
                        key_algorithm: Some(algorithm),
                    };
                    
                    black_box(generate_root_ca(&params).expect(&format!("rsa{} root", bits)));
                    
                    let gen_duration = gen_start.elapsed();
                    metrics.record_key_generation(gen_duration.as_millis() as u64);
                }
                
                let total_duration = start.elapsed();
                
                // Report performance metrics
                eprintln!(
                    "\n=== RSA-{} Performance Metrics ===", 
                    bits
                );
                eprintln!(
                    "Average generation time: {:.2} ms", 
                    metrics.avg_key_generation_ms()
                );
                eprintln!(
                    "Outliers detected: {} out of {} samples", 
                    metrics.outliers_count(), 
                    iters
                );
                
                if metrics.outliers_count() > iters as usize / 10 {
                    eprintln!(
                        "⚠️  WARNING: High outlier ratio ({}%) for RSA-{}", 
                        (metrics.outliers_count() * 100) / iters as usize,
                        bits
                    );
                }
                
                total_duration
            });
        });
    }

    group.finish();
}

/// Benchmark with entropy source analysis
fn bench_entropy_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("entropy_analysis");
    
    group.bench_function("os_rng_entropy", |b| {
        b.iter(|| {
            use rand_core::{OsRng, RngCore};
            let mut rng = OsRng;
            let mut buffer = [0u8; 32];
            black_box(rng.fill_bytes(&mut buffer));
            buffer
        });
    });
    
    group.finish();
}

/// Memory allocation pattern analysis
fn bench_memory_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_analysis");
    
    group.bench_function("rsa2048_memory", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            
            for _ in 0..iters {
                // Measure peak memory usage during RSA generation
                let empty_strings: &[String] = &[];
                let params = RootCaParams {
                    common_name: "Memory Test RSA 2048",
                    org_salt: b"memory-test-rsa2048",
                    calibration_text: "Memory Test RSA 2048 Calibration",
                    validity_days: 365,
                    cps_uris: empty_strings,
                    policy_oids: empty_strings,
                    key_algorithm: Some(KeyAlgorithm::Rsa2048),
                };
                
                black_box(generate_root_ca(&params).expect("memory test rsa2048"));
                
                // Force garbage collection to measure actual memory impact
                // GC analysis would require additional tools
            }
            
            start.elapsed()
        });
    });
    
    group.finish();
}

/// System resource contention analysis
fn bench_concurrent_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrency_analysis");
    
    group.bench_function("concurrent_rsa2048", |b| {
        b.iter(|| {
            use std::thread;
            
            let handles: Vec<_> = (0..4).map(|i| {
                thread::spawn(move || {
                    let empty_strings: &[String] = &[];
                    let common_name = format!("Concurrent RSA 2048 #{}", i);
                    let org_salt = format!("concurrent-rsa2048-{}", i);
                    let calibration_text = format!("Concurrent RSA 2048 Calibration #{}", i);
                    
                    let params = RootCaParams {
                        common_name: &common_name,
                        org_salt: org_salt.as_bytes(),
                        calibration_text: &calibration_text,
                        validity_days: 365,
                        cps_uris: empty_strings,
                        policy_oids: empty_strings,
                        key_algorithm: Some(KeyAlgorithm::Rsa2048),
                    };
                    
                    generate_root_ca(&params).expect("concurrent rsa2048")
                })
            }).collect();
            
            let results: Vec<_> = handles.into_iter()
                .map(|h| h.join().unwrap())
                .collect();
            
            black_box(results);
        });
    });
    
    group.finish();
}

criterion_group!(
    benches, 
    bench_root_generation_with_metrics,
    bench_entropy_performance,
    bench_memory_patterns,
    bench_concurrent_operations
);
criterion_main!(benches);