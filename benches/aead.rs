use aunsorm_core::{
    calibration::calib_from_text,
    coord32_derive,
    kdf::{derive_seed64_and_pdk, KdfPreset, KdfProfile},
    salts::Salts,
};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};

fn bench_coord_derivation(c: &mut Criterion) {
    let profile = KdfProfile::preset(KdfPreset::Medium);
    c.bench_function("coord32_derive", |b| {
        b.iter_batched(
            || {
                let (seed, _, _) = derive_seed64_and_pdk(
                    "bench-password",
                    b"bench-password-salt",
                    b"bench-calibration-salt",
                    b"bench-chain-salt",
                    profile,
                )
                .expect("kdf");
                let (calibration, _) = calib_from_text(b"bench-org", "bench-note");
                let salts = Salts::new(
                    b"bench-calibration-salt".to_vec(),
                    b"bench-chain-salt".to_vec(),
                    b"bench-coord-salt".to_vec(),
                )
                .expect("salts");
                (seed, calibration, salts)
            },
            |(seed, calibration, salts)| {
                let _ = coord32_derive(seed.as_ref(), &calibration, &salts).expect("coord");
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_coord_derivation);
criterion_main!(benches);
