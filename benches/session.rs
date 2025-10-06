use aunsorm_core::SessionRatchet;
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_ratchet(c: &mut Criterion) {
    c.bench_function("session_ratchet_next", |b| {
        b.iter(|| {
            let mut ratchet = SessionRatchet::new([1_u8; 32], [2_u8; 16], false);
            for _ in 0..32 {
                let _ = ratchet.next_step().expect("ratchet");
            }
        });
    });
}

criterion_group!(session, bench_ratchet);
criterion_main!(session);
