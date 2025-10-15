use std::net::IpAddr;

use aunsorm_x509::ca::{
    generate_root_ca, sign_server_cert, KeyAlgorithm, RootCaParams, ServerCertParams,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_root_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("x509_root_generation");

    group.bench_function("ed25519", |b| {
        b.iter(|| {
            let empty_strings: &[String] = &[];
            let params = RootCaParams {
                common_name: "Benchmark Root Ed25519",
                org_salt: b"bench-root-ed25519",
                calibration_text: "Benchmark Root Calibration Ed25519",
                validity_days: 3650,
                cps_uris: empty_strings,
                policy_oids: empty_strings,
                key_algorithm: Some(KeyAlgorithm::Ed25519),
            };
            black_box(generate_root_ca(&params).expect("ed25519 root"));
        });
    });

    group.bench_function("rsa2048", |b| {
        b.iter(|| {
            let empty_strings: &[String] = &[];
            let params = RootCaParams {
                common_name: "Benchmark Root RSA 2048",
                org_salt: b"bench-root-rsa2048",
                calibration_text: "Benchmark Root Calibration RSA 2048",
                validity_days: 3650,
                cps_uris: empty_strings,
                policy_oids: empty_strings,
                key_algorithm: Some(KeyAlgorithm::Rsa2048),
            };
            black_box(generate_root_ca(&params).expect("rsa2048 root"));
        });
    });

    group.bench_function("rsa4096", |b| {
        b.iter(|| {
            let empty_strings: &[String] = &[];
            let params = RootCaParams {
                common_name: "Benchmark Root RSA 4096",
                org_salt: b"bench-root-rsa4096",
                calibration_text: "Benchmark Root Calibration RSA 4096",
                validity_days: 3650,
                cps_uris: empty_strings,
                policy_oids: empty_strings,
                key_algorithm: Some(KeyAlgorithm::Rsa4096),
            };
            black_box(generate_root_ca(&params).expect("rsa4096 root"));
        });
    });

    group.finish();
}

fn bench_server_signing(c: &mut Criterion) {
    let empty_strings: &[String] = &[];
    let empty_ips: &[IpAddr] = &[];

    let ed_root = generate_root_ca(&RootCaParams {
        common_name: "Bench CA Ed25519",
        org_salt: b"bench-ca-ed25519",
        calibration_text: "Bench CA Calibration Ed25519",
        validity_days: 3650,
        cps_uris: empty_strings,
        policy_oids: empty_strings,
        key_algorithm: Some(KeyAlgorithm::Ed25519),
    })
    .expect("ed root");

    let rsa2048_root = generate_root_ca(&RootCaParams {
        common_name: "Bench CA RSA 2048",
        org_salt: b"bench-ca-rsa2048",
        calibration_text: "Bench CA Calibration RSA 2048",
        validity_days: 3650,
        cps_uris: empty_strings,
        policy_oids: empty_strings,
        key_algorithm: Some(KeyAlgorithm::Rsa2048),
    })
    .expect("rsa2048 root");

    let rsa4096_root = generate_root_ca(&RootCaParams {
        common_name: "Bench CA RSA 4096",
        org_salt: b"bench-ca-rsa4096",
        calibration_text: "Bench CA Calibration RSA 4096",
        validity_days: 3650,
        cps_uris: empty_strings,
        policy_oids: empty_strings,
        key_algorithm: Some(KeyAlgorithm::Rsa4096),
    })
    .expect("rsa4096 root");

    let mut group = c.benchmark_group("x509_server_signing");

    group.bench_function("ed25519", |b| {
        let ca_cert = ed_root.certificate_pem.clone();
        let ca_key = ed_root.private_key_pem.clone();
        b.iter(|| {
            let params = ServerCertParams {
                hostname: "bench-ed25519.local",
                org_salt: b"bench-server-ed25519",
                calibration_text: "Bench Server Calibration Ed25519",
                ca_cert_pem: ca_cert.as_str(),
                ca_key_pem: ca_key.as_str(),
                validity_days: 825,
                extra_dns: empty_strings,
                extra_ips: empty_ips,
                key_algorithm: Some(KeyAlgorithm::Ed25519),
            };
            black_box(sign_server_cert(&params).expect("sign ed25519"));
        });
    });

    group.bench_function("rsa2048", |b| {
        let ca_cert = rsa2048_root.certificate_pem.clone();
        let ca_key = rsa2048_root.private_key_pem.clone();
        b.iter(|| {
            let params = ServerCertParams {
                hostname: "bench-rsa2048.local",
                org_salt: b"bench-server-rsa2048",
                calibration_text: "Bench Server Calibration RSA 2048",
                ca_cert_pem: ca_cert.as_str(),
                ca_key_pem: ca_key.as_str(),
                validity_days: 825,
                extra_dns: empty_strings,
                extra_ips: empty_ips,
                key_algorithm: Some(KeyAlgorithm::Rsa2048),
            };
            black_box(sign_server_cert(&params).expect("sign rsa2048"));
        });
    });

    group.bench_function("rsa4096", |b| {
        let ca_cert = rsa4096_root.certificate_pem.clone();
        let ca_key = rsa4096_root.private_key_pem.clone();
        b.iter(|| {
            let params = ServerCertParams {
                hostname: "bench-rsa4096.local",
                org_salt: b"bench-server-rsa4096",
                calibration_text: "Bench Server Calibration RSA 4096",
                ca_cert_pem: ca_cert.as_str(),
                ca_key_pem: ca_key.as_str(),
                validity_days: 825,
                extra_dns: empty_strings,
                extra_ips: empty_ips,
                key_algorithm: Some(KeyAlgorithm::Rsa4096),
            };
            black_box(sign_server_cert(&params).expect("sign rsa4096"));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_root_generation, bench_server_signing);
criterion_main!(benches);
