# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- RSA 2048/4096 anahtar üretimi `ring` entegrasyonu ile birlikte etkinleştirildi.
- `aunsorm-cli x509` komutları için `--algorithm` seçeneği (ed25519, rsa2048, rsa4096)
  tam destekle sunuldu.
- `aunsorm-x509` için RSA zincir doğrulama testleri ve Ed25519/RSA kıyaslaması yapan
  Criterion benchmark'ları eklendi.
- `aunsorm-acme` crate'i ACME directory uç noktalarını ayrıştırmak ve doğrulamak için
  tip güvenli veri modelleri sağlıyor.
- `aunsorm-acme` içinde `NonceManager`, `newNonce` uç noktasına yapılan çağrıları
  test edilebilir istemci soyutlamasıyla yönetip Replay-Nonce havuzunu otomatik
  doldurur.
- `aunsorm-acme` için Ed25519 tabanlı ACME JWS imzalama yardımcıları ve
  deterministik test vektörleri eklendi.
- `aunsorm-id` crate'i için opsiyonel `serde` seri/deserialize desteği ve JSON
  yuvarlama testleri eklendi.

### Changed
- CA otomasyon dokümantasyonu ve kimlik bileşeni açıklamaları RSA desteğini
  yansıtacak şekilde güncellendi.

### Planned for v0.5.0 (Q1 2026)
- ACME v2 protocol client implementation (Let's Encrypt integration)
- Automatic certificate issuance and renewal
- Domain validation (HTTP-01, DNS-01, TLS-ALPN-01)
- Zero-downtime certificate rotation
- Prometheus metrics and monitoring

## [0.4.2] - 2025-10-15

### Added
- **X.509 CA Server Certificate Signing**: `aunsorm-cli x509 ca sign-server` command
  - Sign server certificates with CA key
  - Subject Alternative Names (DNS and IP)
  - Configurable validity period
  - Ed25519 signature algorithm
  - Aunsorm calibration metadata extension
- **RSA Algorithm Infrastructure** (foundation for v0.4.3)
  - `KeyAlgorithm` enum (Ed25519, Rsa2048, Rsa4096)
  - Algorithm selection in `RootCaParams` and `ServerCertParams`
  - CLI `--algorithm` parameter (requires `ring` crate for full support)
- **Test Certificates**: Generated test CA and server certificates
  - Root CA with 10-year validity
  - Server certificate for localhost with SAN extensions
  - Documentation in `test-certs/README.md`

### Changed
- **Roadmap Documentation**: Comprehensive planning for ACME client (v0.5.0)
  - Let's Encrypt integration strategy
  - Domain validation methods
  - Automatic renewal workflow
  - DNS provider integration planning
- **README**: Complete feature overview and use cases
  - Self-hosted CA examples
  - Let's Encrypt automation preview
  - Architecture diagrams
  - Roadmap visibility

### Fixed
- Certificate generation with proper SAN extensions
- Ed25519 key generation in CA workflows

### Documentation
- Added `ROADMAP.md` with detailed v0.4.3-v0.6.0 planning
- Updated `README.md` with modern feature showcase
- Created `test-certs/README.md` for certificate management guide

## [0.4.1] - 2025-10-20
### Changed
- Synchronized all workspace crate manifests and npm metadata to publish the 0.4.1 maintenance release.

### Documentation
- Updated the mdBook introduction to reference the 0.4.1 architecture baseline.

## [0.4.0] - 2025-10-13
### Added
- `aunsorm-cli calib fingerprint` komutu EXTERNAL kalibrasyon bağlamı
  için Base64/hex parmak izi raporu üretir ve otomasyon entegrasyonlarına
  uygun JSON çıktısı sağlar.
- `aunsorm-cli calib verify` komutu, beklenen kalibrasyon kimliği ve
  parmak izi değerlerini doğrulayıp uyumsuzluk durumunda hata kodu
  döndürür.
- CI pipeline now builds the mdBook documentation and publishes it as an artifact
- Hacker regression test now verifies that tampering with the coordinate digest is caught
  alongside rustdoc output, ensuring architectural docs remain up to date.
- Configurable tracing initialisation with optional OpenTelemetry OTLP export
  controlled via `AUNSORM_LOG` and `AUNSORM_OTEL_ENDPOINT` environment bindings
  when the `aunsorm-server` crate is built with the `otel` feature.
- CLI `aunsorm-cli pq checklist` alt komutu PQC imza algoritmaları için NIST
  kategorisi, anahtar boyları ve çalışma zamanı kontrollerini hem metin hem JSON
  formatında raporlar.
- `aunsorm-pytests` crate providing Python 1.01 compatibility vectors and
  negative/positive decrypt fixtures for AES-GCM and ML-KEM-768 scenarios.
- `session_store_roundtrip` fuzz hedefi ile oturum ratchet ve `SessionStore`
  etkileşimi için genişletilmiş libFuzzer kapsamı.
- `aunsorm-tests` crate'i altında `session_ratchet_roundtrip_soak` ve
  `kms_local_roundtrip_soak` uzun süreli doğrulama senaryoları.
- `kms_remote_live_soak` testi; GCP ve Azure anahtarlarını ortam değişkeni
  tabanlı yapılandırma ile canlı olarak doğrular ve iterasyon/filtresi
  `AUNSORM_KMS_REMOTE_SOAK` ile kontrol edilebilir.
- Azure ve GCP sağlayıcıları için yeni KMS conformance fixture testleri;
  tekrarlı/boş `key_id` ve kaynak değerleri artık deterministik `KmsError::Config`
  mesajları üretir.
- Deterministik `tests/data/kms/` fixture korpusu ve mdBook sertifikasyon
  özeti ile GCP, Azure ve PKCS#11 sağlayıcıları için entegrasyon testleri
  aynı veri setini kullanır.
- `docs/` altında mdBook tabanlı mimari rehber ve operasyonel test dökümantasyonu.
- Nightly zamanlanmış iş akışı fuzz korpuslarını ısıtıp `cargo fuzz cmin` ile minimize
  ederek indirilebilir artefakt üretir.
- `aunsorm-packet` içinde X25519/HKDF-SHA256 tabanlı HPKE modu (`hpke` özelliği)
  ve exporter secret türetimi için yeni yardımcı API'ler.
- Paket ve oturum akışları için deterministik `TranscriptHash` üretimi;
  CLI çıktılarında ve denetim loglarında hex olarak raporlanır.
- `aunsorm-server` başlangıç JWKS yayımını `KeyTransparencyLog` içine
  kaydedip `/transparency/tree` uç noktası üzerinden Merkle benzeri ağaç
  başlığını JSON olarak sunar.
- CLI `calib derive-coord` komutuna `--coord-raw-out` seçeneği eklenerek
  türetilen koordinatın 32 baytlık ham değeri güvenli biçimde dosyaya
  yazılabilir hale geldi; rapor çıktılarındaki Base64 değer ile birebir
  doğrulanabilir.
### Changed
- Uzak KMS soak testi `kid` değerini public anahtarın SHA-256 özetine göre
  doğrular ve isteğe bağlı JSON raporunda anahtar özeti/public anahtar
  alanlarını yayınlar.
### Fixed
- `aunsorm-core` calibration metni artık NFC normalizasyonu ve boşluk daraltması
  uygulayarak aynı anlamlı içeriğe sahip girdiler için farklı kimliklerin
  üretilmesini engeller.
- Calibration binding text rejects Unicode private-use and noncharacter code
  points to avoid hidden or environment-specific glyphs leaking into the
  deterministic identifier.
### Planned

## [0.1.0] - 2025-10-07
### Added
- Initial workspace layout with security-focused defaults and lint gates.
- `aunsorm-core` crate implementing Argon2id KDF profiles, EXTERNAL calibration
  binding, deterministic coordinate derivation, and ratchet primitives.
- `aunsorm-packet` crate providing authenticated packet construction, validation,
  and replay protection hooks.
- PQC bridge crate with strict-mode fail-fast semantics and ML-KEM/ML-DSA
  feature toggles.
- CLI, server, and WASM frontends for encryption, ratcheting sessions, JWT/X.509
  flows, and browser bindings.
- Identity crates for JWT, X.509, and KMS interoperability with zeroization of
  sensitive material.
- Comprehensive examples, benchmarks, and initial CI scaffolding for fmt/clippy/test.

### Security
- Enforced `#![forbid(unsafe_code)]` and `#![deny(warnings)]` across all crates.
- Documented strict-mode environment bindings and downgrade protection story.
- Added deterministic calibration identifiers and coordinate digests to prevent
  tampering and mis-binding attacks.
