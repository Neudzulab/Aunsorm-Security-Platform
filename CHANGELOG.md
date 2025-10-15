# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `aunsorm-cli x509 ca init` ve `aunsorm-cli x509 ca issue` komutları CA
  otomasyon profillerini kullanarak deterministik kök/ara sertifika üretimi,
  JSON özet raporları ve CA paketlerini güncelleme desteği sağlıyor.
- `aunsorm-x509` içerisine `CaAutomationProfile`, `CaBundle`, ara CA
  imzalama yardımcıları ve anahtar kimliği/seri numarası hesaplayıcıları
  eklendi.
- `aunsorm-id` crate providing head-anchored unique identifier generation with
  namespace normalization and verifiable parsing helpers.
- `aunsorm-mdm` crate delivering device enrollment, policy storage and
  certificate distribution planning APIs alongside `/mdm/*` server
  uçları ve Prometheus metriği.

### Documentation
- Documented the Certificate Authority automation plan for `aunsorm-x509`,
  covering CLI/kitaplık genişletmeleri, KMS entegrasyonu ve test stratejisi
  (`docs/src/operations/ca-automation.md`).

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
