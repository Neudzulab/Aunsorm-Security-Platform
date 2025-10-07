# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Python uyumluluk test koşum takımı ve CI otomasyon genişletmeleri.

## [0.1.0] - 2025-02-15

### Added
- Argon2id tabanlı KDF, otomatik profil seçimi ve HKDF türetimleriyle çekirdek kriptografi katmanı (`aunsorm-core`).
- EXTERNAL kalibrasyon bağlamı, deterministik kalibrasyon kimlikleri ve oturum ratchet yapısı (`aunsorm-core`).
- JSON üstbilgi + PMAC gövde koruması ve Strict kip doğrulamaları ile paket katmanı (`aunsorm-packet`).
- ML-KEM, ML-DSA, Falcon ve SPHINCS+ uyarlayıcılarıyla post-kuantum köprü ve Strict fallback politikaları (`aunsorm-pqc`).
- Şifreleme, oturum, JWT/JWKS, X.509 ve KMS iş akışlarını kapsayan komut satırı arayüzü (`aunsorm-cli`).
- PKCE S256 destekli OAuth benzeri sunucu, JWKS yayınlama ve Strict kipte JTI zorunluluğu (`aunsorm-server`).
- Şifreleme/çözme ve başlık inceleme için WASM bağlayıcıları (`aunsorm-wasm`).
- Kıyaslama senaryoları, örnekler ve SQLite destekli JWT JTI deposu.

### Security
- Tüm crate'lerde `#![forbid(unsafe_code)]`, `#![deny(warnings)]` ve sıkı Clippy profilleri zorunlu hale getirildi.
- `zeroize` ve sabit zamanlı karşılaştırmalarla gizli materyal temizliği sağlandı.

