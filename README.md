# Aunsorm Monorepo Hazırlığı

Bu depo, PLAN.md'de tanımlanan Aunsorm v1.01+ güvenlik aracının tam kapsamlı uygulaması için hazırlanmaktadır. Tüm çalışmalar çok ajanlı bir plana göre yürütülecektir.

## 5 Dakikada Başla

```bash
cargo build --release
cargo run -p aunsorm-cli -- encrypt --password P --in msg.bin --out pkt.b64 \
  --org-salt V2VBcmVLdXQuZXU= --calib-text "Neudzulab | Prod | 2025-08"
cargo run -p aunsorm-cli -- decrypt --password P --in pkt.b64 --out out.bin \
  --org-salt V2VBcmVLdXQuZXU= --calib-text "Neudzulab | Prod | 2025-08"
```

## Sprint 0: Planlama ve Altyapı
- [x] PLAN.md gereksinimlerini analiz et ve ajan rollerini belirle.
- [x] Kılavuzları `AGENTS.md` ile belgeleyip iş akışını kur.
- [x] Monorepo dosya yapısını (workspace, crates, CI) oluştur.
- [x] `aunsorm-core` kriptografik temel modüllerini uygula.
- [x] `aunsorm-packet` paket formatı ve doğrulamalarını geliştir.
- [x] PQC köprüsü ve strict kip mantığını tamamla.
- [x] CLI / Server / WASM katmanlarını çıkar.
  - [x] CLI: encrypt/decrypt/peek komutlarını sağla.
  - [x] CLI: oturum komutlarını ekle.
  - [x] CLI: jwt/x509 akışlarını ekle.
    - [x] JWT anahtar üretimi, imzalama ve doğrulama komutları.
    - [x] X.509 komutları.
  - [x] Server katmanını uygula.
- [x] WASM bağlayıcısını hazırla.
- [x] Kimlik bileşenlerini (JWT, X.509, KMS) entegre et.
- [x] Test/Fuzz/Bench altyapısını çalışır hale getir.
- [x] Dokümantasyon, güvenlik rehberi ve lisansları yayımla.

Her sprint tamamlandıkça ilgili maddeler işaretlenecektir. Ajanslar yeni dosya/dizin açtıklarında kapsamlarına özel `AGENTS.md` oluşturmakla yükümlüdür.

## Sprint 1: Kripto ve Paket Temelleri
- [ ] Argon2id profil otomasyonu ve `KdfProfile` API'sini tamamla.
- [ ] AEAD anahtar türetme, nonce yönetimi ve `strict` kip zorunluluklarını uygula.
- [ ] Oturum/ratchet akışlarını ve deterministik hata yüzeylerini üret.
- [ ] Paket başlık/gövde serileştirme ile sınır kontrollerini bitir.
- [ ] Replay koruması ve JTI/PacketId mağazasını entegre et.
- [ ] PQC köprüsünü (ML-KEM/Falcon/SPHINCS+) tamamla ve `strict` davranışlarını doğrula.

## Sprint 2: Kimlik ve Platform Katmanları
- [ ] `aunsorm-kms` için GCP, Azure ve PKCS#11 imzacılarını uygulamaya al.
- [ ] `aunsorm-jwt` üzerinde Ed25519 JWT/JWKS akışlarını ve JTI mağazasını gerçekleştir.
- [ ] `aunsorm-x509` için calib/policy OID, CPS kontrolleri ve opsiyonel PQ işaretlerini ekle.
- [ ] CLI oturum/jwt/x509 komutlarını üretim seviyesinde tamamla.
- [ ] Sunucu bileşeni için OAuth benzeri uçları, sağlık ve metrikleri çıkar.

## Sprint 3: İnterop, Gözlemlenebilirlik ve Dağıtım
- [ ] WASM bağlayıcısını `wasm-bindgen` ile yayımla ve EXTERNAL kalibrasyonunu doğrula.
- [ ] Python uyumluluk testleri için referans karşılaştırmalarını çalıştır.
- [ ] Benchmark, fuzz ve property test akışlarını CI'ya entegre et.
- [ ] OpenTelemetry temelli gözlemlenebilirlik ve yapılandırılabilir logging ekle.
- [ ] GitHub Actions matris CI'sini (fmt/clippy/test/fuzz/bench/audit/deny) etkinleştir.

## Test, Fuzz ve Benchmark Çalıştırma

Aşağıdaki komutlar test/fuzz/bench altyapısını kullanıma hazır hale getirir:

- `cargo test --all-features` — modül testleri ve `tests/` altındaki property testlerini çalıştırır.
- `cargo bench --benches` — Criterion tabanlı AEAD ve oturum ölçümlerini yürütür.
- `cargo fuzz run fuzz_packet` ve `cargo fuzz run fuzz_session` — paket/oturum katmanlarını libFuzzer ile zorlar (Nightly + `cargo-fuzz` gerektirir).

## Nasıl Katkı Sağlanır?
Tüm katkılar PR süreci üzerinden yapılmalı; PR açıklamalarında yapılan değişiklikler, ilgili ajan ve kontrol edilen gereksinimler belirtilmelidir. Ayrıntılı kurallar için [`CONTRIBUTING.md`](CONTRIBUTING.md) dosyasına başvurabilirsiniz. Standart çalışma komutları:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features
cargo test --all-features
```

Gereksinimler ilerledikçe bu belge güncellenecektir.


## Belgeler

Projeyi keşfetmeye başlamadan önce aşağıdaki belgeleri okuyun:

- [CHANGELOG.md](CHANGELOG.md) — Sürüm geçmişi ve önemli değişiklikler.
- [CONTRIBUTING.md](CONTRIBUTING.md) — Katkı ve kod inceleme süreci.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Topluluk davranış standartları.
- [SECURITY.md](SECURITY.md) — Güvenlik açığı bildirim prosedürü.

## Örnekler

Mevcut örnekler aşağıdaki komutlarla çalıştırılabilir:

```bash
cargo run --example encrypt_decrypt
cargo run --example session_roundtrip
cargo run --example jwt_flow
```
