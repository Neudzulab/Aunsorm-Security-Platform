# Aunsorm Crypt

Bu depo, PLAN.md'de tanımlanan Aunsorm v1.01+ güvenlik aracının tam kapsamlı uygulaması için hazırlanmaktadır. Tüm çalışmalar çok ajanlı bir plana göre yürütülecektir.

## Revizyon Kilidi Prensipleri

- README, PLAN ve TODO gibi planlama belgelerinde `[x]` veya "done" olarak işaretlenen tüm teslimatlar kilitlidir.
- Revizyon gerekiyorsa mevcut maddeyi değiştirmek yerine ilgili bölümde `Revize:` önekiyle yeni bir madde açıp kilitli göreve referans verin.
- Ajanlar yalnızca açık/to-do maddeleri, ana planı ve kapsamlarındaki `AGENTS.md` yönergelerini baz almalı; tamamlanan işlere tekrar dokunmamalıdır.

## 5 Dakikada Başla

```bash
cargo build --release
cargo run -p aunsorm-cli -- encrypt --password P --in msg.bin --out pkt.b64 \
  --org-salt V2VBcmVLdXQuZXU= --calib-text "Neudzulab | Prod | 2025-08"
cargo run -p aunsorm-cli -- decrypt --password P --in pkt.b64 --out out.bin \
  --org-salt V2VBcmVLdXQuZXU= --calib-text "Neudzulab | Prod | 2025-08"
cargo run -p aunsorm-cli -- calib inspect \
  --org-salt V2VBcmVLdXQuZXU= --calib-text "Neudzulab | Prod | 2025-08"
cargo run -p aunsorm-cli -- calib derive-coord \
  --password P --org-salt V2VBcmVLdXQuZXU= \
  --calib-text "Neudzulab | Prod | 2025-08" --kdf medium
cargo run -p aunsorm-cli -- calib fingerprint \
  --org-salt V2VBcmVLdXQuZXU= \
  --calib-text "Neudzulab | Prod | 2025-08" --format text
cargo run -p aunsorm-cli -- pq checklist --algorithm ml-dsa-65 --format text
```

Kalibrasyon değerini bir dosyada saklıyorsanız aynı komutlara
`--calib-file calib.txt` seçeneğini ekleyebilir, dosya sonundaki satır
sonlarının otomatik kırpılmasını sağlayabilirsiniz.

Kalibrasyon raporlarını insan tarafından okunur biçimde görmek için
`calib` komutlarına `--format text` parametresini ekleyebilirsiniz.

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
- [x] Argon2id profil otomasyonu ve `KdfProfile` API'sini tamamla.
- [x] AEAD anahtar türetme, nonce yönetimi ve `strict` kip zorunluluklarını uygula.
- [x] Oturum/ratchet akışlarını ve deterministik hata yüzeylerini üret.
- [x] Paket başlık/gövde serileştirme ile sınır kontrollerini bitir.
- [x] Replay koruması ve JTI/PacketId mağazasını entegre et.
- [x] PQC köprüsünü (ML-KEM/Falcon/SPHINCS+) tamamla ve `strict` davranışlarını doğrula.

## Sprint 2: Kimlik ve Platform Katmanları
- [x] `aunsorm-kms` için GCP, Azure ve PKCS#11 imzacılarını uygulamaya al.
- [x] `aunsorm-jwt` üzerinde Ed25519 JWT/JWKS akışlarını ve JTI mağazasını gerçekleştir.
- [x] `aunsorm-x509` için calib/policy OID, CPS kontrolleri ve opsiyonel PQ işaretlerini ekle.
- [ ] Revize: `aunsorm-x509` Certificate Authority (CA) kök/ara sertifika imzalama otomasyonunu planla (bkz. kilitli Sprint 2 maddesi).
- [x] CLI oturum/jwt/x509 komutlarını üretim seviyesinde tamamla.
- [x] Sunucu bileşeni için OAuth benzeri uçları, sağlık ve metrikleri çıkar.

## Sprint 3: İnterop, Gözlemlenebilirlik ve Dağıtım
- [x] WASM bağlayıcısını `wasm-bindgen` ile yayımla ve EXTERNAL kalibrasyonunu doğrula.
- [x] Python uyumluluk testleri için referans karşılaştırmalarını çalıştır.
- [x] Benchmark, fuzz ve property test akışlarını CI'ya entegre et.
- [x] OpenTelemetry temelli gözlemlenebilirlik ve yapılandırılabilir logging ekle.
- [x] GitHub Actions matris CI'sini (fmt/clippy/test/fuzz/bench/audit/deny) etkinleştir.

## Bonus (Vizyon)
- [x] WebTransport/DataChannel E2EE adaptor örneği.
- [x] Kilitli bellek / SGX / SEV entegrasyon planı.
- [x] Key transparency ve transcript hash (gelecek sürüm).

## Test, Fuzz ve Benchmark Çalıştırma

Aşağıdaki komutlar test/fuzz/bench altyapısını kullanıma hazır hale getirir:

- `cargo test --all-features` — modül testleri ve `tests/` altındaki property testlerini çalıştırır.
- `cargo bench --benches` — Criterion tabanlı AEAD ve oturum ölçümlerini yürütür.
- `cargo fuzz run fuzz_packet` ve `cargo fuzz run fuzz_session` — paket/oturum katmanlarını libFuzzer ile zorlar (Nightly + `cargo-fuzz` gerektirir).
- `cargo fuzz run session_store_roundtrip` — oturum ratchet’ı ve `SessionStore` kayıtlarını çok adımlı senaryolarda doğrular.
- GitHub Actions üzerindeki **Nightly Fuzz Corpus** iş akışı korpusları her gece ısıtır,
  minimize eder ve indirilebilir artefakt olarak yayımlar.

### Soak Testleri

- `cargo test -p aunsorm-tests -- --ignored session_ratchet_roundtrip_soak` — uzun süreli oturum ratchet turu; `AUNSORM_SESSION_SOAK` ile iterasyon sayısını artırabilirsiniz.
- `cargo test -p aunsorm-tests -- --ignored kms_local_roundtrip_soak` — yerel KMS imzalama ve sarma/çözme tekrarlarını doğrular; `AUNSORM_KMS_SOAK` ortam değişkeni desteklenir.
- `cargo test -p aunsorm-tests --features "kms-remote" -- --ignored kms_remote_live_soak` — GCP/Azure uzak KMS anahtarlarını canlı olarak imzalatır; `AUNSORM_KMS_GCP_CONFIG` ve/veya `AUNSORM_KMS_AZURE_CONFIG` JSON yapılandırmaları ile `AUNSORM_KMS_REMOTE_SOAK`/`AUNSORM_KMS_REMOTE_KEYS` değişkenleri döngü ve filtre kontrolü sağlar.

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
- [docs/](docs/) — mdBook tabanlı mimari rehber (`mdbook serve docs`).

Statik HTML çıktısını yerel olarak üretmek için `mdbook build docs` komutunu
kullanabilirsiniz; CI pipeline'ı her çalıştığında aynı kitap otomatik olarak
yayınlanabilir artefakt olarak oluşturulur.

## Örnekler

Mevcut örnekler aşağıdaki komutlarla çalıştırılabilir:

```bash
cargo run --example encrypt_decrypt
cargo run --example session_roundtrip
cargo run --example jwt_flow
cargo run --example webtransport_adapter
```
