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
- [ ] Test/Fuzz/Bench altyapısını çalışır hale getir.
- [x] Dokümantasyon, güvenlik rehberi ve lisansları yayımla.

Her sprint tamamlandıkça ilgili maddeler işaretlenecektir. Ajanslar yeni dosya/dizin açtıklarında kapsamlarına özel `AGENTS.md` oluşturmakla yükümlüdür.

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
