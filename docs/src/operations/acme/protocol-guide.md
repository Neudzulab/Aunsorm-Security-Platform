# ACME Protokol Rehberi

Bu rehber, Aunsorm ACME bileşenlerinin RFC 8555 uyumlu davranışını, servis
uç noktalarını ve istemci etkileşim akışlarını özetler. Amaç, Let’s Encrypt
benzeri sertifika yaşam döngüsünü kendi altyapımızda deterministik, ölçülebilir
ve denetlenebilir şekilde işletmektir.

## Mimari Bileşenler

- **`crates/acme`** — Directory keşfi, nonce yönetimi, JWS imzalama ve order
  modellerini sağlayan temel crate.
- **`crates/server`** — `/acme/*` uç noktalarını barındıran HTTP hizmeti.
- **`aunsorm-cli`** — Hesap açma, order oluşturma ve sertifika indirme komutları.
- **`tests/src/acme/mock_server.rs`** — Let’s Encrypt akışını taklit eden mock
  sunucu ve happy/sad path testleri.
- **`docs/src/operations/acme/*`** — Operasyon runbook’ları ve sorun giderme
  kılavuzları.

## Uç Nokta Özeti

| Endpoint                         | Açıklama                                                |
|---------------------------------|---------------------------------------------------------|
| `GET /acme/directory`           | Directory belgesi + `Replay-Nonce` başlığı              |
| `GET /acme/new-nonce`           | Yeni nonce üretimi                                      |
| `POST /acme/new-account`        | Hesap kaydı, `Location` başlığı ile account URL’i        |
| `POST /acme/new-order`          | Domain listesi ile order oluşturma                      |
| `POST /acme/order/{id}`         | POST-as-GET order durumu                                |
| `POST /acme/order/{id}/finalize`| CSR ile finalize                                         |
| `GET /acme/cert/{id}`           | Sertifika zinciri indirme                               |
| `POST /acme/revoke-cert`        | Sertifika iptali (kid doğrulamalı)                      |
| `POST /acme/validation/*`       | HTTP-01 ve DNS-01 yayınlama/güncelleme uçları           |

Her yanıt `Replay-Nonce` başlığı içerir; istemci `NonceManager` yardımıyla
havuzu günceller ve tekrar saldırılarına karşı koruma sağlar.

## İstemci Akışı

1. Directory sorgula ve uç noktaları cache’le.
2. `newNonce` çağrısı ile ilk nonce değerini al.
3. Hesap kaydı (`newAccount`) — JWS `kid` olmadan imzalanır.
4. Order oluştur (`newOrder`) — Domain listesi `identifiers[]` altında belirtilir.
5. Challenge doğrulamalarını gerçekleştir (HTTP-01/DNS-01).
6. CSR ile finalize (`/finalize`).
7. Sertifika zincirini indir (`/cert/{id}`).
8. Opsiyonel: Sertifika iptali veya yenileme planlaması.

## Güvenlik ve Doğrulama

- **Rastgelelik:** Tüm anahtar üretimleri `AunsormNativeRng` üzerinden yapılır.
- **Nonce Havuzu:** `NoncePool` capacity overflow durumlarında en eski değeri
düşürerek tekrar kullanımını engeller.
- **JWS İmzalama:** Ed25519, ES256 ve RS256 desteklenir; protected header
  `nonce`, `url` ve `kid` (hesap sonrası) içerir.
- **Rate Limit:** Mock sunucudaki sad path testi, yetkisiz domain isteğine
  `urn:ietf:params:acme:error:rejectedIdentifier` döndürür.

## Staging ve Mock Altyapısı

- `.github/workflows/ci/acme.yml` — ACME staging smoke job’ı; gerekli secrets
  (`ACME_STAGING_DIRECTORY`, `ACME_STAGING_ACCOUNT_KEY`, `ACME_STAGING_CONTACT`)
  tanımlı değilse pipeline hızlıca hata verir ve staging hesabı `acme_staging`
  testiyle Let’s Encrypt’e karşı doğrular.
- `cargo test -p aunsorm-tests mock_server` — Mock senaryoları çalıştırır; CI
  job’ı aynı komutu kullanır.
- `cargo test -p aunsorm-tests --test acme_staging -- --ignored --nocapture` —
  Staging directory → newAccount → POST-as-GET hesabı akışını doğrular; secrets
  eksikse test erken "Skipping" mesajıyla çıkar.
- `tests/src/acme/mock_server.rs` — Directory → Nonce → Account → Order
  sırasını doğrulayan happy path; yetkisiz domain için sad path testi.
- `docs/src/operations/acme/production-deploy.md` — Production dağıtım ve Let’s
  Encrypt rate limit runbook’u.

## Operasyonel İpuçları

- Production ve staging dizin URL’lerini `config/acme/` altında saklayın ve
  CLI komutlarına parametre olarak verin.
- `Replay-Nonce` başlığı alınamadığında istemci otomatik olarak yeni nonce
  talep etmeli; mock testleri bu davranışı doğrular.
- `authorizations[]` URL’leri domain başına benzersizdir; DNS/HTTP otomasyonu
  sırasında bu referansları runbook’larda saklayın.
- Yenileme iş akışları için `docs/src/operations/acme/domain-validation.md`
  ve `docs/src/operations/acme/troubleshooting.md` belgelerine başvurun.
