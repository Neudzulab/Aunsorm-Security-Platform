# Mimari Genel Bakış

Aunsorm bileşenleri dört ana katmana ayrılır:

1. **Kriptografik Çekirdek (`aunsorm-core` ve `aunsorm-pqc`):**
   - KDF profilleri, kalibrasyon bağlamı ve ratchet mekanizmaları.
   - PQC köprüsü sayesinde ML-KEM ve ML-DSA kombinasyonları strict kipte doğrulanır.
2. **Paketleme (`aunsorm-packet`):**
   - El sıkışma, oturum paketleri ve JTI/Replay engelleyiciler.
   - `SessionStore` üzerinden yeniden kullanım tespitleri.
3. **Kimlik (`aunsorm-kms`, `aunsorm-jwt`, `aunsorm-x509`):**
   - Çok sağlayıcılı KMS istemcisi, Ed25519 JWT/X.509 üretimi ve doğrulaması.
   - Strict kipte fallback stratejileri ve kid hesaplamaları.
4. **Platform (`aunsorm-cli`, `aunsorm-server`, `aunsorm-wasm`):**
   - CLI iş akışları, HTTP uçları ve tarayıcı bağlayıcıları.

Bu katmanlar `PLAN.md` ve sprint checklist'leriyle hizalıdır.

## Veri Akışı

```text
Parola -> Argon2id -> KDF Profili -> Anahtar Matrisi
                             |             |
                             v             v
                        Packet Builder   Session Ratchet
                             |             |
                             +------> KMS/Identity
```

- Kalibrasyon kimliği ve koordinat digest'i her paket başlığına yazılır.
- Oturum paketleri `SessionRatchet` üzerinde deterministik olarak ilerler.
- Kimlik katmanı, paket başlıklarının `kid` ve `hdrmac` alanlarını doğrular.

## Sertleştirme Notları

- `#[forbid(unsafe_code)]` ve `#[deny(warnings)]` tüm crate'lerde etkin.
- Yeni KMS conformance testleri, sağlayıcı yapılandırma hatalarını erken yakalar.
- Fuzz hedefi `session_store_roundtrip` ile oturum mağazası ve ratchet akışı
  aynı orkestrasyon altında zorlanır.
