# Hyperledger Fabric DID Doğrulama Planı

*Revizyon: 2025-10-19*

## Amaç ve Kapsam
- Hyperledger Fabric ağına çapalanmış Aunsorm DID kayıtlarının kanıtlarının
  REST katmanı üzerinden doğrulanması.
- Ledger tutarlılığının (blok hash'i ve işlem kimliği) PoC düzeyinde
  doğrulanması ve denetim için metriklerin üretilmesi.
- PoC çıktılarının ileride Quorum tabanlı audit trail planı ile
  genişletilmesine zemin hazırlamak.

## REST Endpoint Tasarımı
- **Endpoint:** `POST /blockchain/fabric/did/verify`
- **İstek gövdesi:**
  ```jsonc
  {
    "did": "did:fabric:testnet:aunsorm:device-root",
    "channel": "aunsorm-channel",
    "proof": {
      "challenge": "<base64url>",
      "signature": "<base64url>",
      "block_hash": "<hex-encoded 32 bayt>",
      "transaction_id": "<fabric tx id>",
      "timestamp_ms": 1728000200000
    }
  }
  ```
- **Yanıt gövdesi:**
  ```jsonc
  {
    "did": "did:fabric:testnet:aunsorm:device-root",
    "verified": true,
    "controller": "did:fabric:testnet:aunsorm:controller",
    "status": "active",
    "channel": "aunsorm-channel",
    "mspId": "AUNSORMMSP",
    "ledger_anchor": {
      "blockIndex": 42,
      "blockHash": "...",
      "transactionId": "b9f8a6d97f4c41b89f0dfcc0aunsorm",
      "timestampMs": 1728000200000
    },
    "verification_method": {
      "id": "did:fabric:testnet:aunsorm:device-root#key-1",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:fabric:testnet:aunsorm:controller",
      "publicKeyBase64": "..."
    },
    "service": {
      "id": "#ledger-audit",
      "type": "LedgerAuditChannel",
      "endpoint": "https://api.aunsorm.local/blockchain/did"
    },
    "audit": {
      "challenge": "<base64url>",
      "checkedAtMs": 1728000200500,
      "clockSkewMs": 12
    }
  }
  ```
- Yanıt alanları, operasyonel denetim için blok konumu ve imza doğrulama
  metadatasını içerir.

## Doğrulama Akışı
1. DID ve kanal alanları beyaz listeye alınmış PoC kayıtları ile
   eşleştirilir.
2. Ledger anchor verisi (blok index'i, hash ve transaction_id)
   `FabricDidRegistry` tarafından beklenen değerlerle karşılaştırılır.
3. `canonical_challenge(did, block_hash_hex, timestamp_ms)` fonksiyonu ile
   deterministik meydan okuma metni üretilir. İstek yükündeki challenge ile
   eşleşmesi zorunludur.
4. İmza doğrulaması, `Ed25519VerificationKey2018` yöntemine göre
   `ed25519-dalek` kitaplığıyla gerçekleştirilir.
5. Sistem saati ile istemci zaman damgası arasındaki sapma 30 saniye (`30_000ms`)
   üzerinde ise istek reddedilir.

## Operasyonel Hususlar
- **Anahtar Yönetimi:** PoC verifikasyon anahtarı deterministik seed ile
  üretilmiştir. Üretim ortamında HSM destekli anahtar rotasyonu planlanmalıdır.
- **Saat Eşzamanı:** `clock_skew_ms` alanı gözlemlenerek out-of-sync istemciler
  için uyarı eşiği belirlenmelidir.
- **Hata Mesajları:** Tüm başarısızlıklar RFC 6749 uyumlu `error` ve
  `error_description` alanları ile döndürülür. Ledger uyuşmazlıkları
  operasyon kayıtlarına loglanmalıdır.
- **Gözlemlenebilirlik:** Başarılı doğrulamalar audit alanındaki canonical
  challenge ve ölçülen sapma değerleriyle birlikte izlenebilir.

## Test ve Regresyon
- `fabric_did_verification_succeeds` testi, imza doğrulamasının ve ledger
  doğrulamasının mutlu yolu kapsar.
- `fabric_did_verification_rejects_tampered_anchor` testi, blok hash'i
  manipüle edilmiş kanıtların reddedildiğini doğrular.
- Blockchain PoC test harness'i (`tests/blockchain/`) hash zinciri
  tutarlılığını sınayarak ledger tarafındaki regresyonlara erken uyarı sağlar.

## İleri İşler
- Quorum tabanlı tokenizasyon ve audit trail gereksinimleri bu belgeye
  eklenecek, Fabric PoC çıktılarıyla birlikte birleşik bir entegrasyon planı
  oluşturulacaktır.
- Zincirler arası test harness'i (`tests/blockchain/cross_network.rs`) için
  veri seti gereksinimleri belirlenip PoC doğrulama endpoint'i ile entegre
  edilecektir.
