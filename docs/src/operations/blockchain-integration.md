# Hyperledger Fabric DID Doğrulama Planı

*Revizyon: 2025-10-22*

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

## Quorum Audit Trail ve Tokenizasyon Gereksinimleri

Hyperledger Fabric doğrulama PoC'u, müşteri işlemlerinin Quorum tabanlı bir
audit trail'e tokenizasyon yoluyla yansıtılacağı birleşik bir izleme
mimarisinin temelini oluşturur. Bu bölüm, Quorum ağının kapsamını, veri
modelini ve operasyonel beklentilerini netleştirir.

### Ağ Topolojisi ve Konsensüs
- **Quorum Sürümü:** GoQuorum 23.x, Istanbul BFT konsensüsü ile dört doğrulayıcı
  (OrgSecurity, OrgCompliance, OrgOps, OrgObserver) ve iki erişim düğümü.
- **Kanalizasyon:** Audit trail işlemleri, `aunsorm-audit` adında izinli bir
  ağ üzerinde yürütülecek; Fabric ağına köprüleyen `bridge-relay` servisi
  yalnızca `TOKENIZE_AUDIT` yetkisine sahip API anahtarlarıyla çağrılabilir.
- **Zaman Senkronizasyonu:** Tüm Quorum düğümleri, Fabric tarafıyla aynı NTP
  havuzuna bağlı olacak; maksimum izin verilen sapma 250 ms. Sapma aşıldığında
  `audit_sync_skew_ms` metriği `Critical` seviyesine yükseltilip olay yönetimi
  süreci başlatılır.

### Tokenizasyon Modeli
- **Varlık Tanımı:** Her sertifika veya anahtar olayı `AuditAsset` adlı bir
  ERC-721 uyumlu, devredilebilir olmayan (soulbound) token ile temsil edilir.
  Token ID, `sha256(fabric_channel || block_hash || transaction_id)` olarak
  hesaplanır.
- **Metaveri Alanları:**
  - `calibration_ref`: Aunsorm calibration kimliği veya `External` bağlamı.
  - `event_type`: `certificate_issued`, `certificate_revoked`,
    `kms_key_rotated`, `kms_key_destroyed` gibi sabit enum değerleri.
  - `org_scope`: Olayın bağlı olduğu tenant veya müşteri kimliği.
  - `retention_policy`: İlgili saklama politikasının sürüm numarası.
  - `fabric_anchor`: DID doğrulama PoC'undan gelen blok/işlem referansı.
- **Yetki Devri:** Token'lar devredilemediğinden, audit izleri yalnızca
  `OrgCompliance` tarafından `viewAuditTrail` izniyle sorgulanabilir. Okuma
  yetkisi zaman kutulu `permit` mesajları (EIP-712) ile delegasyona açılır.

### İşlem Yaşam Döngüsü
1. Fabric üzerindeki `POST /blockchain/fabric/did/verify` isteği başarıyla
   sonuçlandığında, `AuditRelay` servisi Fabric blok referansını ve olay türünü
   yakalar.
2. `AuditRelay`, Quorum ağındaki `AuditAssetRegistry` sözleşmesine `mint`
   çağrısı yapar. Çağrı öncesinde:
   - `org_salt` ve `calibration_text` kullanılarak koordinatlar tekrar
     doğrulanır.
   - `retention_policy` bilgisi `PolicyStore` API'sinden alınır.
   - Olay, `tokenization_queue` Kafka konusuna idempotent olarak yazılır.
3. `mint` işlemi onaylandığında Quorum olay log'u, Fabric transaction ID ile
   birlikte `audit_events` veri ambarına aktarılır.
4. Başarısız tokenizasyonlar `AuditRelay` tarafından maksimum üç kez
   yeniden denenir; başarısızlıklar `OpsOnCall` ekibine PagerDuty alarmı olarak
   geçer.

### Veri Modeli ve Entegrasyon
- **Off-Chain Depolama:** Token metaverileri, Quorum'da saklanan IPFS benzeri
  içerik adresli pointer'lara değil, `aunsorm-audit` Postgres şemasına JSONB
  olarak yazılır. Böylece kişisel veriler zincir dışında kalır.
- **Raporlama Katmanı:**
  - Günlük raporlar, `audit_asset_daily_rollup` görünümü üzerinden
    oluşturulur.
  - SOC 2 için aylık doğrulanmış token sayısı ve `calibration_ref` eşleşme
    oranı raporlanır.
  - eIDAS gereği, revokasyon olayları için 24 saat içinde Quorum kaydı
    doğrulanmalı ve otomatik bildirim e-postası gönderilmelidir.
- **API Genişletmesi:** `GET /blockchain/quorum/audit-assets/{token_id}`
  endpoint'i, token metaverisini Fabric referanslarıyla birlikte dönecek.

### Güvenlik ve Uyum Kontrolleri
- **Yetkilendirme:** `TOKENIZE_AUDIT` anahtarlarının saklanması HSM destekli
  `aunsorm-kms` politikalarıyla yapılır; anahtar rotasyonu 60 günde bir
  zorunludur.
- **Gizlilik:** `org_scope` alanı müşteri pseudonym'i içerir. Gerçek müşteri
  kimliği yalnızca `OrgCompliance` tarafından offline KMS ile çözülebilir.
- **Denetim:** Tüm Quorum işlemleri, `aunsorm-observability` pipeline'ına
  OpenTelemetry trace olarak aktarılır. Trace'ler Fabric çağrı kimliği ile
  ilişkilendirilir.
- **Uyum:** FATF Travel Rule gereği tokenize edilen olaylar arasında müşteri
  varlık transferi yoktur; bu sayede müşteri KYC/AML verisi zincire yazılmaz.
  Travel Rule kapsamında gerekli raporlar `audit_asset_daily_rollup`'tan
  türetilen XML şablonları ile üretilir.

### Yol Haritası ve Mil Taşları
- **2024-11-15:** AuditRelay prototipinin Fabric PoC ortamına bağlanması.
- **2024-12-10:** Quorum üzerinde `AuditAssetRegistry` akıllı sözleşmesi için
  güvenlik incelemesi ve formal doğrulama raporunun tamamlanması.
- **2025-01-20:** SOC 2 kanıt paketine günlük raporların entegre edilmesi ve
  otomatik dağıtım pipeline'ının açılması.
- **2025-02-05:** Quorum audit verileri ile müşteri bazlı saklama politikası
  eşlemesinin tamamlanması; `retention_policy` alanının CI testleriyle
  doğrulanması.
- **2025-03-01:** Canlı ortamda haftalık tokenizasyon tatbikatı ve felaket
  kurtarma (DR) planının Quorum zinciriyle test edilmesi.

## Test ve Regresyon
- `fabric_did_verification_succeeds` testi, imza doğrulamasının ve ledger
  doğrulamasının mutlu yolu kapsar.
- `fabric_did_verification_rejects_tampered_anchor` testi, blok hash'i
  manipüle edilmiş kanıtların reddedildiğini doğrular.
- Blockchain PoC test harness'i (`tests/blockchain/`) hash zinciri
  tutarlılığını sınayarak ledger tarafındaki regresyonlara erken uyarı sağlar.

## İleri İşler
- Zincirler arası test harness'i (`tests/blockchain/cross_network.rs`) için
  veri seti gereksinimleri belirlenip PoC doğrulama endpoint'i ile entegre
  edilecektir.
- Quorum `AuditAssetRegistry` sözleşmesi için formel doğrulama sonuçları ve
  bytecode hash'leri `certifications/quorum/` dizininde yayımlanacaktır.
- Quorum ve Fabric arasında `bridge-relay` servisinin yüksek erişilebilirlik
  topolojisi (`active-active` Geo cluster) değerlendirilip operasyonel runbook'a
  eklenecektir.
