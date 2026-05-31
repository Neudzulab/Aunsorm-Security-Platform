<!--
  Scope: Repository-wide change history for the Aunsorm Cryptography Suite.
  Last updated: Logged VibeCO v0.7.0 documentation alignment and architecture tree sync.
-->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `aunsorm-server` now exposes first-party application session endpoints
  (`POST /sessions`, `POST /sessions/{sessionId}/keys`) plus
  `/security/hmac-sign` and `/security/hmac-verify` for session-cookie signing
  integrations such as MyeOffice.
- `aunsorm-server` OAuth flow enforces per-role session/refresh TTL'leri,
  MFA zorunlulukları ve kalıcı refresh token deposu; yanıtlar `role`,
  `mfaRequired`, `mfaVerified` ve `refreshExpiresIn` alanları içerir.
  `POST /oauth/revoke` uç noktası hem refresh hem access token'ları iptal
  ederek audit kayıtlarına `oauth.revoke` olayları ekler.
- Revocation webhooks now include structured client context (client ID, subject,
  role, scope and MFA verification state) alongside token metadata, enabling
  downstream replay protection stores to attach richer audit trails.
- Access token revocation notifications now emit the same client context as
  refresh token events, keeping downstream auditing consistent regardless of
  token type.
- `aunsorm-server` now exposes `/v1/...` compatibility aliases for active
  HTTP endpoints (including `/v1/health` and `/v1/pqc/capabilities`) while
  keeping unversioned routes operational during the transition period.
- `aunsorm-server` Strict kipte kalibrasyon doğrulama hatalarını audit telemetri
  olayları (`AuditEvent::Failure`) olarak kaydeder; entegrasyon testleri HTTP
  422 yanıtını ve telemetri tetikleyicisini doğrular.
- `aunsorm-server` clock attestation now runs the background `ClockRefreshService`
  when `AUNSORM_CLOCK_REFRESH_URL` is configured, enforcing production refresh
  intervals (`AUNSORM_CLOCK_REFRESH_INTERVAL_SECS`) and exposing freshness
  telemetry via the `/health` endpoint (`clock.status`, `ageMs`, `refreshEnabled`).
- Disaster recovery runbook documenting RTO/RPO hedefleri, DR aktivasyonu ve failback adımlarını kapsayan operasyon rehberi.
- `aunsorm-cli jwt verify` komutu `--format text` seçeneğiyle normalize
  edilmiş claim çıktısını insan okunur biçimde raporlar; varsayılan JSON
  formatı korunur ve `claims_out` hedefi loglarda kullanılan format bilgisiyle
  birlikte bildirilir.
- `aunsorm-server` HTTP hizmetine `tower-http` TraceLayer ve istek/yanıt
  sıkıştırma katmanları eklenerek her isteğin başlangıcı/yanıtı milisaniye
  gecikmesiyle stdout log'larına aktarılır; `br/gzip/deflate/zstd`
  algoritmaları otomatik müzakere edilir ve gelen gövdeler aynı
  `Content-Encoding` değerleriyle açılır.
- `aunsorm-server` CORS katmanı `AUNSORM_CORS_*` değişkenleriyle yapılandırılabilir
  hale getirildi; origin, method ve header allowlist'leri ile isteğe bağlı
  credential/max-age ayarları desteklenir.
- Fabric DID registry için chaincode lifecycle scripti ve gateway event relay uygulaması eklendi.
- `POST /blockchain/media/record` uç noktası, Fabric gateway yapılandırıldığında
  denetim izlerini zincire gönderip `ledgerReceipt` ile onay bilgisi döndürür.
- GitHub Actions `ACME Staging Smoke` job'u Let’s Encrypt staging API’sine
  karşı `tests/tests/acme_staging.rs` hesabı roundtrip testini çalıştırır;
  secrets eksikse erken hata verilir ve sonuçlar `docs/src/operations/acme/production-deploy.md`

## [0.5.0] - 2026-02-19

### Added
- Post-quantum cryptography expansion with ML-KEM key encapsulation and SLH-DSA / ML-DSA signing pipelines across PQC service endpoints.
- Calibration workflow finalized with strict clock attestation enforcement and refresh worker guidance for production deployments.
- AunsormNativeRng hardened seeding and reuse model shared across crates and service examples.
- Clock attestation observability exposing freshness and authority fingerprint status on health endpoints.
- ACME service partial implementation covering account onboarding, nonce management, and order scaffolding for future challenge handlers.
  rehberinde belgelenir.
- `endpoint-validator` kütüphanesi ve `aunsorm-cli validate-endpoints`
  komutu: OpenAPI/sitemap/HTML keşfi, otomatik gövde üretimi, geri çekilme
  politikaları ve Markdown/JSON raporlarıyla uzak API uçlarını doğrular.
- `endpoint-validator` doğrulama raporları özet metrikler üretir; JSON ve
  Markdown çıktılarında toplam, başarılı, allowlist ve atlanan uç sayıları
  ayrı ayrı raporlanır ve CLI özet mesajları bu sayımları kullanır.
- `aunsorm-server` `GET /pqc/capabilities` endpoint'i PQC algoritma envanterini
  ve `AUNSORM_STRICT` ortam değişkeni davranışını JSON formatında raporlar.
- `aunsorm-id` HEAD parmak izini ham byte dizisi olarak döndüren
  `HeadIdGenerator::head_fingerprint_bytes` ve `HeadStampedId::fingerprint_bytes`
  yardımcılarını sağlayarak ikili doğrulama ve anahtar materyali karşılaştırma
  senaryolarını kolaylaştırıyor.
- `aunsorm-acme` HTTP-01 domain doğrulamaları için key-authorization üretimi,
  beklenen `/.well-known/acme-challenge/<token>` dosya yolu ve yanıt gövdesi
  doğrulaması sağlayan yardımcılar ekledi; basit dosya sunucu dağıtımlarında
  sondaki newline karakterleri tolere ediliyor.
- Docker Compose `compose.yaml` reçetesi: kalıcı `AUNSORM_JTI_DB` volume'ü,
  healthcheck ve varsayılan `RUST_LOG`/strict yapılandırmasıyla konteyner
  dağıtımlarını tek komutla başlatır.
- `aunsorm-server` güvenlik servisine `POST /security/jwt-verify` endpoint'i eklendi;
  Zasian medya token'larını imza/claim kontrolleriyle doğrulayıp payload veya hata
  mesajı döndürüyor ve kayıtlı olmayan `jti` değerlerini reddediyor.
- `aunsorm-server` kalibrasyon uçları: `POST /calib/inspect` CLI `calib inspect`
  raporuna denk JSON döndürür, `POST /calib/verify` ise yapılandırılmış parmak
  iziyle eşleşmeyi doğrulayıp Strict kipte uyuşmazlıklarda HTTP 422 üretir.
- `/security/jwt-verify` yanıtı `issuedAt` ve `notBefore` claim alanlarını saniye
  cinsinden raporlayarak istemcilerin oturum penceresi değerlendirmesini
  kolaylaştırıyor.
- `aunsorm-pqc` KEM ve imza algoritması enum'ları `FromStr` implementasyonları ile
  kullanıcı girdilerini normalize ederek alias desteği sağlıyor ve derleme
  konfigürasyonu gerekliliklerini hata mesajlarıyla bildiriyor.
- `aunsorm-acme` doğrulama modülü HTTP-01/DNS-01 durum makineleri, DNS sağlayıcı
  arayüzü ve Cloudflare/Route53 adaptör iskeletleriyle genişletildi; `aunsorm-server`
  tarafında challenge yayınlama/geri çağırma uçları ve eşlik eden entegrasyon testi eklendi.
- Retention policy audit fixtures and regression tests ensuring PolicyStore
  sürümleri, `AuditAssetRegistry` kayıtları ve `kms_key_destroyed` olaylarıyla
  kronolojik olarak zincirleniyor.
- `aunsorm-server` ACME servisi: `GET /acme/directory`, `GET /acme/new-nonce`, `POST /acme/new-account`, `POST /acme/new-order` uçları JWS doğrulaması ve nonce/account/order yönetimiyle yayınlandı.
- ACME finalize akışı: `POST /acme/order/{order_id}/finalize` CSR SubjectAltName kapsamını doğrulayıp sertifika URL'si yayınlar.
- ACME sertifika zinciri yayını: `GET /acme/cert/{order_id}` finalize edilmiş order için PEM formatında leaf + issuer zinciri döner.
- ACME POST-as-GET kaynakları: `POST /acme/account/{id}` ve `POST /acme/order/{order_id}` mevcut hesap/order durumunu kid doğrulamasıyla döndürür.
- ACME sertifika iptali: `POST /acme/revoke-cert` endpoint'i kid doğrulaması ve reason kodlarıyla sertifikayı iptal eder, tekrar indirmeleri engeller.
- ACME onboarding entegrasyon testi (`acme_happy_path_flow`) directory → new-nonce → new-account → new-order senaryosunu doğruluyor.
- `aunsorm-cli acme` komutları: directory keşfi (`acme directory`), hesap kaydı (`acme register`) ve order oluşturma (`acme order`) akışları state dosyası yönetimi ve JSON çıktısı desteğiyle eklendi.
- `aunsorm-cli acme finalize` komutu: CSR dosyasından finalize isteği gönderip order durumunu state dosyasında günceller.
- `aunsorm-cli acme fetch-cert` komutu: finalize edilmiş order için PEM zincirini indirip belirtilen dosyaya yazar.
- `aunsorm-cli acme revoke` komutu: yayınlanan sertifika zincirini RFC 5280 reason kodlarıyla iptal eder ve state dosyası
  üzerinden hesap takibini sürdürür.
- `scripts/deploy_gateway_cert.sh` betiği: ACME kayıt/order/finalize akışını zincirleyip sertifikayı gateway dağıtımı için otomatikleştirir.
- VibeCO v0.7.0 uyumu için README, PLAN ve PROJECT_SUMMARY dosyalarına açıklayıcı başlık blokları eklendi.
- ACME hesap anahtarları için RFC 7638 uyumlu JWK thumbprint yardımcıları (Ed25519, ES256, RS256).
- ACME `newOrder` identifier doğrulaması artık IDNA normalizasyonu ile uluslararası alan adlarını destekliyor.
- ACME `newAccount` isteği builder'ı e-posta/telefon URI doğrulaması ve
  `externalAccountBinding` yapısı için zorunlu alan kontrolleri ekledi.
- ACME `newAccount` builder'ı, URI metinlerinden iletişim eklemek için
  `try_contact_uri` ve `try_contacts_uri` yardımcılarını sunarak doğrudan
  `AccountContact` üretme ihtiyacını ortadan kaldırıyor.
- ACME authorization veri modelleri: Authorization/Challenge JSON belgeleri
  HTTP-01/DNS-01/TLS-ALPN-01 türlerini doğrulayıp token formatını denetler.
- ACME DNS-01 doğrulama yardımcıları: `_acme-challenge` TXT kayıt adı ve
  SHA-256 key-authorization digest değerini deterministik olarak üretir,
  wildcard domainleri normalleştirir.
- Üretim ağ sertleştirmesi: ingress-nginx TLS sonlandırması, Istio mTLS devre kesici
  politikaları ve Cloudflare/AWS Shield DDoS kuralları `docs/src/operations/networking-load-balancing.md`
  altında belgelendi; Kubernetes/terraform manifestleri `config/kubernetes/networking/`,
  `config/cloudflare/` ve `config/aws/` dizinlerine eklendi.
- ACME TLS-ALPN-01 doğrulama yardımcıları: key-authorization SHA-256 özetini
  hesaplayıp `acmeIdentifier` uzantısı ve Ed25519 anahtarlarıyla kendinden
  imzalı sertifika üreten yardımcılar sağlar; PEM çıktıları ALPN `acme-tls/1`
  protokolüyle birlikte döndürülür.
- ACME hesap anahtarları için Ed25519, ES256 ve RS256 üretim yardımcıları; RNG
  enjeksiyonunu destekleyerek CLI ve sunucu entegrasyonları için hazır anahtar
  üretimi sağlar.
- `HeadIdGenerator::from_env_with_namespace` yardımıyla HEAD-stamped ID jeneratörleri çalışma anında namespace geçersiz kılmayı
  destekler hale geldi.
- Hyperledger Fabric DID doğrulama PoC'u için `POST /blockchain/fabric/did/verify` endpoint'i ve `FabricDidRegistry` PoC kayıt deposu.
- Server entegrasyon testleri: `fabric_did_verification_succeeds` ve `fabric_did_verification_rejects_tampered_anchor`.
- JWT doğrulama regresyon testi `jwt_verify_endpoint_rejects_missing_token` boş token girişlerini yakalayarak `/security/jwt-verify`
  uç noktasının hata mesajını güvence altına alıyor.
- Ek regresyon testi `jwt_verify_endpoint_rejects_tokens_missing_jti`, JTI claim'i olmayan token'ların reddedildiğini doğrulayarak
  replay korumasının zorunlu kılınmasını güvence altına alıyor.
- Experimental `GET /http3/capabilities` endpoint exposing Alt-Svc metadata and QUIC datagram channel descriptors behind the `http3-experimental` feature flag.
- Router test coverage ensuring the HTTP/3 capability payload advertises active status and datagram limits.
- Optional `http3-poc` GitHub Actions job gated by `ENABLE_HTTP3_POC=true`, executing `aunsorm-server` and integration tests with `http3-experimental` enabled.
- HTTP/3 canary integration test (`http3_poc_ci`) that asserts the QUIC listener binds to the expected port and produces telemetry datagrams.
- Blockchain PoC mock ledger (`tests/blockchain/mock_ledger.rs`) and integrity regression tests (`blockchain_poc`) validating hash chain enforcement.
- Optional `blockchain-poc.yml` workflow guarded by `BLOCKCHAIN_POC_ENABLED`/manual dispatch for running the PoC harness end-to-end.
- Cross-network harness plan with deterministic datasets (`tests/blockchain/cross_network.rs`) and accompanying fixtures for Fabric→Quorum and Quorum→Sepolia köprü akışları.
- Identity flow integration test harness combining JWT, KMS and X.509 via deterministic fixtures (`tests/tests/identity_flows.rs`).
- Linux/macOS ortamları için `cargo fmt`/`cargo clippy`/`cargo test` adımlarını tek komutla çalıştıran `scripts/test-all.sh` betiği.

### Changed
- `aunsorm-acme` crate version bumped to 0.5.0 so all published crates share
  the 0.5.x release line and documentation references remain consistent.
- `endpoint-validator` rate limiter artık `0` değeri verildiğinde sınırsız
  istek kabul ederek CLI yapılandırmalarındaki "0 = kapalı" semantiğiyle
  tutarlılık sağlıyor ve gereksiz yavaşlamayı önlüyor.
- `aunsorm-server` otomatik servis modu tespiti: `SERVICE_MODE` tanımlanmadığında
  ikili adı veya `AUNSORM_LISTEN` portu üzerinden uygun servis modu seçilerek
  Docker varsayılanlarıyla manuel override gereksinimi ortadan kalktı.
- `/metrics` endpoint now pulls live counts from the server state instead of
  returning placeholder metric values.
- `aunsorm-jwt` doğrulaması varsayılan olarak `jti` alanını zorunlu kılar ve
  yapılandırılmış JTI store olmadan `jti store not configured` hatası döndürür;
  `aunsorm-server` doğrulayıcısı yapılandırılan defter arka ucuna bağlı
  `JtiStore` ile tekrar saldırılarını engeller.
- `aunsorm-jwt` imzalayıcıları eksik `jti` claim'lerini otomatik olarak
  üretmek için mutable claim referansları kabul eder; CLI ve sunucu akışları
  yeni API ile uyumlu olacak şekilde güncellendi.
- `/security/generate-media-token` now issues Ed25519-signed JWTs via
  `aunsorm-jwt`, records issued JTIs in the ledger, and `/security/jwt-verify`
  performs full signature/claim validation with descriptive error mapping.
- `/oauth/begin-auth` now validates registered redirect URIs and scopes, returning RFC-compliant `invalid_redirect_uri` and
  `invalid_scope` errors when clients use unauthorized values.
- Randomness API's entropy mapper now performs branchless constant-time rejection sampling to harden the `/random/number`
  endpoint against timing analysis.
- `/random/number` yanıtları artık `Cache-Control: no-store, no-cache, must-revalidate`,
  `Pragma: no-cache` ve `Expires: 0` başlıklarını göndererek kriptografik sonuçların
  ara cache katmanlarında saklanmasını engelliyor.
- `aunsorm-cli` ACME hesap anahtarı üretimi işletim sistemi RNG'si yerine
  `AunsormNativeRng` kullanarak platformun zorunlu entropy hattı ile uyumlu
  hale getirildi.
- `aunsorm-server` artık `AUNSORM_CLOCK_MAX_AGE_SECS` değerini doğrular; strict
  kipte 30 saniyeyi aşan veya 0 olarak ayarlanan pencereler yapılandırma
  hatasıyla reddedilir ve non-strict dağıtımlar varsayılan olarak 300 saniye
  toleransa geri döner.
- `/id/generate` endpoint'i, namespace doğrulama hatalarında artık `invalid_request` döndürerek misconfiguration ile istemci
  hatalarını ayırt ediyor ve HEAD bilgisi için `from_env_with_namespace` yardımcısını kullanıyor.
- ACME HTTP uçları artık doğrudan `AcmeService` mantığına delegasyon yaparak nonce tüketimi, JWS doğrulaması ve RFC 8555 problem
  yanıtlarını sunuyor; eski sabit JSON yanıtları kaldırıldı.
- ACME directory ve `new-nonce` uçları `aunsorm-acme` trait tabanlı servis
  soyutlamalarını kullanacak şekilde `routes/acme` modülüne taşındı; nonce
  üretimi ve JWS yetkilendirmesi çekirdek yardımcılarla paylaşılarak RFC 8555
  akışı dokümante edildi.

### Fixed
- `/security/jwt-verify` artık JWT `aud` alanındaki tüm değerleri virgül ile
  ayrılmış olarak raporlayarak birden fazla audience içeren token'larda eksik
  bilgi sunulmasını engelliyor ve CLI çıktılarıyla hizalanıyor.
- `aunsorm-jwt` signer now rejects blank `jti` values before generating a token,
  matching verifier-side validation and preventing replay bypass attempts with
  whitespace identifiers.
- Pinned `ed25519-dalek` dependencies to the 2.1 release line so builds continue
  to target the repository MSRV of Rust 1.76 without requiring newer toolchains.
- `aunsorm-jwt` exposes `JwtSigner::kid()` again so server endpoints and tests
  can report signer metadata after temporal claim validation tightened.
- `/security/jwt-verify` artık JSON gövdesinde `Bearer` önekiyle gelen token
  değerlerini temizleyerek Authorization başlığına özgü formatı yeniden
  kullanan istemcilerin doğrulama sürecinde hata almamasını sağlıyor.
- `/security/jwt-verify` token temizlemesi artık ASCII kontrol karakterleri içeren
  değerleri reddederek satır sonu enjeksiyonlarını ve gövde taşmalarını engelliyor.
- `derive_seed64_and_pdk` now rejects empty passwords, preventing accidental derivation of seeds from blank credentials.
- `/random/number` artık tam `u64` aralığını destekleyerek yüksek üst limitlerde hata vermeden deterministik reddetme örneklemesini uyguluyor.
- ACME account telephone normalization now accepts DTMF digits (`*`, `#`) so service codes and keypad suffixes parse correctly.
- ACME directory parser artık `newNonce`/`newAccount`/`newOrder`/`revokeCert`/`keyChange` uç noktaları için HTTPS dışı URL'leri reddederek yanlış yapılandırmalardan kaynaklanan güvensiz istekleri engelliyor.
- ACME directory parser bilinmeyen/ek uç noktaları da HTTPS zorunluluğuna tabi tutarak directory belgelerindeki HTTP şemalı linkleri reddediyor.
- `GET /http3/capabilities` yeniden yönlendiriciye bağlanarak Alt-Svc başlığı ve datagram metrikleri `http3-experimental` bayrağı aktif sunumlarda doğru şekilde ilan ediliyor.
- `aunsorm-cli` varsayılan sunucu URL'si artık `HOST` ortam değişkeninden gelen port/path/query bilgilerinin tümünü koruyarak `http://host:port:8080` gibi hatalı URL'lerin oluşmasını engelliyor.

### Security
- Clock refresh worker enforces HTTPS endpoints, caps attestation payloads, and validates refreshed snapshots with the configured `SecureClockVerifier` before publishing them to subscribers.

### Documentation
- README ACME roadmap anlatımı, yayınlanan onboarding uçlarını ve v0.5.0 için kalan authorization/finalize/revoke planını yansıtacak şekilde güncellendi.
- README mimari ağacı VibeCO formatıyla yeniden yazıldı; endpoint durum etiketleri ve servis ağaç disiplini notları güncellendi.
- PROD_PLAN.md ve PROJECT_SUMMARY.md VibeCO yol haritası ve ilerleme tablolarıyla yeniden hizalandı; güncel ilerleme kaydı eklendi.
- README ve `docs/src/operations/acme-gateway-automation.md` ACME sertifika iptali (`acme revoke`) ve operasyonel geri dönüş
  prosedürlerini içerecek şekilde genişletildi.
- Hyperledger Fabric DID doğrulama planı (`docs/src/operations/blockchain-integration.md`) ve uyumluluk kontrol listesi güncellemeleri.
- README HTTP/3 service tree and discovery section updated with `GET /http3/capabilities` usage examples.
- `crates/server/AGENTS.md` now requires README + CHANGELOG updates whenever a new HTTP endpoint is introduced.
- HTTP/3 operations runbook extended with activation/rollback steps, observability checks, and incident feedback SLA’ları.
- Yeni ACME gateway otomasyon rehberi (`docs/src/operations/acme-gateway-automation.md`) cron senaryoları, hata yakalama ipuçları ve dağıtım komutlarıyla yayımlandı.
- New blockchain innovation guide (`docs/src/innovation/blockchain.md`) and compliance checklist cross-referencing CI artefaktları ve regülasyon maddeleri.
- Agent charter and sprint intake guide aligned with the revizyon kilidi policy (`docs/src/operations/agent-charters.md`).
- OAuth PKCE uçları için OpenAPI 3.1 şeması ve redirect URI kayıt rehberi (`docs/src/operations/oauth-openapi.md`).
- Blockchain retention runbook documented CI fixtures linking policy versions to on-chain anchors (`docs/src/innovation/blockchain.md`, `docs/src/operations/blockchain-integration.md`).
- README ACME roadmap anlatımı, yayınlanan onboarding uçlarını ve v0.5.0 için kalan authorization/finalize/revoke planını yansıtacak şekilde güncellendi.
- README mimari ağacı VibeCO formatıyla yeniden yazıldı; endpoint durum etiketleri ve servis ağaç disiplini notları güncellendi.
- PROD_PLAN.md ve PROJECT_SUMMARY.md VibeCO yol haritası ve ilerleme tablolarıyla yeniden hizalandı; güncel ilerleme kaydı eklendi.
- Hyperledger Fabric DID doğrulama planı (`docs/src/operations/blockchain-integration.md`) ve uyumluluk kontrol listesi güncellemeleri.
- README HTTP/3 service tree and discovery section updated with `GET /http3/capabilities` usage examples.
- `crates/server/AGENTS.md` now requires README + CHANGELOG updates whenever a new HTTP endpoint is introduced.
- HTTP/3 operations runbook extended with activation/rollback steps, observability checks, and incident feedback SLA’ları.
- Yeni ACME gateway otomasyon rehberi (`docs/src/operations/acme-gateway-automation.md`) cron senaryoları, hata yakalama ipuçları ve dağıtım komutlarıyla yayımlandı.
- New blockchain innovation guide (`docs/src/innovation/blockchain.md`) and compliance checklist cross-referencing CI artefaktları ve regülasyon maddeleri.
- Agent charter and sprint intake guide aligned with the revizyon kilidi policy (`docs/src/operations/agent-charters.md`).
- OAuth PKCE uçları için OpenAPI 3.1 şeması ve redirect URI kayıt rehberi (`docs/src/operations/oauth-openapi.md`).

### Removed
- `aunsorm-server` HTTP `/random/number` uç noktası üçüncü taraf istemcilere hizmet verecek şekilde tutulur ve yanıtlara `X-Aunsorm-Rng-Policy: external-only` başlığı eklendi; iç servisler native RNG hattını kullanmaya devam eder.

### Planned
- 📋 **v0.6.0** – `POST /security/jwe/encrypt`: WebRTC medya oturumlarını JWE ile sarmalayacak güvenlik hizmeti için rota ve
  handler iskeleti ayrıldı.
- 📋 **v0.6.1** – `POST /blockchain/media/record`: Medya köprüsü ledger kayıtlarını kabul edecek blockchain servisi uç noktası
  router'a eklendi ve beklemede olan iş mantığı `todo!()` ile belirlendi.

### Planned for v0.5.0 (Q1 2026)
- ACME v2 protocol client implementation (Let's Encrypt integration)
- Automatic certificate issuance and renewal
- Domain validation (HTTP-01, DNS-01, TLS-ALPN-01)
- Zero-downtime certificate rotation
- Prometheus metrics and monitoring

## [0.4.6] - 2025-10-18

### 🚨 BREAKING CHANGES

**OAuth2 endpoints now RFC 6749/7636 compliant - schema updated!**

#### `/oauth/begin-auth` endpoint changes:
- ❌ **Removed:** `username` field (non-standard)
- ✅ **Added:** `redirect_uri` (required, HTTPS enforced)
- ✅ **Added:** `state` (optional, CSRF protection)
- ✅ **Added:** `scope` (optional, permission delegation)
- ✅ **Added:** `subject` (optional hint, replaces username)
- ✅ **Response:** Returns `code` instead of `auth_request_id`
- ✅ **Response:** Echoes `state` parameter for CSRF validation

#### `/oauth/token` endpoint changes:
- ✅ **Added:** `grant_type` field (must be "authorization_code")
- ✅ **Added:** `redirect_uri` field (must match authorization request)
- ✅ **Changed:** `auth_request_id` → `code` (authorization code)
- ✅ **Validation:** Enforces redirect_uri match (prevents authorization code interception)
- ✅ **Scope:** Embedded in JWT claims if provided during authorization

### Added
- **RFC 6749 OAuth 2.0 Authorization Framework compliance**
  - Standard authorization code flow with PKCE (RFC 7636)
  - Redirect URI validation (HTTPS required, localhost HTTP allowed)
  - State parameter support for CSRF protection
  - Scope parameter support for permission delegation
  - Single-use authorization codes (consumed after first exchange)
  - Comprehensive error responses (invalid_grant, invalid_client, invalid_request)

- **Security Enhancements**
  - Redirect URI open redirect prevention (URL validation)
  - State parameter replay protection
  - Authorization code reuse prevention
  - Subject hint validation (control character filtering)

- **Documentation**
  - `docs/oauth-aunsorm-integration-request.md`: Complete RFC compliance guide
  - TypeScript/JavaScript PKCE client implementation example
  - Web app integration patterns and security best practices
  - Migration guide for clients using old schema

### Changed
- **OAuth2 Schema Updates**
  - `BeginAuthRequest`: Removed `username`, added `redirect_uri`, `state`, `scope`, `subject`
  - `BeginAuthResponse`: Changed `auth_request_id` → `code`, added `state` echo
  - `TokenRequest`: Added `grant_type`, `redirect_uri`, changed `auth_request_id` → `code`
  - `AuthRequest` (state): Added `redirect_uri`, `state`, `scope` fields

- **Test Suite Updates**
  - Updated all OAuth2 tests to use new RFC-compliant schema
  - Added redirect URI validation tests
  - Added state parameter tests
  - All 17 server tests passing

### Documentation
- README.md: Updated OAuth2 section with RFC references and examples
- Added PKCE flow example with curl commands
- Documented redirect_uri validation rules
- Added state parameter CSRF protection explanation
- Updated service tree with OAuth2 compliance details

### Security
- **CVE Prevention:** Open redirect vulnerability fixed via redirect_uri validation
- **CSRF Protection:** State parameter support added (RFC 6749 §10.12)
- **Code Interception Prevention:** redirect_uri match validation enforced

### Notes
- **Migration Required:** Existing clients using `username` field will receive 422 errors
- **Web App Compatibility:** Now compatible with standard OAuth2 libraries (oauth4webapi, etc.)
- **Mobile App Support:** Ready for iOS/Android OAuth flows with custom URL schemes
- **Issue Reference:** Fixes #12 (OAuth2 + Aunsorm integration request)

## [0.4.5] - 2025-10-17

### Added
- **HEAD-Stamped ID Generation Service**
  - 3 REST endpoints: `POST /id/generate`, `POST /id/parse`, `POST /id/verify-head`
  - Full integration of `aunsorm-id` crate (v0.4.5) into server
  - Environment variable support: AUNSORM_HEAD, GITHUB_SHA, GIT_COMMIT, CI_COMMIT_SHA, VERGEN_GIT_SHA
  - Custom namespace support with fallback to default ("aunsorm")
  - Git commit SHA-based unique identifier generation
  - Monotonic timestamp (microseconds) + atomic counter for collision prevention
  - HEAD fingerprint verification for artifact tracking
  - JSON response format with full metadata
  - Turkish error messages for validation failures

### Changed
- **Test Suite Optimization**
  - Removed redundant 1M+ sample distribution tests
  - Added smoke test (1K samples, ~0.04s) for random number generation
  - Reduced test execution time from 60+ seconds to <5 seconds
  - All 242 tests passing successfully

### Documentation
- README.md: Updated ID Generation endpoints from 📋 Planned → ✅ Active
- Service tree: Marked 3 ID endpoints as production-ready
- Environment variable configuration documented
- Added usage examples and response format documentation

## [0.4.4] - 2025-10-17

### Added
- **Service Discovery Directive in AGENTS.md**
  - 🚨 Mandatory endpoint documentation policy for all agents
  - Status indicators: ✅ Active, 🚧 Development, 📋 Planned, 🔮 Future
  - Responsibility matrix for Platform, Identity, Crypto, and Interop agents
  - Git commit checkpoint: README vs routes.rs comparison requirement
- **Missing Service Documentation**
  - `aunsorm-id` crate (v0.1.0) documented as 📋 Planned for v0.4.5
  - 3 ID endpoints: `/id/generate`, `/id/parse`, `/id/verify-head`
  - `aunsorm-acme` crate documented as 📋 Planned for v0.5.0
  - 8 ACME endpoints for RFC 8555 compliance
- **HTTP/3 QUIC Datagrams (Experimental)**
  - Merged HTTP/3 PoC from origin/main (982 lines)
  - 3 datagram channels: Telemetry(0), Audit(1), Ratchet(2)
  - Postcard binary encoding (max payload: 1150 bytes)
  - Alt-Svc header for HTTP/3 upgrade advertisement
  - Feature flag: `http3-experimental`
  - 120+ lines of HTTP/3 documentation in README
- **Parametric Random Number Endpoint**
  - `/random/number?min=X&max=Y` query parameters
  - Default range: 0-100 (backward compatible)
  - Validation: min ≤ max, max ≤ u64::MAX/2
  - Mathematical entropy mixing: NEUDZ-PCS + AACM models
  - Chi-square validation: χ² = 101.18 ≈ 100.0 (4M samples)

### Fixed
- Duplicate `/transparency/tree` route causing test failures
- Missing `listen_port()` accessor method in `ServerState`
- Proptest whitespace calibration bug (added `prop_assume!(!note_text.trim().is_empty())`)
- Route conflict from duplicate `.with_state(state)` call

### Changed
- **Version Standardization**
  - All version references updated from v0.4.2 → v0.4.4
  - CLI version: v0.4.1 → v0.4.4
  - Server version: v0.4.1 → v0.4.4
  - Roadmap timeline adjusted for ID service (v0.4.5) and ACME (v0.5.0)
- **Documentation Improvements**
  - README expanded: 1167 → 1214 lines (+47 lines)
  - Comprehensive CLI command tree documentation
  - Server endpoint tree with 17 active + 11 planned endpoints
  - Kalibrasyon system explanation (100+ lines)
  - HTTP/3 QUIC technical documentation (120+ lines)
  - Professional consistency across all sections

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
- HTTP/3 + QUIC programı için kütüphane kıyaslaması ve datagram mesaj planı `docs/src/architecture/http3-quic.md` içinde yayımlandı.
- `http3-experimental` özelliği ile `aunsorm-server` HTTP/3 PoC dinleyicisi, Alt-Svc başlığı
  enjeksiyonu ve postcard tabanlı QUIC datagram telemetri akışı hazırlandı.

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
