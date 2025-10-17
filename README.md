# Aunsorm Cryptography Suite

**Modern, bağımsız ve production-ready kriptografi ve sertifika yönetim platformu.**

Aunsorm, end-to-end encryption (E2EE), post-quantum cryptography (PQC), JWT token management, X.509 certificate authority ve **otomatik Let's Encrypt entegrasyonu** sağlayan kapsamlı bir güvenlik çözümüdür.

## 🚀 Özellikler

### ✅ Aktif Özellikler (v0.4.2)

#### 🔐 X.509 Certificate Authority (CA)
- **Self-Hosted CA:** Kendi sertifika otoritenizi kurun
- **Ed25519 & RSA Sertifikalar:** Modern, hızlı ve güvenli algoritmalar
- **Root CA ve Intermediate CA:** Tam certificate chain management
- **Server Certificate Signing:** Domain sertifikaları oluşturma
- **RFC 5280 Compliant:** Tam Distinguished Name fields (CN, O, OU, C, ST, L)
- **Aunsorm Calibration Extension:** Benzersiz sertifika metadata
- **CLI Tools:** Komut satırından tam kontrol

```bash
# Root CA oluştur
aunsorm-cli x509 ca init --profile ca-profile.yaml \
  --cert-out root-ca.crt --key-out root-ca.key \
  --algorithm rsa4096

# Server sertifikası imzala (production)
aunsorm-cli x509 ca sign-server \
  --ca-cert root-ca.crt --ca-key root-ca.key \
  --hostname example.com --cert-out server.crt --key-out server.key \
  --algorithm rsa2048 \
  --organization "Company Name" \
  --organizational-unit "IT Security" \
  --country US --state California --locality "San Francisco"
```

##### 🏠 Self-Signed Certificate for Local Development

**Localhost HTTPS için self-signed sertifika oluşturma:**

```bash
# 1. Root CA profile oluştur (ca-profile.yaml)
profile_id: localhost-dev-ca
org_salt: 7Vrq0SWuzHfG1pCEvZFUEg==
root:
  common_name: Localhost Development Root CA
  organization: MyCompany Development
  organizational_unit: Security Services
  country: US
  state: California
  locality: San Francisco
  calibration_text: localhost-dev-root-ca-2025
  validity_days: 3650  # 10 yıl

# 2. Root CA oluştur
aunsorm-cli x509 ca init --profile ca-profile.yaml \
  --cert-out localhost-ca.crt --key-out localhost-ca.key \
  --algorithm rsa2048

# 3. Server sertifikası oluştur (NGINX/Apache için RSA2048 önerilidir)
aunsorm-cli x509 ca sign-server \
  --ca-cert localhost-ca.crt --ca-key localhost-ca.key \
  --hostname localhost \
  --org-salt ed5aead125aecc77c6d69084bd915412 \
  --calibration-text "localhost-server-2025" \
  --cert-out localhost.crt --key-out localhost.key \
  --algorithm rsa2048 \
  --organization "MyCompany Development" \
  --organizational-unit "Security Services" \
  --country US --state California --locality "San Francisco"
```

**Browser'da "Güvenli" gösterimi için Root CA import:**

⚠️ **ÖNEMLİ:** Self-signed sertifikalar browser'larda `NET::ERR_CERT_AUTHORITY_INVALID` uyarısı verir. Bu **NORMAL** bir durumdur ve araçtan (makecert, openssl, Aunsorm Crypt) bağımsızdır. Root CA'yı güvenilir listeye eklemek gerekir.

**Windows (tüm browser'lar için):**
```powershell
# PowerShell (Admin)
Import-Certificate -FilePath localhost-ca.crt -CertStoreLocation Cert:\CurrentUser\Root
```

**Manuel (GUI):**
1. `localhost-ca.crt` dosyasına çift tıkla
2. **Install Certificate** > **Current User**
3. **Place all certificates in the following store** seç
4. **Browse** > **Trusted Root Certification Authorities**
5. **Next** > **Finish** > Güvenlik uyarısını kabul et
6. Browser'ı yeniden başlat

**Chrome/Edge (sadece browser için):**
1. `chrome://settings/certificates` aç
2. **Authorities** tab
3. **Import** button
4. `localhost-ca.crt` seç
5. ✓ **Trust this certificate for identifying websites**
6. **OK** > Browser'ı yeniden başlat

**Firefox:**
1. `about:preferences#privacy` aç
2. **Certificates** > **View Certificates**
3. **Authorities** tab > **Import**
4. `localhost-ca.crt` seç
5. ✓ **Trust this CA to identify websites**

**Import sonrası:** `https://localhost` artık 🔒 **Güvenli** gösterecektir!

**NGINX config örneği:**
```nginx
server {
    listen 443 ssl http2;
    server_name localhost;
    
    ssl_certificate /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    # ... diğer config
}
```

#### 🛡️ Post-Quantum Cryptography (PQC)
- **Kyber-1024 KEM:** Quantum-resistant key encapsulation
- **Dilithium-5:** Post-quantum digital signatures
- **Hybrid Encryption:** Classical + PQC combined security
- **Future-Proof:** Quantum bilgisayarlara karşı korumalı

#### 🔒 End-to-End Encryption (E2EE)
- **Double Ratchet Protocol:** Signal-style forward secrecy
- **Session Management:** Güvenli oturum kurma ve yönetimi
- **Key Rotation:** Otomatik anahtar yenileme
- **Replay Protection:** Paket tekrar saldırılarına karşı koruma

#### 🎫 JWT Token Management
- **Ed25519 Signing:** Modern algoritma ile JWT imzalama
- **Token Generation:** Özelleştirilebilir claim'ler
- **Token Verification:** Signature ve expiry validation
- **JTI Store:** Token replay koruması

#### 🗝️ Key Management Service (KMS)
- **Secure Key Storage:** Güvenli anahtar depolama
- **Key Derivation:** HKDF ve Argon2 based KDF
- **Profile System:** Farklı güvenlik seviyeleri (mobile, low, medium, high, ultra)
- **Hardware Integration:** HSM ve cloud KMS desteği (planned)

#### 📦 Paket Encryption
- **AEAD Encryption:** AES-GCM ve ChaCha20-Poly1305
- **Calibration System:** Organization-specific entropy
- **Strict Mode:** Enhanced security validations
- **Binary Format:** Compact ve verimli serileştirme

### 🎯 Yakında Gelecek Özellikler

#### v0.4.3 (Q4 2025) - RSA Support
- ✅ RSA 2048/4096 key generation
- ✅ Windows ve legacy sistem uyumluluğu
- ✅ Multi-algorithm certificate support

#### v0.5.0 (Q1 2026) - **Let's Encrypt ACME Client**
- 🚀 **Otomatik Sertifika Yönetimi:** Hiçbir manuel işlem gerektirmeden
- 🌍 **Let's Encrypt Entegrasyonu:** Ücretsiz, güvenilir SSL/TLS sertifikaları
- ♻️ **Auto-Renewal:** 30 gün kala otomatik yenileme
- 🎯 **Domain Validation:** HTTP-01, DNS-01, TLS-ALPN-01
- 🔄 **Zero-Downtime:** Kesintisiz sertifika rotation
- 📊 **Monitoring:** Prometheus metrics ve alerting

```bash
# ACME ile Let's Encrypt sertifikası al (v0.5.0)
aunsorm-cli acme certify --domain example.com \
  --validation http-01 --webroot /var/www/html

# Otomatik renewal (cron ile)
aunsorm-cli acme renew --check-all --days-before 30
```

**TAMAMEN BAĞIMSIZ:** Certbot, acme.sh veya başka hiçbir araca ihtiyaç yok!

## 🔥 Neden Aunsorm?

### 🎯 Tam Bağımsızlık
- ❌ **Certbot yok** - Kendi ACME client'ımız
- ❌ **OpenSSL dependency yok** - Pure Rust implementation
- ❌ **External CA yok** - Self-hosted CA solution
- ✅ **Tek Binary** - Tüm özellikler tek executable'da

### 🚀 Production-Ready
- ✅ Comprehensive test coverage
- ✅ Fuzz testing with libFuzzer
- ✅ Security audits
- ✅ Performance benchmarks
- ✅ CI/CD integration

### 🛡️ Security-First
- ✅ Post-quantum cryptography
- ✅ Forward secrecy (Double Ratchet)
- ✅ Replay protection
- ✅ Strict mode validations
- ✅ Audit logging

### ⚡ Performance
- ✅ Ed25519 (10x faster than RSA)
- ✅ Zero-copy serialization
- ✅ Async/await runtime
- ✅ SIMD optimizations

## 📦 Installation

```bash
# From source
cargo install --path packages/aunsorm-crypt/crates/cli

# Binary release (coming soon)
curl -sSL https://install.aunsorm.dev | sh
```

## 🚀 5 Dakikada Başla

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
- [x] Revize: `aunsorm-x509` Certificate Authority (CA) kök/ara sertifika imzalama otomasyonunu planla (bkz. kilitli Sprint 2 maddesi). Plan ayrıntıları için bkz. [CA İmzalama Otomasyon Planı](docs/src/operations/ca-automation.md).
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

## Yan Ürün & MDM Altyapısı
- [x] MDM temel altyapısı: kayıt, politika deposu ve sertifika dağıtım planı.

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

##  Use Cases

### 1. Self-Hosted Certificate Authority
Internal servisler için kendi CA'nızı kurun:
```bash
# Root CA oluştur
aunsorm-cli x509 ca init --profile internal-ca.yaml \
  --cert-out /etc/pki/root-ca.crt --key-out /etc/pki/root-ca.key \
  --algorithm rsa4096

# Microservice sertifikaları
aunsorm-cli x509 ca sign-server --ca-cert /etc/pki/root-ca.crt \
  --hostname api.internal --cert-out api.crt --key-out api.key \
  --algorithm rsa2048
```

### 2. Let's Encrypt Automation (v0.5.0)
Production domain'ler için otomatik SSL:
```bash
# İlk kurulum
aunsorm-cli acme register --email admin@example.com

# Sertifika al
aunsorm-cli acme certify --domain www.example.com \
  --validation http-01 --webroot /var/www/html

# Cron ile otomatik renewal
0 0 * * * /usr/local/bin/aunsorm-cli acme renew --check-all
```

##  Roadmap

Detaylı roadmap için: [ROADMAP.md](ROADMAP.md)

**Yakın gelecek:**
-  **v0.4.2** (Now): CA sign-server command
-  **v0.4.3** (Q4 2025): RSA key generation
-  **v0.5.0** (Q1 2026): Let's Encrypt ACME client
-  **v0.5.1** (Q1 2026): Certificate monitoring & alerting
-  **v0.6.0** (Q2 2026): HSM integration, CT monitoring

## HTTP/3 + QUIC Programı Durumu
- [x] Araştırma & Seçim — `quinn`/`h3` ile `quiche` kıyaslaması ve datagram mesaj planı yayımlandı ([docs/src/architecture/http3-quic.md](docs/src/architecture/http3-quic.md)).
- [x] PoC Sprinti — `apps/server` içinde `http3-experimental` dinleyici ve QUIC datagram telemetri PoC'u.
- [ ] Sertifikasyon ve Güvenlik Analizi — HSM uyumu ve QUIC datagram AEAD stratejileri raporlanacak.
- [ ] Ürünleştirme ve CI Entegrasyonu — HTTP/3 opsiyonel CI job'ı ve operasyon rehberi güncellenecek.

##  Contributing

Katkılarınızı bekliyoruz! Lütfen [CONTRIBUTING.md](CONTRIBUTING.md) dosyasını okuyun.

##  License

MIT License - see [LICENSE](LICENSE) file.

##  Security

Security vulnerabilities: security@myeoffice.com

---

**Aunsorm** - Modern, Independent, Production-Ready Cryptography Platform
