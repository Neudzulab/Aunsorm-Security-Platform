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

#### 🌐 Aunsorm Ekosistemi - Komple Güvenlik Platformu

Aunsorm, CLI araçlarından production-ready HTTP API'ye kadar eksiksiz bir güvenlik ekosistemi sunar.

##### 🔧 Aunsorm CLI - Komut Satırı Araçları

```
aunsorm-cli v0.4.1
│
├─ 🔐 Encryption & Decryption
│  ├─ encrypt                          → EXTERNAL kalibrasyon ile AEAD şifreleme
│  │                                     └─ Password: --password / --password-file
│  │                                     └─ Calibration: --org-salt, --calib-text/--calib-file
│  │                                     └─ AEAD: AES-GCM, ChaCha20-Poly1305
│  │                                     └─ KDF Profiles: mobile/low/medium/high/ultra
│  │                                     └─ AAD: --aad (text) / --aad-file (binary)
│  │                                     └─ KEM Support: ml-kem-768 (post-quantum)
│  │                                     └─ Output: Base64 encoded packet
│  │
│  ├─ decrypt                          → Paketi çöz ve doğrula
│  │                                     └─ Password + calibration verification
│  │                                     └─ AAD integrity check
│  │                                     └─ Metadata export: --metadata-out (JSON)
│  │                                     └─ Session info extraction
│  │
│  └─ peek                             → Paket başlığını incele (şifre gerektirmez)
│                                        └─ AEAD algorithm detection
│                                        └─ KEM info extraction
│                                        └─ Header-only parse (fast)
│
├─ 📊 Calibration Management
│  ├─ calib inspect                    → Kalibrasyon parametrelerini görüntüle
│  │                                     └─ Input: --org-salt, --calib-text
│  │                                     └─ Output:
│  │                                     │   ├─ Calibration Context hash
│  │                                     │   ├─ Organization salt (base64)
│  │                                     │   ├─ Calibration text
│  │                                     │   ├─ Derived salts preview
│  │                                     │   └─ Status: READY / INVALID
│  │                                     │
│  │                                     └─ Format: text (human-readable) / json
│  │                                     └─ Validation: syntax + entropy check
│  │
│  ├─ calib derive-coord               → Koordinat kimliği ve değeri türet
│  │                                     └─ Input:
│  │                                     │   ├─ --password (required)
│  │                                     │   ├─ --org-salt (base64)
│  │                                     │   ├─ --calib-text
│  │                                     │   └─ --kdf (profile: mobile/low/medium/high/ultra)
│  │                                     │
│  │                                     └─ Process:
│  │                                     │   ├─ Calibration context creation
│  │                                     │   ├─ Salt derivation (HKDF)
│  │                                     │   ├─ KDF execution (Argon2)
│  │                                     │   └─ Coordinate extraction (32-byte)
│  │                                     │
│  │                                     └─ Output:
│  │                                     │   ├─ coord_id: hex string
│  │                                     │   ├─ coord_value: hex string
│  │                                     │   ├─ kdf_info: algorithm details
│  │                                     │   └─ calibration_id
│  │                                     │
│  │                                     └─ Format: text / json
│  │                                     └─ Use case: deterministic key derivation
│  │
│  ├─ calib fingerprint                → SHA-256 parmak izi oluştur
│  │                                     └─ Input: --org-salt, --calib-text
│  │                                     └─ Output: SHA-256 hash (hex)
│  │                                     └─ Use case:
│  │                                     │   ├─ X.509 certificate metadata
│  │                                     │   ├─ Audit trail tagging
│  │                                     │   └─ Configuration versioning
│  │                                     │
│  │                                     └─ Format: text (hex) / json
│  │                                     └─ Deterministic: same input = same output
│  │
│  └─ calib verify                     → Kalibrasyon doğrula
│                                        └─ Input: --org-salt, --calib-text, --fingerprint
│                                        └─ Process:
│                                        │   ├─ Recompute fingerprint
│                                        │   ├─ Compare with expected
│                                        │   └─ Validate calibration context
│                                        │
│                                        └─ Output: VALID / INVALID
│                                        └─ Exit code: 0 (valid) / 1 (invalid)
│                                        └─ Use case: configuration integrity check
│
├─ 🔄 Session Management (Double Ratchet)
│  ├─ session-encrypt                  → E2EE oturum mesajı şifrele
│  │                                     └─ Input: plaintext message, session store
│  │                                     └─ SessionRatchet: automatic key derivation
│  │                                     └─ Forward secrecy (each message = new key)
│  │                                     └─ Replay protection (message numbering)
│  │                                     └─ Output: encrypted packet + updated store
│  │                                     └─ Store format: JSON (persistent state)
│  │
│  └─ session-decrypt                  → Oturum mesajını çöz
│                                        └─ Input: encrypted packet, session store
│                                        └─ Ratchet state verification
│                                        └─ Message ordering check
│                                        └─ Automatic ratchet advance
│                                        └─ Output: decrypted plaintext + updated store
│                                        └─ SessionStore management (file-based)
│
├─ 🛡️ Post-Quantum Cryptography
│  ├─ pq status                        → PQC hazırlık durumu raporu
│  │                                     └─ Algorithm support status:
│  │                                     │   ├─ ML-KEM-768 (Kyber-768)
│  │                                     │   ├─ ML-KEM-1024 (Kyber-1024)
│  │                                     │   ├─ ML-DSA-65 (Dilithium-5)
│  │                                     │   ├─ Falcon-512
│  │                                     │   └─ SPHINCS+-SHAKE-128f
│  │                                     │
│  │                                     └─ Implementation status
│  │                                     └─ NIST standardization info
│  │                                     └─ Format: text / json
│  │
│  └─ pq checklist                     → İmza algoritması sertleştirme kontrolü
│                                        └─ Algorithm: --algorithm (ml-dsa-65, falcon-512, sphincs+)
│                                        └─ Security checklist validation:
│                                        │   ├─ Strict mode compatibility
│                                        │   ├─ Key generation requirements
│                                        │   ├─ Signature size limits
│                                        │   └─ Implementation hardening
│                                        │
│                                        └─ Output: compliance report
│                                        └─ Format: text / json
│
├─ 🎫 JWT Operations
│  ├─ jwt keygen                       → Ed25519 JWT anahtar çifti oluştur
│  │                                     └─ Output: private.pem, public.pem
│  │                                     └─ Automatic key ID (kid) generation
│  │
│  ├─ jwt sign                         → JWT token imzala
│  │                                     └─ Local key file veya KMS backend
│  │                                     └─ KMS Support: Local, GCP KMS, Azure Key Vault
│  │                                     └─ Custom claims (JSON)
│  │                                     └─ Expiry duration
│  │                                     └─ JTI injection (replay protection)
│  │                                     └─ Fallback backend support
│  │
│  ├─ jwt verify                       → JWT signature doğrula
│  │                                     └─ Public key validation
│  │                                     └─ JTI replay check (SQLite store)
│  │                                     └─ Expiry ve issuer validation
│  │                                     └─ Output: decoded claims (JSON)
│  │
│  └─ jwt export-jwks                  → JWKS (JSON Web Key Set) export
│                                        └─ Multiple public keys
│                                        └─ RFC 7517 compliant
│                                        └─ OAuth/OIDC discovery compatible
│
└─ 🔒 X.509 Certificate Management
   ├─ x509 self-signed                 → Ed25519 self-signed cert oluştur
   │                                     └─ Minimal setup: CN, validity
   │                                     └─ Quick dev/test certificates
   │                                     └─ Output: PEM format (cert + key)
   │
   ├─ x509 local-dev                   → Localhost HTTPS development cert
   │                                     └─ SAN extensions (DNS + IP)
   │                                     └─ Hostname: localhost / custom
   │                                     └─ Extra DNS/IP SANs
   │                                     └─ Browser-ready (import CA root)
   │                                     └─ Validity: configurable days
   │
   └─ x509 ca [subcommands]            → Production CA automation
      │
      ├─ ca init                       → Root CA oluştur (profil tabanlı)
      │                                  └─ Input: YAML/JSON profile file
      │                                  │   ├─ profile_id
      │                                  │   ├─ org_salt (16 bytes, base64)
      │                                  │   └─ root:
      │                                  │       ├─ common_name
      │                                  │       ├─ organization
      │                                  │       ├─ organizational_unit
      │                                  │       ├─ country / state / locality
      │                                  │       ├─ calibration_text
      │                                  │       └─ validity_days
      │                                  │
      │                                  └─ Output: root-ca.crt, root-ca.key (PEM)
      │                                  └─ Algorithms: Ed25519, RSA-2048, RSA-4096
      │                                  └─ Bundle management (JSON format)
      │                                  │   └─ Multi-CA chain tracking
      │                                  │   └─ Automatic entry creation
      │                                  │
      │                                  └─ Summary report: --summary-out (JSON)
      │                                      ├─ profile_id
      │                                      ├─ calibration_id
      │                                      ├─ serial number
      │                                      ├─ subject key identifier (SKI)
      │                                      ├─ validity period
      │                                      └─ PEM paths
      │
      ├─ ca issue                      → Intermediate CA oluştur
      │                                  └─ Parent: issuer cert + key
      │                                  └─ Profile: intermediate section from YAML
      │                                  └─ Certificate chain building
      │                                  │   ├─ Automatic serial generation
      │                                  │   ├─ SKI (Subject Key Identifier)
      │                                  │   └─ AKI (Authority Key Identifier)
      │                                  │
      │                                  └─ Basic Constraints: CA=TRUE, pathlen
      │                                  └─ Key Usage: keyCertSign, cRLSign
      │                                  └─ Bundle update: --bundle-out
      │                                  └─ Summary: --summary-out (JSON)
      │
      └─ ca sign-server                → Server certificate imzala
                                         └─ Input:
                                         │   ├─ CA cert + key (PEM)
                                         │   ├─ Hostname (required)
                                         │   ├─ Organization salt (hex)
                                         │   └─ Calibration text
                                         │
                                         └─ SAN Extensions:
                                         │   ├─ Primary: DNS:{hostname}
                                         │   ├─ --extra-dns: comma-separated
                                         │   └─ --extra-ip: comma-separated
                                         │
                                         └─ Aunsorm Calibration Extension:
                                         │   └─ OID: 1.3.6.1.4.1.99999.1
                                         │   └─ Embedded metadata in DER
                                         │
                                         └─ Distinguished Name:
                                         │   ├─ CN: {hostname}
                                         │   ├─ O: --organization
                                         │   ├─ OU: --organizational-unit
                                         │   └─ C/ST/L: --country/state/locality
                                         │
                                         └─ Key Usage: digitalSignature, keyEncipherment
                                         └─ Extended Key Usage: serverAuth
                                         └─ Algorithms: Ed25519, RSA-2048, RSA-4096
                                         └─ Validity: --validity-days (default: 365)
                                         └─ Output: server.crt, server.key (PEM)
                                         └─ Production-ready TLS certificates
```

##### 🌐 Aunsorm Server - Production HTTP API

```
aunsorm-server v0.4.1
│
├─ 🔐 OAuth 2.0 / OIDC Flow
│  ├─ POST   /oauth/begin-auth          → PKCE S256 yetkilendirme başlat
│  ├─ POST   /oauth/token               → Access token al
│  ├─ POST   /oauth/introspect          → Token doğrula
│  ├─ GET    /oauth/jwks.json           → Public key seti (JWKS)
│  └─ GET    /oauth/transparency        → Token şeffaflık günlüğü
│
├─ 🎲 Cryptographic RNG (Matematiksel Geliştirilmiş Entropi)
│  └─ GET    /random/number             → HKDF + NEUDZ-PCS + AACM mixing
│                                          └─ Query: ?min=X&max=Y (default: 0-100)
│                                          └─ χ² = 101.18 ≈ 100.0 (4M samples validated)
│                                          └─ Performans: ~78,000 samples/second
│
├─ 📹 SFU Integration (E2EE Key Management)
│  ├─ POST   /sfu/context               → E2EE session oluştur
│  │                                       └─ Input: room_id, participant, enable_e2ee
│  │                                       └─ Output: context_id, session_id, key, nonce
│  └─ POST   /sfu/context/step          → Ratchet key rotation
│                                          └─ Forward secrecy + replay protection
│
├─ 📱 MDM (Mobile Device Management)
│  ├─ POST   /mdm/register              → Cihaz kaydı + Politika + Sertifika
│  ├─ GET    /mdm/policy/{platform}     → Platform politikası (ios/android/windows)
│  └─ GET    /mdm/cert-plan/{device_id} → Sertifika dağıtım planı
│
├─ 🔍 Transparency & Audit
│  └─ GET    /transparency/tree         → Merkle tree audit log
│
├─ 📊 Monitoring
│  ├─ GET    /health                    → Health check endpoint
│  └─ GET    /metrics                   → Prometheus metrics (opsiyonel)
│
└─ 🔜 ACME Protocol (v0.5.0 - Planned)
   ├─ GET    /acme/directory            → ACME directory discovery
   ├─ HEAD   /acme/new-nonce            → Nonce generation
   ├─ POST   /acme/new-account          → Account creation
   ├─ POST   /acme/new-order            → Certificate order
   ├─ POST   /acme/authz/{id}           → Authorization status
   ├─ POST   /acme/challenge/{id}       → Challenge validation
   ├─ POST   /acme/finalize/{order_id}  → Certificate finalization
   └─ POST   /acme/revoke-cert          → Certificate revocation
```

> **📌 NOT:** Bu ağaçta gösterilen her komut ve endpoint, ilerleyen sürümlerde **daha fazla özellik ve parametre** ile genişletilecektir.
> 
> **🔜 GELECEK ENDPOINT'LER:**
> - **v0.5.0 (Q1 2026):** ACME Protocol endpoints (RFC 8555) - `aunsorm-acme` crate zaten hazır, entegrasyon bekliyor
> - **v0.6.0:** WebTransport E2EE endpoints - HTTP/3 QUIC datagrams
> - **v0.7.0:** Blockchain integration endpoints - Transparency log anchoring 
> Detaylı kullanım ve tüm parametreler için:
> - CLI: `aunsorm-cli <command> --help`
> - Server: [`crates/server/README.md`](crates/server/README.md)
> - X.509: [`crates/x509/README.md`](crates/x509/README.md)
> - JWT: [`crates/jwt/README.md`](crates/jwt/README.md)

**Özellikler:**
- ✅ **PKCE S256 OAuth Flow:** Güvenli authorization code exchange
- ✅ **Ed25519 JWT Signing:** Post-quantum ready token imzalama
- ✅ **JTI Replay Protection:** SQLite tabanlı token replay koruması
- ✅ **Matematiksel Entropi Mixing:** NEUDZ-PCS + AACM prime distribution models
- ✅ **Session Ratcheting:** SFU E2EE için otomatik key rotation
- ✅ **Multi-platform MDM:** iOS, Android, Windows, macOS, Linux desteği
- ✅ **Transparency Logging:** Merkle tree based audit trail
- ✅ **Production Ready:** Async/await, structured logging, OpenTelemetry

**Hızlı Başlangıç:**
```bash
# Environment variables
export AUNSORM_JWT_SEED_B64="$(openssl rand -base64 32)"
export AUNSORM_JWT_KID="prod-key-2025"
export AUNSORM_ISSUER="https://auth.example.com"
export AUNSORM_AUDIENCE="example-app"

# Sunucuyu başlat
cargo run --release --bin aunsorm-server

# Test et
curl http://localhost:8080/health
curl http://localhost:8080/random/number
curl "http://localhost:8080/random/number?min=1&max=1000"
```

Detaylı API dokümantasyonu ve kullanım örnekleri için: [`crates/server/README.md`](crates/server/README.md)

#### 🎲 Kriptografik Rastgele Sayı Üretimi (RNG)

Aunsorm Server, endüstri standardı kriptografik güvenliği matematiksel entropi karışımıyla birleştiren benzersiz bir RNG sistemi sunar.

**Entropy Pipeline:**
```
1. Multi-Source Base Entropy
   ├─ OsRng (OS kernel entropy - 32 bytes)
   ├─ Counter (monotonic increment)
   ├─ Timestamp (nanosecond precision)
   ├─ Process ID (PID isolation)
   └─ Thread ID (thread-safe parallelism)
         ↓
2. HKDF Extract-and-Expand (RFC 5869)
   └─ Algorithm: HMAC-SHA256
   └─ Output: 32 bytes deterministic-but-unpredictable
         ↓
3. Mathematical Entropy Mixing
   ├─ First 16 bytes  → NEUDZ-PCS (Prime Counting Function)
   │                     └─ π(x) ≈ x/ln(x) × (1 + a/ln(x) + b/(ln(x))²)
   └─ Last 16 bytes   → AACM (Anglenna Angular Correction Model)
                         └─ Cipolla expansion + sinusoidal correction
         ↓
4. Constant-Time Rejection Sampling
   └─ Uniform distribution without modulo bias
         ↓
5. Output: Cryptographically secure random number
```

**Matematiksel Modeller:**

1. **NEUDZ-PCS (Prime Counting Function):**
   - Asal sayı dağılımı teorisine dayalı entropi karışımı
   - Zeroish sabitleri ile asal boşlukları modelleme
   - Her byte için bağımsız prime distribution mixing

2. **AACM (Anglenna Angular Correction Model):**
   - Cipolla polinomial genişlemesi
   - Sinüzoidal düzeltme terimleri
   - Yüksek dereceli moment dengeleme

**İstatistiksel Validasyon:**

| Metrik | Hedef | Gerçekleşen | Durum |
|--------|-------|-------------|-------|
| **Chi-Square (χ²)** | 100.0 ± 5 | 101.18 | ✅ PASS |
| **Test Samples** | 1M+ | 4M (4 test × 1M) | ✅ |
| **Confidence Level** | 95%+ | 96.7% | ✅ |
| **Throughput** | 50K+/s | ~78K/s | ✅ |
| **Degrees of Freedom** | 100 | 100 | ✅ |

**API Kullanımı:**

```bash
# 1. Varsayılan range (0-100)
curl http://localhost:8080/random/number
# {"value":42,"min":0,"max":100,"entropy":"a1b2c3..."}

# 2. Custom range (1-1000)
curl "http://localhost:8080/random/number?min=1&max=1000"
# {"value":347,"min":1,"max":1000,"entropy":"d4e5f6..."}

# 3. Büyük sayılar (lottery simulation)
curl "http://localhost:8080/random/number?min=1&max=90000000"
# {"value":45782103,"min":1,"max":90000000,"entropy":"g7h8i9..."}

# 4. Sadece max (0-20)
curl "http://localhost:8080/random/number?max=20"
# {"value":13,"min":0,"max":20,"entropy":"j0k1l2..."}

# 5. Sadece min (50-100)
curl "http://localhost:8080/random/number?min=50"
# {"value":78,"min":50,"max":100,"entropy":"m3n4o5..."}
```

**Validasyon:**
- `min ≤ max` (aksi halde `400 Bad Request`)
- `max ≤ u64::MAX/2` (güvenlik limiti)
- Constant-time implementation (timing attack koruması)

**Production Use Cases:**
- 🎰 **Online Gaming:** Slot machines, dice rolls, card shuffling
- 🎫 **Lottery Systems:** Fair ve audit-ready random number generation
- 🔐 **Cryptographic Nonces:** Session IDs, CSRF tokens, API keys
- 🎲 **Simulation:** Monte Carlo, statistical sampling
- 🔢 **OTP Generation:** 2FA codes, verification PINs

**Neden Aunsorm RNG?**
- ✅ Matematiksel model ile doğrulanmış uniformity
- ✅ NIST SP 800-90 standartlarına uyumlu HKDF
- ✅ Multi-source entropy (kernel + system state)
- ✅ Constant-time implementation (side-channel safe)
- ✅ Parametric range (1 request = her aralık için)
- ✅ Audit trail (her request için entropy hex)

Detaylı matematiksel analiz: [`crates/server/PRODUCTION_ENTROPY_MODEL.md`](crates/server/PRODUCTION_ENTROPY_MODEL.md)

### 🎯 Yakında Gelecek Özellikler

#### v0.4.3 (Q4 2025) - RSA Support
- ✅ RSA 2048/4096 key generation
- ✅ Windows ve legacy sistem uyumluluğu
- ✅ Multi-algorithm certificate support

#### v0.5.0 (Q1 2026) - **Let's Encrypt ACME Client + Server Endpoints**

**CLI (aunsorm-cli acme):**
- 🚀 **Otomatik Sertifika Yönetimi:** Hiçbir manuel işlem gerektirmeden
- 🌍 **Let's Encrypt Entegrasyonu:** Ücretsiz, güvenilir SSL/TLS sertifikaları
- ♻️ **Auto-Renewal:** 30 gün kala otomatik yenileme
- 🎯 **Domain Validation:** HTTP-01, DNS-01, TLS-ALPN-01
- 🔄 **Zero-Downtime:** Kesintisiz sertifika rotation

**Server API (aunsorm-server /acme/*):**
- 🔌 **ACME Protocol Endpoints:** RFC 8555 compliant server implementation
- 📋 **Directory Discovery:** GET /acme/directory → newNonce, newAccount, newOrder
- 🔐 **Account Management:** POST /acme/new-account → ACME account creation
- � **Order Management:** POST /acme/new-order → Certificate order workflow
- ✅ **Authorization:** Challenge validation (HTTP-01, DNS-01, TLS-ALPN-01)
- 🔄 **Certificate Lifecycle:** Issue, revoke, renew operations
- �📊 **Monitoring:** Prometheus metrics ve alerting

```bash
# CLI: ACME ile Let's Encrypt sertifikası al (v0.5.0)
aunsorm-cli acme certify --domain example.com \
  --validation http-01 --webroot /var/www/html

# CLI: Otomatik renewal (cron ile)
aunsorm-cli acme renew --check-all --days-before 30

# Server: ACME directory endpoint (v0.5.0)
curl http://localhost:8080/acme/directory
# Response: {"newNonce":"...","newAccount":"...","newOrder":"..."}
```

**TAMAMEN BAĞIMSIZ:** Certbot, acme.sh veya başka hiçbir araca ihtiyaç yok!

> **📦 Not:** `aunsorm-acme` crate (directory parser, nonce manager, JWS signing) mevcut ve test edilmiştir. 
> v0.5.0'da CLI komutları ve Server endpoint'leri eklenecektir.

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

## 🎯 Aunsorm Kalibrasyon Sistemi

Aunsorm'un **kalibrasyon sistemi**, organizasyona özgü entropi oluşturarak her kurulumun benzersiz kriptografik parmak izine sahip olmasını sağlar. Bu sistem, aynı şifreleme anahtarını kullansanız bile farklı organizasyonların farklı çıktılar üretmesini garantiler.

### Kalibrasyon Nedir?

Kalibrasyon, üç temel bileşenden oluşur:

1. **Organization Salt (`org-salt`)**: Base64 encoded 16-byte random değer
2. **Calibration Text (`calib-text`)**: Organizasyona özgü metin (örn: "Neudzulab | Prod | 2025-08")
3. **KDF Profile**: Key derivation zorluk seviyesi (mobile/low/medium/high/ultra)

Bu üç değer birleşerek **Calibration Context** oluşturur ve tüm kriptografik işlemlerde temel entropi kaynağı olarak kullanılır.

### Neden Kalibrasyon?

✅ **Organizasyon İzolasyonu:** Her kuruluş kendi kriptografik alanında çalışır
✅ **Replay Saldırı Koruması:** Bir organizasyonun paketi başka organizasyonda geçersizdir
✅ **Audit Trail:** Her işlem kalibrasyona bağlı, izlenebilir
✅ **Deterministik Güvenlik:** Aynı kalibrasyon = aynı davranış (test edilebilir)
✅ **X.509 Entegrasyonu:** Sertifikalarda metadata olarak saklanabilir

### Kalibrasyon Nasıl Oluşturulur?

```bash
# 1. Organization salt oluştur (bir kez yapılır, güvenli sakla!)
openssl rand -base64 16
# Çıktı: V2VBcmVLdXQuZXU=

# 2. Calibration text belirle (organizasyon adı + environment + yıl)
# Örnekler:
# - "Neudzulab | Production | 2025-08"
# - "ACME Corp | Development | 2025-Q4"
# - "MyCompany | Staging | 2025"

# 3. Kalibrasyonu doğrula
aunsorm-cli calib inspect \
  --org-salt V2VBcmVLdXQuZXU= \
  --calib-text "Neudzulab | Prod | 2025-08" \
  --format text

# Output:
# ✓ Calibration Context Valid
# Organization Salt: V2VBcmVLdXQuZXU=
# Calibration Text: Neudzulab | Prod | 2025-08
# Context Hash: 3a7f9c...
# Status: READY

# 4. Koordinat türet (şifreleme/imzalama için)
aunsorm-cli calib derive-coord \
  --password MySecretPassword \
  --org-salt V2VBcmVLdXQuZXU= \
  --calib-text "Neudzulab | Prod | 2025-08" \
  --kdf medium \
  --format text

# 5. Fingerprint oluştur (sertifika metadata için)
aunsorm-cli calib fingerprint \
  --org-salt V2VBcmVLdXQuZXU= \
  --calib-text "Neudzulab | Prod | 2025-08" \
  --format text

# Çıktı: SHA-256 hash of calibration context
```

### KDF Profilleri

Aunsorm, farklı güvenlik seviyelerine göre 5 KDF profili sunar:

| Profile | Argon2 Memory | Time Cost | Parallelism | Kullanım Senaryosu |
|---------|---------------|-----------|-------------|---------------------|
| **mobile** | 16 MB | 2 | 1 | Mobil cihazlar, IoT |
| **low** | 32 MB | 3 | 1 | Düşük kaynaklı sistemler |
| **medium** | 64 MB | 4 | 2 | **Varsayılan (önerilen)** |
| **high** | 128 MB | 5 | 4 | Yüksek güvenlik gereksinimleri |
| **ultra** | 256 MB | 8 | 8 | Maksimum güvenlik (sunucular) |

```bash
# Medium profile (önerilen)
aunsorm-cli encrypt --password P --in msg.txt --out enc.b64 \
  --org-salt V2VBcmVLdXQuZXU= \
  --calib-text "Neudzulab | Prod | 2025-08" \
  --kdf medium

# Ultra profile (sunucu ortamları için)
aunsorm-cli encrypt --password P --in msg.txt --out enc.b64 \
  --org-salt V2VBcmVLdXQuZXU= \
  --calib-text "Neudzulab | Prod | 2025-08" \
  --kdf ultra
```

### X.509 Sertifikalarında Kalibrasyon

Aunsorm, sertifikalara **kalibrasyon metadata** ekleyerek izlenebilirlik sağlar:

```bash
# Sertifika oluşturma sırasında kalibrasyon ekleme
aunsorm-cli x509 ca sign-server \
  --ca-cert root-ca.crt --ca-key root-ca.key \
  --hostname example.com \
  --cert-out server.crt --key-out server.key \
  --org-salt V2VBcmVLdXQuZXU= \
  --calibration-text "Neudzulab | Prod | 2025-08" \
  --algorithm ed25519

# Sertifikayı inspect et (kalibrasyon bilgisi görünür)
openssl x509 -in server.crt -text -noout | grep -A2 "Aunsorm"
```

### Kalibrasyon Best Practices

1. **Organization Salt'u Güvenli Sakla:**
   - Secrets manager (AWS Secrets Manager, HashiCorp Vault) kullan
   - Asla Git/version control'e commit etme
   - Production/staging için farklı salt kullan

2. **Calibration Text Standardı:**
   - Format: `"Organization | Environment | Period"`
   - Örnek: `"ACME Corp | Production | 2025-Q4"`
   - Yıllık veya dönemsel olarak güncelle

3. **KDF Profile Seçimi:**
   - Mobil: `mobile` veya `low`
   - Web/Desktop: `medium` (default)
   - Sunucu: `high` veya `ultra`

4. **Environment İzolasyonu:**
   ```bash
   # Production
   --org-salt <prod-salt> --calib-text "Company | Prod | 2025"
   
   # Staging
   --org-salt <staging-salt> --calib-text "Company | Staging | 2025"
   
   # Development
   --org-salt <dev-salt> --calib-text "Company | Dev | 2025"
   ```

5. **Kalibrasyon Dosyası:**
   ```bash
   # calib-prod.txt dosyası oluştur
   echo "Neudzulab | Production | 2025-08" > calib-prod.txt
   
   # Kullan
   aunsorm-cli encrypt --password P --in msg.txt --out enc.b64 \
     --org-salt V2VBcmVLdXQuZXU= \
     --calib-file calib-prod.txt \
     --kdf medium
   ```

### Kalibrasyon Migrasyonu

Eğer kalibrasyon değerlerini değiştirmeniz gerekirse:

```bash
# 1. Eski kalibrasyon ile şifreyi çöz
aunsorm-cli decrypt --password P --in old.b64 --out plain.txt \
  --org-salt <old-salt> --calib-text "Old Calib"

# 2. Yeni kalibrasyon ile tekrar şifrele
aunsorm-cli encrypt --password P --in plain.txt --out new.b64 \
  --org-salt <new-salt> --calib-text "New Calib"
```

**Uyarı:** Kalibrasyon değiştirme, tüm mevcut şifrelenmiş verilerin yeniden şifrelenmesini gerektirir!

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
