# Aunsorm Cryptography Suite

**Modern, bağımsız ve production-ready kriptografi ve sertifika yönetim platformu.**

Aunsorm, end-to-end encryption (E2EE), post-quantum cryptography (PQC), JWT token management, X.509 certificate authority ve **otomatik Let's Encrypt entegrasyonu** sağlayan kapsamlı bir güvenlik çözümüdür.

## 🚀 Özellikler

### ✅ Aktif Özellikler (v0.4.5)

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
aunsorm-cli v0.4.5
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
aunsorm-server v0.4.5
│
├─ 🔐 OAuth 2.0 / OIDC Flow (RFC 6749 + RFC 7636 PKCE)
│  ├─ POST   /oauth/begin-auth ✅       → RFC uyumlu yetkilendirme başlat
│  │                                       └─ Input: client_id, redirect_uri, state, scope, code_challenge (S256)
│  │                                       └─ Output: code (authorization code), state (echoed)
│  │                                       └─ PKCE: SHA-256 code_challenge required
│  │                                       └─ State: CSRF protection (recommended)
│  │                                       └─ Redirect URI: HTTPS enforced (localhost HTTP allowed)
│  │                                       └─ Subject: Optional hint (not for authentication)
│  │
│  ├─ POST   /oauth/token ✅            → Access token al (authorization_code grant)
│  │                                       └─ Input: grant_type, code, code_verifier, client_id, redirect_uri
│  │                                       └─ Output: access_token (JWT), token_type (Bearer), expires_in
│  │                                       └─ PKCE Verification: SHA-256(code_verifier) == code_challenge
│  │                                       └─ Redirect URI Match: CRITICAL security validation
│  │                                       └─ Single-use code: Consumed after first use
│  │                                       └─ Scope: Embedded in JWT claims if provided
│  │
│  ├─ POST   /oauth/introspect ✅       → Token doğrula (RFC 7662)
│  │                                       └─ Input: token (JWT access token)
│  │                                       └─ Output: active (bool), sub, client_id, scope, exp, iat
│  │                                       └─ JTI Replay Protection: SQLite-based token store
│  │                                       └─ Signature Validation: Ed25519 public key verification
│  │
│  ├─ GET    /oauth/jwks.json ✅        → Public key seti (RFC 7517 JWKS)
│  │                                       └─ Output: Multiple Ed25519 public keys
│  │                                       └─ Use Case: OAuth/OIDC discovery, token verification
│  │
│  └─ GET    /oauth/transparency ✅     → Token şeffaflık günlüğü
│                                          └─ Output: Token issuance events (Merkle tree)
│                                          └─ Audit Trail: JTI, subject, audience, expiry
│
├─ 🎲 Cryptographic RNG (Matematiksel Geliştirilmiş Entropi)
│  └─ GET    /random/number             → HKDF + NEUDZ-PCS + AACM mixing
│                                          └─ Query: ?min=X&max=Y (default: 0-100)
│                                          └─ χ² = 101.18 ≈ 100.0 (4M samples validated)
│                                          └─ Performans: ~78,000 samples/second
│
├─ 🆔 ID Generation (HEAD-Stamped Unique IDs)
│  ├─ POST   /id/generate �            → Git HEAD tabanlı benzersiz kimlik oluştur
│  │                                       └─ `aunsorm-id` crate (v0.4.1)
│  │                                       └─ Environment: AUNSORM_HEAD, GITHUB_SHA, GIT_COMMIT
│  │                                       └─ Format: aid.<namespace>.<head>.<payload>
│  │                                       └─ Input: namespace (optional, default: "aunsorm")
│  │                                       └─ Output: HeadStampedId (JSON)
│  │                                       │   ├─ id: string
│  │                                       │   ├─ namespace: string
│  │                                       │   ├─ head_prefix: string (8 hex chars)
│  │                                       │   ├─ fingerprint: string (20 hex chars)
│  │                                       │   ├─ timestamp_micros: u64
│  │                                       │   └─ counter: u64
│  │
│  ├─ POST   /id/parse �               → [Planlandı v0.4.5] Kimlik doğrula ve çözümle
│  │                                       └─ Input: id (string)
│  │                                       └─ Output: HeadStampedId (JSON) or error
│  │                                       └─ Validation: format, fingerprint, namespace
│  │
│  └─ POST   /id/verify-head �         → [Planlandı v0.4.5] Kimliğin HEAD ile eşleştiğini doğrula
│                                          └─ Input: id (string), head (git SHA)
│                                          └─ Output: { "matches": boolean }
│                                          └─ Use case: CI/CD artifact verification
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
├─ ⛓️ Blockchain DID Doğrulama (Hyperledger Fabric PoC)
│  └─ POST   /blockchain/fabric/did/verify 🚧 → Fabric ağına çapalanmış DID kanıtını doğrula
│                                             └─ Input: did, channel, proof{challenge(base64url), signature(base64url), block_hash(hex), transaction_id, timestamp_ms}
│                                             └─ Output: ledger_anchor, verification_method, audit(clock_skew)
│                                             └─ Saat sapması limiti: ≤ 30 saniye, Ed25519 imza doğrulaması
│
├─ 🔍 Transparency & Audit
│  └─ GET    /transparency/tree         → Merkle tree audit log
│
├─ 📊 Monitoring
│  ├─ GET    /health                    → Health check endpoint
│  └─ GET    /metrics                   → Prometheus metrics (opsiyonel)
│
├─ 🚀 HTTP/3 QUIC Datagrams (Experimental - v0.4.4)
│  ├─ GET    /http3/capabilities 🚧    → HTTP/3 durum & datagram kanalı keşfi
│  │                                     └─ Output: enabled, alt_svc_port, alt_svc_max_age
│  │                                     └─ Datagram kanalları ve payload açıklamaları
│  │                                     └─ Feature flag: `http3-experimental`
│  ├─ Channel: Telemetry (0)           → OpenTelemetry metrics streaming
│  │                                     └─ Real-time metrics over QUIC
│  │                                     └─ Low latency, unreliable delivery
│  │                                     └─ Max payload: 1150 bytes
│  │
│  ├─ Channel: Audit (1)               → Audit event stream
│  │                                     └─ Security event logging
│  │                                     └─ Transparency log updates
│  │
│  └─ Channel: Ratchet (2)             → Session ratchet probes
│                                        └─ E2EE session state monitoring
│                                        └─ Forward secrecy validation
│
│  **Features:**
│  ├─ Protocol: HTTP/3 (QUIC RFC 9000)
│  ├─ Framing: DATAGRAM frames (RFC 9221)
│  ├─ Encoding: postcard (compact binary)
│  ├─ Alt-Svc: Auto-advertises H3 upgrade
│  ├─ Max wire size: 1350 bytes
│  └─ Feature flag: `http3-experimental`
│
└─ 🔜 ACME Protocol (RFC 8555)
   ├─ GET    /acme/directory 📋         → [Planlandı v0.5.0] ACME directory discovery
   │                                       └─ `aunsorm-acme` crate hazır (directory parser)
   │                                       └─ Output: newNonce, newAccount, newOrder URLs
   │
   ├─ HEAD   /acme/new-nonce 📋         → [Planlandı v0.5.0] Nonce generation
   │                                       └─ Replay-Nonce header generation
   │                                       └─ NonceManager hazır (in-memory + SQLite)
   │
   ├─ POST   /acme/new-account 📋       → [Planlandı v0.5.0] Account creation
   │                                       └─ JWS signature verification (JwsSigner hazır)
   │                                       └─ Account key registration
   │
   ├─ POST   /acme/new-order 📋         → [Planlandı v0.5.0] Certificate order
   │                                       └─ Domain validation workflow
   │                                       └─ Challenge generation (http-01, dns-01)
   │
   ├─ POST   /acme/authz/{id} 📋        → [Planlandı v0.5.0] Authorization status
   │                                       └─ Challenge status polling
   │
   ├─ POST   /acme/challenge/{id} 📋    → [Planlandı v0.5.0] Challenge validation
   │                                       └─ HTTP-01, DNS-01 verification
   │
   ├─ POST   /acme/finalize/{order_id} 📋 → [Planlandı v0.5.0] Certificate finalization
   │                                       └─ CSR processing + X.509 issuance
   │                                       └─ Integration: `aunsorm-x509` CA signing
   │
   └─ POST   /acme/revoke-cert 📋       → [Planlandı v0.5.0] Certificate revocation
                                           └─ CRL management
```

> **📌 NOT:** Bu ağaçta gösterilen her komut ve endpoint, ilerleyen sürümlerde **daha fazla özellik ve parametre** ile genişletilecektir.
> 
> **🔜 GELECEK ENDPOINT'LER:**
> - **v0.4.5 (Q4 2025):** ID Generation endpoints - `aunsorm-id` crate hazır, 3 endpoint eklenmesi gerekiyor
> - **v0.5.0 (Q1 2026):** ACME Protocol endpoints (RFC 8555) - `aunsorm-acme` crate hazır, 8 endpoint entegrasyonu bekliyor
> - **v0.6.0 (Q2 2026):** WebTransport API - Bidirectional HTTP/3 QUIC streams, production-grade datagram hardening
> - **v0.7.0 (Q3 2026):** Blockchain integration endpoints - Transparency log anchoring to public chains 
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
- ✅ **HTTP/3 QUIC Datagrams:** Experimental low-latency telemetry streaming
- � **HEAD-Stamped IDs:** Git commit SHA tabanlı benzersiz kimlik üretimi (`aunsorm-id` crate hazır, v0.4.5'te entegre edilecek)
- 📋 **ACME Protocol:** Let's Encrypt uyumlu otomatik sertifika yönetimi (RFC 8555, `aunsorm-acme` crate hazır, v0.5.0'da entegre edilecek)
- ✅ **Production Ready:** Async/await, structured logging, OpenTelemetry

**Hızlı Başlangıç:**
```bash
# Environment variables
export AUNSORM_JWT_SEED_B64="$(openssl rand -base64 32)"
export AUNSORM_JWT_KID="prod-key-2025"
export AUNSORM_ISSUER="https://auth.example.com"
export AUNSORM_AUDIENCE="example-app"

# Sunucuyu başlat (HTTP/2)
cargo run --release --bin aunsorm-server

# HTTP/3 QUIC experimental desteği ile başlat
cargo run --release --features http3-experimental --bin aunsorm-server

# Test et
curl http://localhost:8080/health
curl http://localhost:8080/random/number
curl "http://localhost:8080/random/number?min=1&max=1000"

# HTTP/3 bağlantı upgrade bilgisi (Alt-Svc header)
curl -I http://localhost:8080/health
# Alt-Svc: h3=":8080"; ma=86400

# OAuth2 PKCE Flow (RFC 6749 + RFC 7636)
# 1. Authorization Request
CODE_VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | base64 | tr -d '=' | tr '+/' '-_')

curl -X POST http://localhost:8080/oauth/begin-auth \
  -H "Content-Type: application/json" \
  -d "{
    \"client_id\": \"webapp-123\",
    \"redirect_uri\": \"https://app.example.com/callback\",
    \"state\": \"random-csrf-token-xyz\",
    \"scope\": \"read write\",
    \"code_challenge\": \"$CODE_CHALLENGE\",
    \"code_challenge_method\": \"S256\"
  }"
# Response: {"code":"auth_abc123","state":"random-csrf-token-xyz","expires_in":600}

# 2. Token Exchange
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\": \"authorization_code\",
    \"code\": \"auth_abc123\",
    \"code_verifier\": \"$CODE_VERIFIER\",
    \"client_id\": \"webapp-123\",
    \"redirect_uri\": \"https://app.example.com/callback\"
  }"
# Response: {"access_token":"eyJ...","token_type":"Bearer","expires_in":600}
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

#### 🚀 HTTP/3 QUIC Datagrams (Experimental)

Aunsorm Server, **HTTP/3 üzerinde QUIC DATAGRAM** frame'leri ile düşük gecikmeli, güvenilir olmayan veri akışı sağlar. Bu özellik, gerçek zamanlı telemetri, audit logging ve session monitoring için optimize edilmiştir.

**HTTP/3 Capability Discovery:**

- `GET /http3/capabilities` endpoint'i, HTTP/3 PoC dinleyicisinin durumunu ve QUIC datagram kanallarını JSON formatında döndürür.
- `enabled`, `alt_svc_port` ve `alt_svc_max_age` alanları; client'ların hangi port üzerinden H3 upgrade yapabileceğini bildirir.
- `datagrams.channels` listesi; Telemetry/Audit/Ratchet kanallarının numeric ID'leri ve amaçlarını içerir.

```bash
curl -s http://127.0.0.1:8080/http3/capabilities | jq
{
  "enabled": true,
  "status": "active",
  "alt_svc_port": 8080,
  "alt_svc_max_age": 3600,
  "datagrams": {
    "supported": true,
    "max_payload_bytes": 1150,
    "channels": [
      { "channel": 0, "label": "telemetry", "purpose": "OpenTelemetry metrik anlık görüntüsü (OtelPayload)" },
      { "channel": 1, "label": "audit", "purpose": "Yetkilendirme denetim olayları (AuditEvent)" },
      { "channel": 2, "label": "ratchet", "purpose": "Oturum ratchet ilerleme gözlemleri (RatchetProbe)" }
    ],
    "notes": "Datagram yükleri postcard ile serileştirilir; en fazla 1150 bayt payload desteklenir."
  }
}
```

**Neden QUIC Datagrams?**
- ⚡ **Ultra-low latency:** TCP head-of-line blocking yok
- 🔒 **Built-in encryption:** TLS 1.3 integrated
- 📦 **Unreliable delivery:** Fire-and-forget semantics
- 🎯 **Multiplexing:** Tek connection üzerinde çoklu stream
- 🚀 **0-RTT reconnection:** Session resumption

**Datagram Kanalları:**

| Kanal | ID | Kullanım | Max Payload |
|-------|----|----------|-------------|
| **Telemetry** | 0 | OpenTelemetry metrics streaming | 1150 bytes |
| **Audit** | 1 | Security event logging | 1150 bytes |
| **Ratchet** | 2 | E2EE session state probes | 1150 bytes |

**Protokol Detayları:**
```
Wire Format (postcard binary encoding):
┌─────────────────────────────────────────┐
│ Version (u8)                            │ 1 byte
├─────────────────────────────────────────┤
│ Channel (u8)                            │ 1 byte
├─────────────────────────────────────────┤
│ Timestamp (u64, milliseconds)           │ 8 bytes
├─────────────────────────────────────────┤
│ Payload (enum-tagged, compact)          │ ≤ 1150 bytes
└─────────────────────────────────────────┘
Max total wire size: 1350 bytes
```

**Payload Türleri:**

1. **OtelPayload (Telemetry):**
   ```rust
   {
       "gauge_name": "server.cpu.utilization",
       "value_f64": 45.2,
       "unit": "percent",
       "attributes": {"host": "prod-01"}
   }
   ```

2. **AuditEvent (Audit):**
   ```rust
   {
       "action": "token.issued",
       "subject": "user@example.com",
       "metadata": {"token_id": "abc123"}
   }
   ```

3. **RatchetProbe (Ratchet):**
   ```rust
   {
       "session_id": "sess_xyz",
       "message_no": 42,
       "ratchet_counter": 15
   }
   ```

**HTTP/3 Upgrade Mekanizması:**

Sunucu, HTTP/2 response'larına `Alt-Svc` header'ı ekleyerek H3 desteğini duyurur:

```http
HTTP/1.1 200 OK
Alt-Svc: h3=":8080"; ma=86400
...
```

Client bu header'ı gördüğünde, aynı endpoint'i HTTP/3 ile tekrar deneyebilir.

**Feature Flag:**
```toml
# Cargo.toml
[features]
http3-experimental = ["h3", "h3-quinn", "quinn", "rustls"]
```

**Derleme ve Çalıştırma:**
```bash
# HTTP/3 desteği ile derle
cargo build --release --features http3-experimental

# Sunucuyu başlat
cargo run --release --features http3-experimental --bin aunsorm-server

# Log'larda HTTP/3 listener bilgisi görünür:
# INFO aunsorm_server: HTTP/3 PoC spawned on 127.0.0.1:8080
```

**Test:**
```bash
# HTTP/3 QUIC datagram testi
cargo test --features http3-experimental --test http3_datagram -- --nocapture

# Test: Telemetry datagram encode/decode roundtrip
# Test: Alt-Svc header injection verification
# Test: Channel routing validation
```

> 🛠️ Ops Notu: GitHub Actions üzerinde `ENABLE_HTTP3_POC=true` olarak tetiklenen akış, `http3-poc` işini çalıştırarak HTTP/3 canary testlerini (`aunsorm-server` + entegrasyon testleri) doğrular.

**Limitasyonlar (Experimental):**
- ⚠️ Production kullanımı önerilmez (v0.4.4 - PoC stage)
- ⚠️ Certificate pinning eksik
- ⚠️ Rate limiting yok
- ⚠️ Datagram ordering garanti edilmez
- ⚠️ Browser support sınırlı (Chrome 92+, Firefox 88+)

**Gelecek İyileştirmeler (v0.6.0):**
- ✨ WebTransport API support
- ✨ Bidirectional datagram streams
- ✨ Certificate transparency integration
- ✨ Congestion control tuning
- ✨ Production-grade hardening

Detaylı döküman: [`docs/src/architecture/http3-quic.md`](docs/src/architecture/http3-quic.md)

### 🎯 Yakında Gelecek Özellikler

#### v0.4.5 (Q4 2025) - ID Generation Service
- 📋 **HEAD-Stamped IDs:** `aunsorm-id` crate server entegrasyonu
- 🔗 **3 REST Endpoints:** /id/generate, /id/parse, /id/verify-head
- 🎯 **CI/CD Integration:** Git commit SHA tracking for artifacts
- ✅ **Monotonic Timestamps:** Collision-free ID generation

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
cargo install --path /aunsorm-crypt/crates/cli

# Binary release (coming soon)
curl -sSL https://install.aunsorm.dev | sh
```

## 🚀 5 Dakikada Başla

### ⚡ Normal Build

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

### ⚡ Build Süresini Azaltma İpuçları

**Problem:** Post-quantum kriptografi crate'leri (pqcrypto-*) build süresini ~10x artırıyor.

**Çözümler:**

```bash
# 1. Sadece ihtiyacınız olan workspace member'ı build edin
cargo build --release -p aunsorm-cli    # Sadece CLI
cargo build --release -p aunsorm-server # Sadece Server

# 2. İnkremental build (dev build daha hızlı)
cargo build  # Release yerine dev profil

# 3. Paralel compilation (CPU core sayınıza göre)
cargo build -j 8  # 8 paralel iş

# 4. sccache kullanın (compilation cache)
# https://github.com/mozilla/sccache
export RUSTC_WRAPPER=sccache
cargo build --release

# 5. mold linker kullanın (Linux/macOS - 10x daha hızlı linking)
# .cargo/config.toml:
# [target.x86_64-unknown-linux-gnu]
# linker = "clang"
# rustflags = ["-C", "link-arg=-fuse-ld=mold"]
```

**Not:** PQC özellikleri varsayılan olarak aktif. İleride ihtiyaç duyulursa feature flag sistemi eklenecek.

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

## Blockchain İnovasyon Programı
- [x] `docs/src/innovation/blockchain.md` vizyon, regülasyon rehberi ve teslimat yol haritasını yayımla.
- [x] `tests/blockchain/` altında mock ledger + bütünlük senaryosu iskeletlerini hazırlayıp PoC testlerini ekle.
- [x] Opsiyonel `.github/workflows/blockchain-poc.yml` işi ve `tests/blockchain/config.example.toml` yapılandırmasını oluştur.
- [x] Hyperledger Fabric için DID doğrulama PoC'unu REST katmanı planıyla birlikte sun (bkz. [`POST /blockchain/fabric/did/verify`](docs/src/operations/blockchain-integration.md)).
- [x] Quorum tabanlı audit trail ve tokenizasyon gereksinimlerini `docs/src/operations/blockchain-integration.md` içinde belgeleyerek finalize et.
  - GoQuorum 23.x audit ağı, `AuditAsset` soulbound token modeli ve `TOKENIZE_AUDIT` yetkileri ayrıntılandırıldı; AuditRelay köprüsü ve SOC 2/eIDAS raporlama takvimi belirlendi.
- [ ] Zincirler arası test harness'ini `tests/blockchain/cross_network.rs` taslağıyla planla ve veri seti gereksinimlerini tanımla.
- [ ] eIDAS/SOC 2 denetim raporu şablonlarını `certifications/` altında yayımla.
- [ ] FATF Travel Rule uyumluluğu için zincir üstü izleme ve raporlama entegrasyon stratejisini oluştur.
- [ ] Müşteri başına saklama/anahtar silme politikalarını blockchain katmanıyla eşleyip operasyonel runbook'a ekle.

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
-  **v0.4.5** (Now): HTTP/3 QUIC Datagrams PoC + Service Discovery Directive
-  **v0.4.5** (Q4 2025): HEAD-Stamped ID Generation endpoints
-  **v0.5.0** (Q1 2026): Let's Encrypt ACME client
-  **v0.5.1** (Q1 2026): Certificate monitoring & alerting
-  **v0.6.0** (Q2 2026): HSM integration, CT monitoring

## HTTP/3 + QUIC Programı Durumu
- [x] Araştırma & Seçim — `quinn`/`h3` ile `quiche` kıyaslaması ve datagram mesaj planı yayımlandı ([docs/src/architecture/http3-quic.md](docs/src/architecture/http3-quic.md)).
- [x] PoC Sprinti — `apps/server` içinde `http3-experimental` dinleyici ve QUIC datagram telemetri PoC'u.
- [x] Sertifikasyon ve Güvenlik Analizi — HSM uyumu ve QUIC datagram AEAD stratejileri raporlandı ([docs/src/operations/http3-quic-security.md](docs/src/operations/http3-quic-security.md)).
- [x] Ürünleştirme ve CI Entegrasyonu — Opsiyonel `http3-poc` CI işi (`ENABLE_HTTP3_POC=true`) ve operasyon runbook'u güncellendi.

##  Contributing

Katkılarınızı bekliyoruz! Lütfen [CONTRIBUTING.md](CONTRIBUTING.md) dosyasını okuyun.

##  License

MIT License - see [LICENSE](LICENSE) file.

##  Security

Security vulnerabilities: security@myeoffice.com

---

**Aunsorm** - Modern, Independent, Production-Ready Cryptography Platform
