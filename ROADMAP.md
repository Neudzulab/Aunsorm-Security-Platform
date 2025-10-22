# Aunsorm Cryptography Suite - Roadmap

## v0.4.5 (Current - October 17, 2025)

### ✅ Tamamlanan Özellikler

1. **X.509 Certificate Authority (CA)**
   - Ed25519 self-signed sertifika oluşturma
   - Root CA generation
   - Server certificate signing
   - Certificate chain validation
   - Aunsorm calibration metadata extension
   - CLI: `aunsorm-cli x509 ca init`, `aunsorm-cli x509 ca sign-server`

2. **Post-Quantum Cryptography (PQC)**
   - Kyber-1024 KEM (Key Encapsulation)
   - Dilithium-5 signatures
   - Hybrid classical + PQC encryption

3. **E2EE (End-to-End Encryption)**
   - Double Ratchet protocol
   - Forward secrecy
   - Session key rotation

4. **JWT Token Management**
   - Ed25519 signing
   - Token generation and verification
   - Calibration-based claims

5. **KMS (Key Management Service)**
   - Secure key storage
   - Key derivation (HKDF)
   - Profile-based KDF (Argon2)

6. **HEAD-Stamped ID Generation Service** ✨ NEW
   - Git commit SHA-based unique IDs
   - REST API: `/id/generate`, `/id/parse`, `/id/verify-head`
   - Custom namespace support
   - Monotonic timestamp + atomic counter
   - CI/CD artifact tracking
   - Environment variable support (AUNSORM_HEAD, GITHUB_SHA, etc.)

## v0.4.3 (Completed - Q4 2025)

### 🎯 RSA Key Generation Support

**Amaç:** Windows ve legacy sistemler için tam uyumluluk

**Yapılacaklar:**
- [x] `ring` crate dependency ekleme
- [x] RSA 2048/4096 key generation implementation
- [x] RSA keypair serialization (PEM format)
- [x] Test suite: RSA certificate chain validation
- [x] Performance benchmarks (Ed25519 vs RSA)
- [x] CLI: `--algorithm` parametresi tam çalışır hale getirme

**Sorumlu Agent:** Cryptography Agent  
**Tahmini Süre:** 4-6 saat  
**Bağımlılıklar:** `ring` v0.17+

**Dosyalar:**
- `/aunsorm-crypt/Cargo.toml` - ring dependency
- `/aunsorm-crypt/crates/x509/src/ca.rs` - RSA keygen impl
- `/aunsorm-crypt/crates/x509/src/tests/rsa_tests.rs` - Test suite

---

## v0.5.0 (Planned - Q1 2026)

### 🚀 ACME Protocol Client (Let's Encrypt Integration)

**Amaç:** Production-ready otomatik sertifika yönetimi

**Özellikler:**
1. **ACME v2 Protocol Implementation**
   - Account registration
   - Domain validation (HTTP-01, DNS-01, TLS-ALPN-01)
   - Certificate issuance
   - Certificate renewal (30 gün öncesi otomatik)
   - Certificate revocation

2. **Let's Encrypt Entegrasyonu**
   - Production API: `https://acme-v02.api.letsencrypt.org/directory`
   - Staging API: `https://acme-staging-v02.api.letsencrypt.org/directory`
   - Rate limit handling
   - Retry logic with exponential backoff

3. **Domain Validation Strategies**
   - **HTTP-01:** `.well-known/acme-challenge/` endpoint
   - **DNS-01:** TXT record automation (DNS provider API)
   - **TLS-ALPN-01:** ALPN protocol negotiation

4. **Certificate Lifecycle Management**
   - Otomatik renewal (30 gün kala)
   - Graceful certificate rotation (zero-downtime)
   - Certificate storage ve versioning
   - Expiry monitoring ve alerting

5. **CLI Commands**
   ```bash
   # ACME account oluştur
   aunsorm-cli acme register --email admin@example.com --staging
   
   # Domain için sertifika al
   aunsorm-cli acme certify \
     --domain example.com \
     --domain www.example.com \
     --validation http-01 \
     --webroot /var/www/html \
     --cert-out /etc/ssl/example.com.crt \
     --key-out /etc/ssl/example.com.key
   
   # Otomatik renewal (cron/systemd timer ile)
   aunsorm-cli acme renew --check-all --days-before 30
   
   # Sertifika iptal et
   aunsorm-cli acme revoke --cert /etc/ssl/example.com.crt
   ```

**Yapılacaklar:**
- [ ] ACME v2 protocol implementation
  - [x] Directory endpoint parsing
  - [x] Nonce management
- [x] JWS (JSON Web Signature) signing
- [x] Account key generation (RSA/ECDSA)
  
- [ ] Domain validation handlers
  - [ ] HTTP-01: Web server challenge response
  - [ ] DNS-01: DNS provider API abstraction
  - [ ] TLS-ALPN-01: ALPN challenge handler
  
- [ ] Certificate management
  - [ ] CSR (Certificate Signing Request) generation
  - [ ] Certificate download ve parsing
  - [ ] Chain validation
  - [ ] Storage backend (filesystem, KMS)
  
- [ ] Renewal logic
  - [ ] Expiry checker (30-day threshold)
  - [ ] Automatic renewal workflow
  - [ ] Post-renewal hooks (nginx reload, etc.)
  
- [ ] DNS Provider Integrations
  - [ ] Cloudflare API
  - [ ] Route53 API
  - [ ] Generic DNS provider interface
  
- [ ] Testing infrastructure
  - [ ] Mock ACME server
  - [ ] Integration tests with Let's Encrypt staging
  - [ ] End-to-end renewal tests
  
- [ ] Documentation
  - [ ] ACME protocol guide
  - [ ] Domain validation setup
  - [ ] Production deployment guide
  - [ ] Troubleshooting FAQ

**Bağımlılıklar:**
- `reqwest` - HTTPS client
- `serde_json` - JSON parsing
- `base64` - JWS encoding
- NO external ACME libraries (pure Rust implementation)

**Sorumlu Agent:** Network Security Agent  
**Tahmini Süre:** 40-60 saat (2-3 hafta)

**Dosyalar:**
- `/aunsorm-crypt/crates/acme/` - New crate
- `/aunsorm-crypt/crates/acme/src/client.rs` - ACME client
- `/aunsorm-crypt/crates/acme/src/validation.rs` - Validation handlers
- `/aunsorm-crypt/crates/acme/src/renewal.rs` - Renewal logic
- `/aunsorm-crypt/crates/cli/src/acme_commands.rs` - CLI integration

**Success Criteria:**
1. ✅ Let's Encrypt'ten production sertifika alabilme
2. ✅ Otomatik 30-günlük renewal çalışır
3. ✅ Zero-downtime certificate rotation
4. ✅ Multi-domain (SAN) sertifika desteği
5. ✅ HTTP-01 ve DNS-01 validation working
6. ✅ Rate limit handling ve retry logic

---

## v0.5.1 (Planned - Q1 2026)

### 🔄 Certificate Automation & Monitoring

**Özellikler:**
1. **Systemd Service Integration**
   ```ini
   # /etc/systemd/system/aunsorm-renewal.service
   [Unit]
   Description=Aunsorm Certificate Renewal
   
   [Service]
   Type=oneshot
   ExecStart=/usr/local/bin/aunsorm-cli acme renew --check-all
   ```

2. **Prometheus Metrics**
   - Certificate expiry days
   - Renewal success/failure rate
   - ACME API response times
   - Domain validation status

3. **Alerting**
   - Email notifications (expiry warnings)
   - Webhook integration (Slack, Discord)
   - Syslog integration

4. **Web Dashboard (Optional)**
   - Certificate inventory
   - Renewal schedule
   - Validation status
   - Historical metrics

---

## Future Considerations (v0.6.0+)

### Advanced Features

1. **Hardware Security Module (HSM) Integration**
   - PKCS#11 interface
   - YubiHSM support
   - Cloud KMS (AWS KMS, Google Cloud KMS)

2. **Certificate Transparency (CT) Monitoring**
   - CT log submission
   - Certificate monitoring
   - Revocation detection

3. **Multi-CA Support**
   - ZeroSSL support
   - Buypass support
   - Custom ACME CA

4. **Advanced Validation**
   - Email validation
   - IP validation
   - Wildcard certificate support

5. **Certificate Pinning**
   - HPKP (HTTP Public Key Pinning) generation
   - Mobile app pinning configuration

---

## Technical Debt & Improvements

### Performance
- [ ] Parallel certificate processing
- [ ] Batch renewal optimization
- [ ] Caching strategies (ACME directory, nonces)

### Security
- [ ] Secure key storage (encrypted at rest)
- [ ] Key rotation policies
- [ ] Audit logging
- [ ] Intrusion detection

### Testing
- [ ] 90%+ code coverage
- [ ] Chaos testing (network failures, API errors)
- [ ] Load testing (1000+ domains)
- [ ] Security audits

### Documentation
- [ ] API reference (rustdoc)
- [ ] Video tutorials
- [ ] Migration guides (from certbot, acme.sh)
- [ ] Best practices guide

---

## Community & Ecosystem

### Integration Examples
- [ ] Nginx integration guide
- [ ] Apache integration guide
- [ ] Caddy comparison
- [ ] Docker/Kubernetes deployment
- [ ] Ansible/Terraform modules

### Third-Party Integrations
- [ ] cPanel/Plesk plugins
- [ ] Control panel APIs
- [ ] CDN integration (Cloudflare, Fastly)
- [ ] Load balancer integration (HAProxy, Traefik)

---

## Version History

- **v0.4.1** (October 2025): Initial CA implementation, Ed25519 support
- **v0.4.2** (October 2025): CLI improvements, sign-server command
- **v0.4.3** (Planned): RSA support
- **v0.5.0** (Planned): ACME client
- **v0.5.1** (Planned): Automation & monitoring

---

## Contributing

Aunsorm açık kaynak bir projedir. Katkılarınızı bekliyoruz!

**Öncelikli Alanlarda:**
- ACME protocol implementation
- DNS provider integrations
- Documentation improvements
- Bug reports ve security issues

**İletişim:**
- GitHub Issues: https://github.com/Neudzulab/myeoffice
- Security: security@myeoffice.com
