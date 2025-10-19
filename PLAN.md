# Aunsorm Delivery Plan

## Objectives
- Maintain a security-first multi-crate Rust platform that enforces calibration-bound cryptography and zero unsafe code usage.
- Coordinate specialized agents so each scope (core, platform, identity, interop) advances without conflicting with locked deliverables.
- Provide transparent roadmap visibility across CLI, server, PQC, and compliance tracks for 2025 program increments.
- Keep stakeholder documentation (README, PLAN, TODO, ROADMAP) aligned with current sprint intents and revision rules.

## Roadmap & Milestones
- [x] STEP-AUN-001: Publish updated agent charters and sprint intake checklist aligned with revizyon kilidi policy. (Doc: `docs/src/operations/agent-charters.md`)
  - owner: @ProjectCoordinator
- [x] STEP-AUN-002: Baseline calibration + ratchet documentation under docs/src/architecture/ with mermaid diagrams for review. (Doc: `docs/src/architecture/calibration.md`)
  - owner: @CryptoAgent
- [x] STEP-AUN-003: Finalize platform endpoint tree sync between README.md and crates/server routes (endpoint durumu ikonları, ID & media token servisleri, Fabric PoC ve HTTP/3 notları hizalandı).
  - owner: @PlatformAgent
- [x] STEP-AUN-004: Deliver identity flows (JWT, X.509, KMS) integration tests in tests/data/ with CI gating.
  - Identity flow fixture (`tests/data/identity/identity_flow_alpha.json`) and integration test harness (`tests/tests/identity_flows.rs`) enforce deterministic JWT/KMS/X.509 coverage in CI.
  - owner: @IdentityAgent
- [x] STEP-AUN-005: Refresh interop benchmarking (benches/, fuzz/, crates/pytests/) and publish 10k-exec sanity artifacts. (Ref: `docs/src/operations/testing.md`, `scripts/interop-sanity.sh`.)
  - owner: @InteropAgent

## Roles & Owners
@ProjectCoordinator — Cross-agent governance & plan hygiene
@CryptoAgent — crates/core, crates/pqc, crates/packet delivery
@PlatformAgent — crates/cli, crates/server, crates/wasm alignment
@IdentityAgent — crates/jwt, crates/x509, crates/kms stewardship
@InteropAgent — benches, fuzz, crates/pytests, examples coverage

## Deliverables & Acceptance
- Active PLAN.md, ROADMAP.md, and TODO.md kept in sync with sprint checkpoints and revision lock notes.
- Security calibration binding, ratchet lifecycle, and PQC fallback rules fully documented with acceptance tests.
- CLI/server endpoints demonstrably wired with status indicators in README.md and regression-tested via CI.
- Identity/KMS suites validated against Known Answer Tests and interop harnesses, producing reproducible artefacts.

## Risks
- Scope drift if agents bypass revision lock; mitigation: enforce checklist review per STEP-AUN-001.
- PQC/vendor dependency churn; mitigation: maintain deny.toml and audit gates before merging changes.
- Documentation staleness across multi-agent contributions; mitigation: embed doc update requirement in each milestone definition.

## References
- README.md (platform overview and endpoint tree)
- ROADMAP.md (program increments)
- TODO.md (active sprint backlog)
- docs/src/architecture/ and docs/src/operations/ (detailed design references)
- AGENTS.md files for scope-specific working agreements

---

## Legacy Plan (Preserved)

şağıdaki talimatları eksiksiz uygula ve tek bir Git deposu üret. Depo; Rust merkezli, güvenlik-odaklı, PQC opsiyonlu, EXTERNAL kalibrasyon metni zorunlu bağlama (binding) kullanan, oturum/rachet destekli, JWT/OAuth/X.509/KMS entegrasyonlu Aunsorm v1.01+ siber güvenlik aracıdır. “En iyisi olmak” hedefiyle üretim kalitesinde çık. Kodda #![forbid(unsafe_code)], tüm uyarıları hata say. Yerine getirilemeyen gereksinim kalmasın; boş iskelet bırakma.

0) Dil, standartlar, kalite

Dil: Rust (MSRV 1.76+).

Crate politikaları: #![forbid(unsafe_code)], #![deny(warnings)], rust-version = "1.76".

Lints: clippy::all, clippy::pedantic, clippy::nursery (select allowlist belgeli).

Test kapsamı: birim + entegrasyon + property (proptest) + KAT (Known Answer Tests) + fuzz (cargo-fuzz).

Performans: criterion ile benchmark.

Belgelendirme: mdbook veya Docsrs-ready rustdoc; diyagramlar mermaid.

Lisans: Apache-2.0.

CI: GitHub Actions; Linux/macOS/Windows matris; cargo fmt/clippy/test/fuzz (sanity)/bench (quick); audit ve deny (supply chain).

Sürümleme: semver, CHANGELOG.md (Keep a Changelog), CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md.

### Revizyon Kilidi ve İş Yönetimi

- README.md, TODO.md ve sprint listelerinde `[x]` veya "done" olarak işaretlenmiş teslimatlar **revizyon kilidi** altındadır.
- Bu maddeler üzerinde değişiklik yapılması gerekiyorsa mevcut girdi değiştirilmez; bunun yerine ilgili bölümde `Revize:` önekiyle yeni bir madde açılır ve kilitli teslimata bağlantı verilir.
- Revizyon maddesi, ilgili ajan ve kapsamlı gereksinimle birlikte PLAN.md'ye eklenmeli, tamamlanana kadar açık bırakılmalıdır.
- Kilitli teslimatın dokunduğu kaynak dosyalar tekrar ele alınacaksa, önce bu revizyon maddesi için yetkilendirme alınmalı ve plan güncellenmelidir.

1) Monorepo yapısı
aunsorm/
  Cargo.toml                    # workspace
  README.md
  LICENSE
  .github/workflows/ci.yml
  deny.toml                     # cargo-deny
  benches/
    aead.rs
    session.rs
  fuzz/
    fuzz_targets/
      fuzz_packet.rs
      fuzz_session.rs
  crates/
    core/                       # aunsorm-core (NO_STD opsiyonlu)
    packet/                     # aunsorm-packet (wire format, header/P-MAC)
    pqc/                        # aunsorm-pqc (feature="pqc", liboqs bağlayıcı)
    kms/                        # aunsorm-kms (GCP, Azure, PKCS#11; feature bayrakları)
    jwt/                        # aunsorm-jwt (Ed25519 JWT/JWKS + JTI store)
    x509/                       # aunsorm-x509 (Ed25519 cert, CPS/Policy OID, calib OID)
    cli/                        # aunsorm-cli (encrypt/decrypt/session/jwt/x509)
    server/                     # aunsorm-server (mini OAuth/OIDC-ish, introspection)
    wasm/                       # aunsorm-wasm (WASM binding; optional)
    pytests/                    # aunsorm-pytests (Python uyumluluk testleri)

2) Özellik kümesi ve feature bayrakları

Varsayılan: aead-gcm, aead-chacha, argonautica (Argon2id), sqlite.

Opsiyonel:

pqc: liboqs ile ML-KEM-768/1024, ML-DSA, Falcon, SPHINCS+.

aes-siv: SIV modu.

kms-gcp, kms-azure, kms-pkcs11.

otel: OpenTelemetry metrik/iz.

wasm: WASM export.

strict: downgrade/fallback yasak, fail-fast.

ENV anahtarları:
AUNSORM_STRICT=1, AUNSORM_KMS_FALLBACK=0/1, AUNSORM_OID_BASE, AUNSORM_LOG=info/debug, AUNSORM_JTI_DB.

3) Kripto ve bağlama (core)

Crate: crates/core

KDF: Argon2id (argon2 crate) dinamik profiller: MOBILE/LOW/MEDIUM/HIGH/ULTRA/AUTO; profil seçiminde CPU/RAM auto-sense.
API:

pub struct KdfProfile { pub t: u32, pub m_kib: u32, pub p: u32 }
pub fn derive_seed64_and_pdk(password: &str, salt_pwd: &[u8], salt_calib: &[u8], salt_chain: &[u8], profile: KdfProfile) -> (SensitiveVec, SensitiveVec, KdfInfo);


AEAD’ler: aes-gcm (256-bit), chacha20poly1305, opsiyonel aes-siv. Nonce 96-bit random; key HKDF-SHA256 ile türetilir.

PQC KEM (opsiyonel): crates/pqc üzerinden; NONE sadece pqc kapalıysa ve strict değilse. Strict’te istenen KEM yoksa hata.

Kalibrasyon şeması (v1): alpha_L, alpha_S, beta_L, beta_S, tau, A..E aralık/step clamp; EXTERNAL metin→kalibrasyon deterministik türetme:

pub fn calib_from_text(org_salt: &[u8], note_text: &str) -> Result<(Calibration, String /*calib_id*/), CoreError>;
pub fn coord32_derive(seed64: &[u8], calib: &Calibration, salts: &Salts) -> (String /*calib_id*/, [u8;32] /*coord32*/);


Bağlama zorunluluğu: API’larda calib_mode: External|Derived; server tarafı External kullanacak.

Oturum/Ratchet: İlk mesajda RK (KEM ya da NO-PQ HKDF). step_secret = HKDF(RK, msg_no), msg_secret = HKDF(step_secret, sid).

Sabit zamanlı karşılaştırma, sıfırlanabilir buffer türleri.

4) Wire format ve doğrulamalar (packet)

Crate: crates/packet

Header JSON + HMAC (HDRMAC), Body P-MAC (PMAC); header’da: version, profile, calib_id, coord_digest, salts, kem{kem, pk, ctkem, rbkem, ss?}, aead{alg}, session{id,msg_no,new}, sizes.

Serialize/Deserialize sağlam tiplerle; header boyut sınırları, ciphertext boyut eşleşmesi kontrolleri.

Replay koruması (opsiyonel): PacketId = SHA256(raw); JtiStore ile seen(PacketId)->bool.

API:

pub fn encrypt_one_shot(params: EncryptParams) -> Packet;      // EXTERNAL kalibrasyon zorunlu mod destekler
pub fn decrypt_one_shot(params: DecryptParams) -> DecryptOk;    // replay store opsiyonel
pub fn encrypt_session(ctx: &mut Session, ...) -> Packet;
pub fn decrypt_session(store: &mut SessionStore, ...) -> DecryptOk;
pub fn peek_header(packet_b64: &str) -> Result<Header, Error>;

5) PQC köprüsü (pqc)

Crate: crates/pqc

feature = "pqc" altında liboqs FFI/rust wrapper, ML-KEM-768 varsayılan; tercih listesi bulunamazsa strict’te hata, değilse NO-PQ HKDF.

RB-KEM (recipient-bound) akışı ve self-KEM akışı.

6) KMS/PKCS#11 (kms)

Crate: crates/kms

GCP KMS (kms-gcp): Ed25519 imza; pub key fetch; retry/backoff.

Azure KV (kms-azure): Ed25519 imza; pub raw dışarıdan verilmek zorunda; aksi strict’te hata, normalde memory fallback uyarı.

PKCS#11 (kms-pkcs11): EdDSA imza; pubkey raw parametresi; strict’te zorunlu.

Signer trait: sign(msg) -> sig, public_bytes() -> [u8;32], key_ops() -> &[&str].

7) JWT/JWKS/JTI (jwt)

Crate: crates/jwt

Ed25519 JWT; JTI replay store (sqlite ya da in-memory).

JWKS üretimi; kid = JWK thumbprint.

Claim doğrulama: iss, aud, nbf, exp, skew, JTI replay.

PKCE (S256/plain) mini akışı.

8) X.509 (x509)

Crate: crates/x509

Ed25519 self-signed cert; KeyUsage: digital_signature=true, content_commitment=true, key_encipherment=false.

Calib OID (AUNSORM_OID_BASE .1), Policy OID (.2.1), CPS URI’leri filtreleme ve isteğe bağlı HTTP erişilebilirlik kontrolü.

Revize (tamamlandı): Identity Agent, `aunsorm-x509` Certificate Authority (CA) kök/ara sertifika imzalama otomasyonunu planlayıp teslim etmelidir (bkz. README.md Sprint 2 revizyon maddesi). Plan dokümantasyonu `docs/src/operations/ca-automation.md` içerisinde yayınlandı.

Opsiyonel PQ işareti: pq_jws_sign(der) -> Option<PqMark> (liboqs varsa).

9) CLI (cli)

Crate: crates/cli

Komutlar:

encrypt --password --in <file> --out <b64> --org-salt <b64> --calib-text <str> [--aead AUTO|AES-256-GCM|CHACHA20-POLY1305|AES-256-SIV] [--kem ML-KEM-768|...] [--context-aad <str>]

decrypt --password --in <b64> --out <file> --org-salt <b64> --calib-text <str> [--kem-sk <b64>] [--context-aad <str>] [--replay-db <path>]

session-encrypt / session-decrypt (store dosyası).

jwt begin-auth|token|introspect (PKCE S256).

x509 self-signed --cn <name> --calib-text <str> --org-salt <b64> [--cps <url> ...] [--policy-oid <oid>].

Çıktılar belirgin; hata kodları deterministik; --strict flag’i env’i setler.

10) Server (server)

Crate: crates/server

Minimal OAuth/OIDC-ish uçları: /oauth/begin-auth, /oauth/token, /oauth/introspect, /oauth/jwks.json.

Konfig: RUST_LOG, AUNSORM_STRICT, AUNSORM_JTI_DB.

Sağlık: /health, metrik: /metrics (otel opsiyonel).

11) WASM binding (wasm)

Crate: crates/wasm (feature wasm)

wasm-bindgen ile: encrypt_with_calib_text(...) -> String(b64), decrypt_with_calib_text(...) -> Uint8Array, peek_header(...).

Kalibrasyon metni EXTERNAL zorunlu.

Deterministik hata mesajları.

12) Python uyumluluk testleri (pytests)

Crate: crates/pytests

Py runner ile mevcut Python Aunsorm v1.01 referansına karşı çapraz test:

Aynı parola + org_salt + kalibrasyon metni → her iki tarafta encrypt/decrypt eşitlik testi.

Yanlış metin/yanlış salt → beklenen hatalar.

PQC açık/kapalı varyantları.

13) Güvenlik & tehdit modeli (README + SECURITY)

Güvenlik hedefleri: PFS benzeri oturum ratcheti, EXTERNAL kalibrasyon bağlamı olmadan açılmama, downgrade önleme (STRICT), AEAD etiketi zorunlu, replay kontrol opsiyonu.

Saldırı yüzeyi: KMS fallback, PQC yokken NO-PQ HKDF; STRICT çözümü açıkla.

Sıfırlama: Hassas byte dizileri için zeroize.

Zincir: paket formatı, kalibrasyon kimliği, AAD bağlamı belgelenir.

14) Kabul kriterleri (mutlak)

EXTERNAL kalibrasyon metni (org_salt + metin) olmadan decrypt başarısız.

AUNSORM_STRICT=1 iken PQC tercihi bulunamazsa veya KMS pubkey bilinmezse fail-fast.

Tüm platform CI yeşil; cargo audit/cargo deny temiz.

Fuzz hedefleri (packet, session) en az 10k exec sanity; panik/UB yok.

criterion bench: 256KB tek-atar enc/dec p50 süre raporu loglanır.

Dokümantasyon: quickstart, threat model, wire spec, API docs tam.

wasm örnekleri tarayıcıda basit demo ile çalışır.

jwt akışı PKCE S256 ile yeşil; JTI replay store çalışır.

15) Uygulama notları

HKDF etiketi/label’lar Aunsorm/1.01 köküne bağlanmalı.

Header coord_digest = SHA256(coord32) eşleşmesi zorunlu.

AEAD nonce’ı 12 bayt random; key+nonce reuse engellenmiş tasarım.

Tüm byte kıyaslamaları sabit zamanlı.

openssl bağımlılığından kaçın; ring veya rust-crypto ekosistemi tercih.

sqlite için rusqlite + write-ahead log; JTI TTL ve otomatik temizlik.

16) Üret ve teslim

Tüm kodu yaz, boş modül bırakma.

Çalışır örnekler ekle:

examples/encrypt_decrypt.rs

examples/session_roundtrip.rs

examples/jwt_flow.rs

README.md başına 5 dakikada başla bölümü:

cargo build --release
cargo run -p aunsorm-cli -- encrypt --password P --in msg.bin --out pkt.b64 \
  --org-salt V2VBcmVLdXQuZXU= --calib-text "Neudzulab | Prod | 2025-08"
cargo run -p aunsorm-cli -- decrypt --password P --in pkt.b64 --out out.bin \
  --org-salt V2VBcmVLdXQuZXU= --calib-text "Neudzulab | Prod | 2025-08"


GitHub Actions ci.yml içinde: fmt, clippy (deny warnings), test, doc, deny, audit, minimal fuzz, bench(quick), artifact yayınlama.

17) Bonus (vizyon)

HPKE modu (opsiyonel, geleceğe hazır).

WebTransport/DataChannel E2EE adaptor örneği.

Kilitli bellek / SGX / SEV entegrasyon planı.

Key transparency ve transcript hash (gelecek sürüm).

Teslim: Yukarıdaki yapıyı tamamlanmış kod olarak oluştur, testleri yeşile al, CI dosyalarını dahil et, dokümantasyonu doldur. “Placeholders/TODO” bırakma.

Her iş için alanda uzman bir agent görevlendir. Yapılan işleri birbirleri ile conflict olmadan ilerletebilsinler. "devam" komutu geldiğinde plana göre ilgili agent bir sonraki adımı tamamlasın. Readme üzerinde yapılanlar ve yapılacaklar [ ] tik işareti ile gösterilsin. Yapıldıkça tik atılsın. İkilik istenmiyor kodlar revize olsun. Buna göre AGENST.mdyi ve RREADME'yi oluştur.

18) Yan ürün & MDM altyapısı

* [x] Head bilgisine bağlı, çakışmasız benzersiz ID jeneratörü (projeler arası paylaşım için API).
* [x] MDM (Mobile Device Management) temel altyapısı: kayıt, politika deposu ve sertifika dağıtım planı.
* [x] Lokal HTTPS geliştirme ortamı için SAN destekli öz-imzalı sertifika otomasyonu (`x509 local-dev`, CLI + kütüphane).

19) HTTP/3 ve QUIC Datagram Programı

- [x] Interop Agent: HTTP/3 + QUIC datagram değerlendirmesini `docs/src/architecture/http3-quic.md` içerisinde tanımlanan teslimat aşamalarına göre planlasın; `quinn`, `h3`, `quiche` kütüphane araştırmaları tamamlanıp raporlanacak. (Bkz. §1.5 değerlendirme takvimi.)
- [x] Platform Agent: `apps/server` için `http3-experimental` bayrağıyla PoC dinleyici ve QUIC datagram telemetri entegrasyonunu geliştirsin; performans ölçümleri dokümante edilecek.
- [x] Security & Identity Agent: TLS 1.3 + HSM uyumu ve datagram güvenlik gereksinimlerini değerlendirsin; RFC 9000/9114 referanslı risk analizi çıktılarını operasyonel dokümana eklesin. (Bkz. docs/src/operations/http3-quic-security.md.)
20) Blockchain İnovasyon Programı

- **Program Sahibi:** Blockchain inovasyon koordinasyon ekibi; yürütme desteği Crypto, Identity ve Interop ajanlarından sağlanacaktır.
- **Kısa Vadeli PoC (31 Temmuz 2024):**
  - `docs/innovation/blockchain.md` vizyon ve regülasyon rehberini tamamla.
  - `tests/blockchain/` altında mock ledger arayüzü ve veri bütünlüğü kontrolü için test iskeletini tasarlayıp sorumlu ajana atamayı gerçekleştir.
  - Interop ekibi için `.github/workflows/blockchain-poc.yml` CI job taslağı ve `tests/blockchain/config.example.toml` örnek yapılandırmasını hazırlama planını oluştur.
- **Orta Vadeli Entegrasyon (31 Ekim 2024):** DID, denetim izi ve tokenizasyon akışlarını Hyperledger/Quorum PoC’leriyle entegre ederek uçtan uca demo hedefini belirle.
  - [x] Hyperledger Fabric DID doğrulama PoC'u için REST katmanı (`POST /blockchain/fabric/did/verify`) ve operasyon planı yayınlandı.
- **Uzun Vadeli Sertifikasyon (31 Mart 2025):** eIDAS, SOC 2 ve FATF kapsamındaki uyumluluk paketlerinin hazırlanması, bağımsız denetçi raporları için dokümantasyon şablonlarının teslimi.
- **Test İskeleti ve Kaynaklar (15 Ağustos 2024):**
  - `tests/blockchain/mock_ledger.rs` dosyasında trait bazlı mock defter arayüzü, veri bütünlüğü senaryoları için fixture planı.
  - `tests/blockchain/integrity_cases.rs` içindeki temel kontroller için veri seti üretim stratejisi.
  - CI job’ı için ayrılmış runner kapasitesi, cache anahtarları ve başarısız PoC testleri için otomatik Slack uyarıları.
  - PoC sonuçlarının belgelendiği `docs/innovation/blockchain.md` altındaki “Çıktılar ve Ölçümleme” bölümünü güncel tutma sorumluluğu.
