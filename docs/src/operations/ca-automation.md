# Certificate Authority İmzalama Otomasyonu Yol Haritası

Bu revizyon, `aunsorm-x509` bileşeninin kök ve ara sertifika
üretimini otomatikleştirmek için gereken adımları tanımlar. Amaç,
EXTERNAL kalibrasyon bağlamı zorunluluğunu koruyarak çevrimiçi ve
çevrimdışı iş akışlarında tekrarlanabilir, denetlenebilir bir CA
pipeline'ı oluşturmaktır.

## Güncel Uygulama Durumu

- `aunsorm-cli x509 ca init` komutu YAML/JSON profilini doğrular,
  deterministik seri numarası ve anahtar kimliğini raporlayarak kök CA
  sertifikası üretir. Opsiyonel olarak CA paketini (`CaBundle`) JSON
  olarak günceller.
- Profil tanımı içerisindeki `org_salt` değeri en az 8 baytlık Base64
  verisine karşılık gelmelidir; CLI ve kitaplık bu koşulu doğrular.
- `aunsorm-cli x509 ca issue` komutu tanımlı ara profili seçerek ilgili
  issuer anahtarı ile imza atar, kalibrasyon kimliğini ve seri numarasını
  özet olarak çıktılar ve mevcut CA paketine ara sertifikayı ekler.
- `aunsorm-x509` kitaplığı `CaAutomationProfile`, `CaBundle` ve
  `IntermediateCaParams` veri modellerini sunarak CLI dışındaki
  bileşenlere aynı otomasyon altyapısını kullanma imkânı sağlar.

## 1. Mimari Prensipler

- **Deterministik Üretim:** Tüm sertifika talepleri (CSR) ve imza
  çıktıları deterministik seri numarası ve kalibrasyon uzantıları ile
  üretilmelidir. `aunsorm-id` tabanlı ID üretimi, kök ve ara sertifika
  kimliklerinin çatallanmasını engellemek için kullanılacaktır.
- **EXTERNAL Kalibrasyon:** Her imza isteği, org-salt + metin bağlamını
  zorunlu kılan `CalibrationBinding` veri yapısı ile eşlenir. Otomasyon
  sırasında kalibrasyon metni `.calib` dosyasında saklanacak ve CLI ile
  uyumlu JSON raporları üretilecektir.
- **Yetki Ayrımı:** Kök sertifika imzalama anahtarı çevrimdışı HSM üzerinde
  tutulurken ara sertifika otomasyonu çevrimiçi `kms-pkcs11` veya `kms-gcp`
  bağlayıcıları ile yürütülecektir. Kök imza adımları manuel onay gerektirir.
- **Audit ve Transcript Hash:** Her adım `TranscriptHash` ile loglanacak,
  böylece CLI ve sunucu bileşenleri aynı denetim zincirini paylaşacaktır.

## 2. CLI ve Kitaplık Genişletmeleri

1. `aunsorm-cli x509 ca init` — yeni bir kök CA profili oluşturur,
   kalibrasyon metnini doğrular, deterministik seri numarası ve key-id
   bilgilerini JSON olarak yazdırır.
2. `aunsorm-cli x509 ca issue` — ara sertifikalar için sertifika isteğini
   okur, `--profile` seçeneği ile uygun imza politikasını seçer ve ilgili
   KMS sağlayıcısı üzerinden imzayı tamamlar.
3. `aunsorm-cli x509 ca rotate` — planlı sertifika yenilemeleri için
   otomatik hatırlatıcı ve geçiş penceresi hesaplayıcısı.
4. `aunsorm-cli x509 ca publish` — imzalanan sertifikaları JWKS benzeri bir
   JSON yayın formatında `aunsorm-server` bileşenine aktarır.

Kitaplık tarafında `aunsorm-x509`:

- `CaAutomationProfile` veri modeli: CPS/CP URI'ları, kalibrasyon metni,
  politika OID eşlemeleri ve geçerlilik pencerelerini içerir.
- `CaSigningBackend` trait'i: Offline (`FileKey`), `kms-pkcs11`, `kms-gcp`
  ve `kms-azure` uygulamaları; strict kipte fallback reddi.
- `CaBundle` yapısı: kök + ara zinciri, revocation metadata ve
  `TranscriptHash` özetlerini taşır.

## 3. Pipeline Adımları

1. **Profil Tanımı:** YAML/JSON profil dosyası mdBook'taki örnek ile uyumlu
   olacak. CLI `ca init` komutu bu profili doğrular.
2. **Anahtar Hazırlığı:**
   - Kök: Çevrimdışı ortamda (Ed25519 varsayılan, RSA 2048/4096 opsiyonlu)
     üretilir, `zeroize` ile bellek temizliği sağlanır, imza sadece onaylı
     oturumlarda yapılır.
   - Ara: Seçilen KMS sağlayıcısında `Ed25519` anahtar çifti oluşturulur;
     `aunsorm-kms` API'leri ile kimlik doğrulaması yapılır.
3. **CSR Oluşturma:** `aunsorm-x509` `CaAutomationProfile` kullanarak CSR
   üretir ve EXTERNAL kalibrasyon uzantılarını gömülü olarak dahil eder.
4. **İmza ve Yayım:**
   - Kök imzalar: `ca init` çıktısındaki `pending_requests/` klasöründe
     sıraya alınır, manuel onay sonrası `signed/` klasörüne taşınır.
   - Ara imzalar: `ca issue` komutu KMS üzerinden imzayı tamamlar ve
     `CaBundle` dosyası oluşturur.
   - Yayım: `ca publish` çıktıları JSON + PEM formatında `dist/` dizinine
     yazılır; `aunsorm-server` başlangıçta bu dizini okuyacaktır.
5. **Denetim Logları:** Tüm adımlar `audit/` klasöründe append-only JSON
   logları üretir. `TranscriptHash` değerleri CLI ile doğrulanabilir.

## 4. Test ve Doğrulama

- **Birim Testleri:** `CaAutomationProfile` doğrulama kuralları, kalibrasyon
  metni kontrolü ve `CaSigningBackend` hata yolları için kapsamlı testler.
- **Entegrasyon Testleri:**
  - `tests/x509_ca_roundtrip.rs`: kök + ara üretimi, sertifika zinciri
    doğrulaması ve kalibrasyon uzantılarının doğrulanması.
  - `tests/cli_ca_workflow.rs`: CLI komutlarının uçtan uca doğrulaması için
    fixture tabanlı testler.
- **Soak/Senaryo Testleri:**
  - `cargo test -p aunsorm-tests -- --ignored x509_ca_rotation_soak`
    komutu, rotasyon planlarının sürekliliğini doğrular.
  - `cargo fuzz run fuzz_x509_ca_profile` hedefi, profil ayrıştırıcılarını
    beklenmeyen girişlere karşı zorlar.

## 5. Zamanlama ve İş Paketleri

1. **Hazırlık (1 sprint):** Profil şeması, dokümantasyon örnekleri ve CLI
   sözleşmelerinin finalize edilmesi.
2. **Kitaplık ve CLI Uygulaması (2 sprint):** `aunsorm-x509` içindeki trait
   ve veri modellerinin eklenmesi, CLI akışlarının geliştirilmesi.
3. **KMS Entegrasyonu (1 sprint):** `kms-*` özellikleri için backend
   uygulamaları ve canlı test harness'inin güncellenmesi.
4. **Test/Fuzz Entegrasyonu (1 sprint):** Yeni testlerin ve fuzz hedefinin
   CI pipeline'ına bağlanması.
5. **Yayın & Belgeler (yarım sprint):** mdBook güncellemeleri, `README`
   ve `CHANGELOG` maddelerinin finalize edilmesi.

Bu plan tamamlandığında Sprint 2 altında listelenen revizyon
kapsamı kapatılabilir ve `aunsorm-x509` için CA otomasyon süreci
üretim dağıtımına hazır hale getirilecektir.
