# Blockchain İnovasyon Programı

*Revizyon: 2025-10-24*

## Vizyon ve Stratejik Amaçlar
- **Şeffaflık ve Denetlenebilirlik:** Aunsorm güven zincirini kamu veya özel blokzincirlere çapalayarak sertifika ve anahtar işlemlerinin denetlenebilirliğini artırmak.
- **Uyumluluk ve Regülasyon:** eIDAS, SOC 2 ve FATF gibi düzenlemelere uyumlu kalırken, verinin saklanması ve işlenmesinde gizlilik gerekliliklerini korumak.
- **Çoklu Ağ Desteği:** Hyperledger Fabric/Quorum gibi izinli ağlar ile seçilmiş kamu ağları arasında taşınabilir bir soyutlama sağlamak.
- **Geleceğe Hazırlık:** DID ve tokenizasyon senaryoları için modüler API katmanı hazırlayarak müşteri ihtiyaçlarına hızlı cevap vermek.

## Regülasyon ve Uyumluluk Rehberi
- **Veri Egemenliği:** Blokzincire yazılan her kayıt, GDPR ve KVKK kapsamında kişisel veriden arındırılmalı veya hash/taahhüt formunda tutulmalıdır. Zincire gönderilen veriler `privacy-preserving` taahhütler olarak tasarlanacak.
- **Kimlik Doğrulama:** Zincir üzerinde tutulan işlemlere erişim, kurumsal IAM (Aunsorm-ID + JWT) ile bağlanacak ve tüm çağrılar denetlenebilir şekilde loglanacaktır.
- **Anahtar Yönetimi:** Ledger imzaları `aunsorm-kms` aracılığıyla HSM destekli anahtarlarla yapılacak; anahtar rotasyonu SOC 2 gereksinimlerine göre üç ayda bir doğrulanacak.
- **Uyum Kontrolleri:** Her sprint sonunda regülasyon kontrol listesi (`docs/src/operations/compliance-checklist.md`) güncellenecek ve Blockchain programındaki değişiklikler ile çapraz referanslanacaktır.

## Teslimat Yol Haritası

### Kısa Vadeli PoC (31 Temmuz 2024)
- [x] `docs/src/innovation/blockchain.md` vizyon ve regülasyon rehberi yayımlandı (bu doküman).
- [x] `tests/blockchain/` altında trait tabanlı mock ledger arayüzü ve veri bütünlüğü kontrol senaryoları hazırlandı.
- [x] `.github/workflows/blockchain-poc.yml` CI iş akışı taslağı ve `tests/blockchain/config.example.toml` örnek yapılandırması oluşturuldu.

### Orta Vadeli Entegrasyon (31 Ekim 2024)
- [x] DID (Decentralized Identifier) doğrulama akışını Hyperledger Fabric PoC'leri ile entegre et; `apps/server` içinde REST katmanı taslağı çıkar (`POST /blockchain/fabric/did/verify`).
- [x] Quorum tabanlı audit trail senaryosu için tokenizasyon ve yetki devri politikalarını belgeleyerek `docs/src/operations/blockchain-integration.md` dosyasına ekle.
  - GoQuorum 23.x üzerinde Istanbul BFT konsensüsü, `AuditAsset` soulbound token modeli ve `TOKENIZE_AUDIT` yetkilendirme politikaları ayrıntılandırıldı.
  - SOC 2/eIDAS raporlama gereksinimlerine yönelik mil taşları (2024-11-15 ila 2025-03-01) ve `AuditRelay` köprüleme servisi sorumlulukları tanımlandı.
- [x] Interop ekibi için zincirler arası test harness'ini `tests/blockchain/cross_network.rs` altında planla ve veri seti gereksinimlerini tanımla.
  - `fabric-devnet → quorum-istanbul` ve `quorum-istanbul → ethereum-sepolia` senaryoları için ağ profilleri, köprüleme modelleri ve finalite hedefleri kod seviyesinde kataloglandı.
  - Fixture gereksinimleri (`tests/data/blockchain/`) Travel Rule, AML ve hash kilitleme kontrollerini doğrulayacak alan setleriyle belirlendi; regresyon testleri veri kayıt sayısını ve zorunlu alanları doğrular.

### Uzun Vadeli Sertifikasyon (31 Mart 2025)
- [ ] eIDAS ve SOC 2 için blokzincir kayıt süreçlerinin bağımsız denetim raporlarını üret ve `certifications/` altında paylaşılacak şablonları tanımla.
- [x] FATF Travel Rule uyumluluğu için zincir üstü işlem izleme ve raporlama entegrasyonlarını değerlendir.
  - Travel Rule veri eşlemesi, TravelRuleBridge mimarisi ve raporlama mil taşları [`docs/src/operations/blockchain-integration.md`](../operations/blockchain-integration.md#fatf-travel-rule-entegrasyon-stratejisi) bölümünde planlandı.
- [ ] Müşteri başına saklama politikaları ve anahtar silme prosedürleri için denetim izlerini Blockchain katmanıyla ilişkilendir.

## Test Kaynakları ve Operasyonel Artefaktlar
- **Mock Ledger:** `tests/blockchain/mock_ledger.rs` dosyası testler için deterministik bir blokzincir arayüzü sunar.
- **Bütünlük Senaryoları:** `tests/blockchain/integrity_cases.rs` tipik saldırı/bozulma durumlarını kodlar ve PoC testlerinin tekrar üretilebilir olmasını sağlar.
- **Konfigürasyon:** `tests/blockchain/config.example.toml` manuel veya CI tetiklemeleri için örnek ağ yapılandırmasını içerir.
- **CI Pipeline:** `.github/workflows/blockchain-poc.yml` opsiyonel olarak PoC testlerini çalıştırır ve `BLOCKCHAIN_POC_ENABLED` bayrağı ile devreye alınır.

## Riskler ve Açık Sorular
- **Performans:** Zincire yazma gecikmeleri yüksek olabilir; PoC aşamasında `batching` ve `async commit` stratejileri ölçülecek.
- **Gizlilik:** Hash/taahhüt verilerinin geri mühendisliğe açık olmaması için ek `salt` ve `pepper` stratejileri değerlendirilecek.
- **Standartlar:** DID/VC ekosistemindeki hızlı değişiklikler izlenerek Aunsorm sürümleriyle uyumlu geçiş planları hazırlanacak.

## Geri Bildirim Döngüsü
Müşteri veya ekip geri bildirimleri `ops/blockchain` etiketiyle Jira/Linear panolarına işlenecek. Her sprint sonunda bu doküman güncellenerek alınan geri bildirimlerin durumu (açık, çözülüyor, kapandı) raporlanacaktır.
