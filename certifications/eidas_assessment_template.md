# eIDAS Uygunluk Değerlendirme Raporu Şablonu

> **Not:** Bu şablon, Aunsorm platformu için eIDAS (EU 910/2014 ve 2024/1183) uygunluk değerlendirmelerini belgelemek üzere hazırlanmıştır. Bölümleri kendi değerlendirme kapsamınıza göre güncelleyin ve gereksiz alanları kaldırmayın; boş bırakmanız gerekiyorsa gerekçesini belirtin.

## 1. Meta Veri
- **Rapor Kimliği:** `EIDAS-YYYY-NNN`
- **Versiyon:** `v1.0-draft`
- **Hazırlayan:**
- **Onaylayan:**
- **Hazırlanma Tarihi:**
- **Yayın Tarihi:**
- **Hedef Hizmet(ler):**
- **Kalibrasyon Bağlamı:** (örn. `External Binding - Prod 2025H1`)
- **Gizlilik Sınıfı:** (örn. `Confidential`)

## 2. Yönetici Özeti
- Değerlendirmenin amacı
- Kapsam dahiline giren servisler
- Kilit bulgular ve yüksek seviyeli riskler
- Regülasyon referansları (EU 910/2014, EU 2024/1183 güncellemeleri)

## 3. Hizmet Tanımı
- Mimari özet (kalibrasyon bağlamı, PQC opsiyonları, KMS entegrasyonu)
- Kullanıcı etkileşim akışı (kimlik doğrulama, imzalama, doğrulama)
- Kritik bağımlılıklar ve dış servisler

## 4. eIDAS Gereksinim Eşlemesi
| eIDAS Maddesi | Kriter | Aunsorm Karşılığı | Durum | Kanıt Referansı |
| --- | --- | --- | --- | --- |
| Madde 24 (Güven Hizmet Sağlayıcısı Gereklilikleri) | Operasyonel güvenlik | `docs/security/operations.md` | ☐ Uyumluluk İncelemede | Kanıt seti ID |
| Madde 25 (Elektronik İmzalar) | Nitelikli imza kriterleri | `crates/x509` CPS | ☐ Uyumluluk İncelemede | Kanıt seti ID |
| Madde 30 (Elektronik Mühürler) | TSE uygunluğu | `crates/kms` entegrasyonları | ☐ Uyumluluk İncelemede | Kanıt seti ID |
| Madde 37 (Güvenlik ve bildirim) | Olay yönetimi prosedürü | `docs/security/incident_response.md` | ☐ Uyumluluk İncelemede | Kanıt seti ID |
| Madde 45 (Güvenliğe ilişkin gereklilikler) | Teknik kontroller | `crates/core` güvenlik mimarisi | ☐ Uyumluluk İncelemede | Kanıt seti ID |

> **İpucu:** Her satır için “Durum” alanını `✅ Uyumlu`, `⚠️ İyileştirme Gerekiyor` veya `🚧 İncelemede` olarak güncelleyin.

## 5. Blockchain Kayıt İzleme
- **Ledger Entegrasyonu:**
  - `fabric_anchor_ref`, `quorum_audit_ref` ve `travel_rule_bundle` alanları için son blok numaralarını ve hash değerlerini kaydedin.
  - Hyperledger Fabric ve Quorum kayıtları arasında `calibration_ref` uyumunu doğrulayın; uyuşmazlık varsa `retention_policy_mismatch` olaylarını belgeleyin.
- **Kayıt Yaşam Döngüsü:**
  - `mint`, `rotate`, `retire` işlemlerinin her biri için tetikleyen servis (örn. `AuditRelay`, `RetentionSync`) ve zaman damgasını not alın.
  - Her kayıt için Travel Rule veri paketinin (`TravelRuleBridge`) nasıl bağlandığını ve maskeleme stratejisini açıklayın.
- **Denetim Adımları:**
  - `tests/blockchain/integrity_cases.rs` sonuçlarını ekleyerek ledger bütünlüğü doğrulamasını özetleyin.
  - `docs/src/operations/blockchain-integration.md` runbook'unda listelenen operasyon kontrol adımlarının durumunu raporlayın.

## 6. Kontrol Doğrulama Detayları
- **Kriter Adı:**
  - Kontrol Açıklaması
  - Kullanılan Test Yöntemi (örn. belge inceleme, teknik test, röportaj)
  - Kanıt Özetleri
  - Sonuç ve değerlendirme
- Kontroller arasında eIDAS Seviye 2 (Signatures) ve Seviye 3 (Qualified Signature) ayrımını belirtin.

## 7. Varlık ve Kanıt Envanteri
| Kanıt ID | Tür | Kaynak | Saklama Konumu | Hash/Checksum | İnceleme Tarihi |
| --- | --- | --- | --- | --- | --- |
| E-001 | Politika Belgesi | `docs/policies/` | Git Commit `abc1234` | SHA256(...) | 2024-05-12 |
| E-002 | Test Raporu | `tests/certifications/` | Artefakt ID | SHA256(...) | 2024-05-12 |

## 8. Risk ve Düzeltici Faaliyet Planı
| Risk ID | Kategori | Tanım | Etki | Olasılık | Öncelik | Düzeltici Faaliyet | Sorumlu | Hedef Tarih | Durum |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |

## 9. İzleme ve Yeniden Değerlendirme
- Periyodik takip planı (örn. yıllık, yarı yıllık)
- Denetim planındaki mil taşları
- Sürekli izleme metrikleri (telemetri, oturum istatistikleri, PQC testleri)

## 10. Ekler
- **Ek A:** Test senaryoları ve sonuç özetleri
- **Ek B:** Politika ve prosedür referans listesi
- **Ek C:** Yetkilendirme matrisleri
- **Ek D:** Terminoloji ve kısaltmalar

---

**İmza Bölümü**
- Operasyon Direktörü
- Güvenlik ve Uyumluluk Lideri
- Dış Denetçi (varsa)
