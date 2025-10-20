# SOC 2 Tip II Denetim Raporu Şablonu

> **Not:** Bu şablon AICPA Trust Services Criteria (Güvenlik, Erişilebilirlik, Gizlilik, İşleme Bütünlüğü, Mahremiyet) çerçevesine göre SOC 2 Tip II raporlarını yapılandırmak için hazırlanmıştır. Denetim dönemini, kapsamı ve kullanılan kontrol testlerini açıkça belirtin.

## 1. Rapor Özeti
- **Rapor Kimliği:** `SOC2-YYYY-NNN`
- **Versiyon:** `v1.0-draft`
- **Denetim Dönemi:** (örn. 01.01.2024 – 30.06.2024)
- **Hizmet Organizasyonu:**
- **Denetçi Kuruluş:**
- **İletişim Bilgileri:**
- **Kalibrasyon Bağlamı:** (örn. `External Binding - Prod 2025H1`)

## 2. Yönetici Özeti
- Denetimin amacı ve kapsamı
- Güçlü yönler
- Kritik bulgular ve iyileştirme önerileri
- Denetim kısıtları (scope dışı alanlar, varsayımlar)

## 3. Hizmet Organizasyonu Açıklaması
- Organizasyon yapısı ve sorumluluk matrisi
- Sistem bileşenleri (core crypto, KMS, packet, server)
- Operasyonel süreçler (CI/CD, olay yönetimi, erişim yönetimi)
- Üçüncü taraf bağımlılıklar

## 4. Trust Services Kriterleri Matrisleri

### 4.1 Güvenlik (Common Criteria, CC)
| Kriter | Açıklama | Aunsorm Kontrolü | Test Yöntemi | Durum | Kanıt |
| --- | --- | --- | --- | --- | --- |
| CC1.1 | Kontrol ortamı | `docs/governance/control_environment.md` | Politika inceleme | ☐ Değerlendirilecek | Kanıt ID |
| CC6.6 | Erişim kontrolü | `crates/server` RBAC | Yapılandırma incelemesi | ☐ Değerlendirilecek | Kanıt ID |
| CC7.2 | Değişiklik yönetimi | `docs/operations/change_management.md` | Süreç walkthrough | ☐ Değerlendirilecek | Kanıt ID |

### 4.2 Erişilebilirlik (A)
| Kriter | Açıklama | Aunsorm Kontrolü | Test Yöntemi | Durum | Kanıt |
| --- | --- | --- | --- | --- | --- |
| A1.2 | Kapasite planlama | `docs/operations/capacity_plan.md` | Kapasite raporu incelemesi | ☐ Değerlendirilecek | Kanıt ID |
| A1.3 | İzleme | `apps/server` telemetri | Log analizi | ☐ Değerlendirilecek | Kanıt ID |

### 4.3 Gizlilik (C)
| Kriter | Açıklama | Aunsorm Kontrolü | Test Yöntemi | Durum | Kanıt |
| --- | --- | --- | --- | --- | --- |
| C1.1 | Gizlilik bildirimi | `docs/policies/privacy_notice.md` | Politika doğrulaması | ☐ Değerlendirilecek | Kanıt ID |
| C1.2 | Veri sınıflandırma | `docs/policies/data_classification.md` | Süreç incelemesi | ☐ Değerlendirilecek | Kanıt ID |

### 4.4 İşleme Bütünlüğü (PI)
| Kriter | Açıklama | Aunsorm Kontrolü | Test Yöntemi | Durum | Kanıt |
| --- | --- | --- | --- | --- | --- |
| PI1.2 | Veri doğrulama | `tests/integration/` senaryoları | Test yürütme | ☐ Değerlendirilecek | Kanıt ID |
| PI1.4 | Hata işleme | `crates/packet` hata yönetimi | Kod incelemesi | ☐ Değerlendirilecek | Kanıt ID |

### 4.5 Mahremiyet (P)
| Kriter | Açıklama | Aunsorm Kontrolü | Test Yöntemi | Durum | Kanıt |
| --- | --- | --- | --- | --- | --- |
| P5.1 | Veri saklama ve silme | `docs/policies/data_retention.md` | Süreç doğrulaması | ☐ Değerlendirilecek | Kanıt ID |
| P6.3 | Olay bildirimi | `docs/security/incident_response.md` | Walkthrough | ☐ Değerlendirilecek | Kanıt ID |

> **İşaretleme Rehberi:** Durum alanını `✅ Uygun`, `⚠️ İyileştirme Gerekli`, `🚧 Denetimde` olarak güncelleyin. Kanıt kolonunda ilgili artefakt ID’sini veya depo referansını belirtin.

## 5. Blockchain Kayıt Süreçleri
- **Ledger Kapsamı:** Denetlenen dönemde kullanılan Hyperledger Fabric ve Quorum ağlarını, ilgili kanal/sözleşme adlarını ve erişim politikalarını belgeleyin.
- **Metaveri İzleme:** `AuditAssetRegistry` kayıtlarındaki `retention_policy`, `travel_rule_bundle` ve `calibration_ref` alanlarının nasıl üretildiğini ve doğrulandığını açıklayın.
- **İz Sürme:** `RetentionSync`, `AuditRelay` ve `TravelRuleBridge` servis log'larının nasıl toplandığını, hash'lendiğini ve `certifications/compliance_exports/` altında nasıl saklandığını belirtin.
- **Test Kanıtları:** `tests/blockchain/cross_network.rs` ve `tests/blockchain/integrity_cases.rs` sonuçlarını özetleyerek ledger bütünlüğü kontrollerini rapora ekleyin.

## 6. Kontrol Test Sonuçları
- Test adı, test edilen dönem, beklenen sonuç
- Uygulanan prosedürler (ör. örnekleme yöntemi, log analizi, yeniden yürütme)
- Elde edilen bulgular ve değerlendirme
- Bağlı risk seviyesi (Düşük/Orta/Yüksek)

## 7. İstisnalar ve Yönetim Yanıtları
| İstisna ID | Kriter | Bulgular | Etki | Yönetim Yanıtı | Düzeltici Aksiyon | Hedef Tarih | Durum |
| --- | --- | --- | --- | --- | --- | --- | --- |

## 8. Sürekli İzleme ve Gelişim
- Denetim sonrası takip mekanizmaları
- Otomatik kontroller (ör. telemetri uyarıları, CI kontrolleri)
- Gelecek denetimlere hazırlık aksiyonları

## 9. Ekler
- **Ek A:** Kanıt envanteri listesi ve imzaları
- **Ek B:** Denetim kapsamı dışında kalan bileşenler
- **Ek C:** Terimler sözlüğü
- **Ek D:** İlgili regülasyon ve standart referansları

---

**İmza Bölümü**
- Operasyon Direktörü
- Güvenlik ve Uyumluluk Lideri
- Bağımsız Denetçi
