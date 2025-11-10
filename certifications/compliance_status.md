# Compliance & Certification Readiness Matrix — 2025-02-17

Bu doküman, Aunsorm platformunun öncelikli regülasyon ve sertifikasyon
programlarına hazırlık durumunu özetler. Her başlık için denetim kapsamı,
uygulanan kontroller, kanıt kaynakları ve açık maddeler aşağıda
belirtilmiştir. Referanslar ilgili çerçeve ve standartların resmi
bölümlerine dayanmaktadır.

## SOC 2 Type II Audit Preparation
- **Çerçeve Referansı:** AICPA Trust Services Criteria (TSP 100) —
  Güvenlik (CC), Erişim Kontrolleri (CC6), Değişiklik Yönetimi (CC8) ve
  Sistem İşletimi (CC7).
- **Kontrol Durumu:**
  - `crates/server` dağıtımı için değişiklik yönetimi, `docs/src/operations/`
    altındaki runbook ve olay müdahale kılavuzlarıyla belgelendi.
  - Log saklama ve denetim izi gereksinimleri, `certifications/audit/`
    raporları ve `tests/blockchain/` regresyonlarıyla doğrulanıyor.
- **Kanıt Artefaktları:**
  - `docs/src/operations/incident-response-playbook.md`
  - `docs/src/operations/runbook-retention.md`
  - `certifications/audit/hsm_retention_audit.md`
- **Açık Maddeler:**
  - CI/CD pipeline değişikliklerinin `CHANGELOG.md` altında otomatik
    bağlantısının tamamlanması.
  - SOC 2 kanıt depo yapısı için `scripts/audit-export` otomasyonunun
    üretime alınması.

## GDPR Compliance Review
- **Çerçeve Referansı:** GDPR Madde 5 (Veri işleme ilkeleri), Madde 30
  (İşleme faaliyetleri kayıtları), Madde 32 (Teknik ve organizasyonel
  önlemler).
- **Kontrol Durumu:**
  - Veri sınıflandırması ve minimizasyon yaklaşımı,
    `docs/src/operations/compliance-checklist.md` kontrol maddeleri ile
    sprint sonlarında gözden geçiriliyor.
  - Saklama planları ve imha süreçleri
    `docs/src/operations/data-retention-policy.md` içerisinde güncellendi.
- **Kanıt Artefaktları:**
  - `docs/src/operations/data-retention-policy.md`
  - `docs/src/operations/privacy-terms-blueprint.md`
  - `docs/src/operations/compliance-checklist.md`
- **Açık Maddeler:**
  - Veri işleme faaliyeti envanterinin
    `config/kubernetes/AGENTS.md` ile uyumlu hale getirilmesi.
  - `apps/web` müşteri iletişim metinleri için çeviri gözden geçirmesi.

## HIPAA Compliance Assessment
- **Çerçeve Referansı:** HIPAA Security Rule (45 CFR §164.308, §164.310,
  §164.312) ve Privacy Rule (45 CFR §164.520).
- **Kontrol Durumu:**
  - Korumalı sağlık bilgisi (PHI) için veri akışı, hizmet bazlı mimari
    gereksinimleri karşılayacak şekilde `docs/src/operations/privacy-terms-blueprint.md`
    dokümanında bölümlendi.
  - Anahtar yönetimi ve erişim denetimi, `crates/kms` kullanım notları ve
    HSM runbook kayıtlarıyla takip ediliyor.
- **Kanıt Artefaktları:**
  - `docs/src/operations/privacy-terms-blueprint.md`
  - `docs/src/operations/data-retention-policy.md`
  - `docs/src/operations/kms-conformance.md`
- **Açık Maddeler:**
  - İş ortağı anlaşması (BAA) şablonunun hukuk ekibi tarafından
    doğrulanması.
  - Audit log maskeleme politikasının `crates/server` içinde uygulanması.

## ISO/IEC 27001 Certification Preparation
- **Çerçeve Referansı:** ISO/IEC 27001:2022 — Madde 6.1.3 (Risk
  değerlendirmesi), Ek A kontrolleri (A.5 Bilgi güvenliği politikaları,
  A.8 Teknoloji kaynaklarının yönetimi, A.12 Operasyonel güvenlik).
- **Kontrol Durumu:**
  - Risk değerlendirme prosedürü, `docs/src/operations/incident-response-playbook.md`
    ve `docs/src/operations/clock-attestation-deployment.md` dokümanları
    ile hizalandı.
  - Varlık envanteri ve saklama yükümlülükleri,
    `docs/src/operations/data-retention-policy.md` ile merkezileştirildi.
- **Kanıt Artefaktları:**
  - `docs/src/operations/clock-attestation-deployment.md`
  - `docs/src/operations/data-retention-policy.md`
  - `docs/src/operations/agent-charters.md`
- **Açık Maddeler:**
  - İç denetim planının `certifications/tests` altında otomatik test
    senaryolarıyla genişletilmesi.
  - Risk kabul matrisinin `docs/src/operations` dizininde ADR formatında
    yayımlanması.

---

Bu doküman her sprint sonunda güncellenmeli, açılan maddeler için Linear
üzerinde `ops/compliance` etiketiyle takip kartı oluşturulmalıdır. SOC 2,
GDPR, HIPAA ve ISO 27001 denetim paketleri `certifications/` kök dizininde
paylaşılan şablonlarla uyumlu tutulmalıdır.
