# Gizlilik Politikası ve Hizmet Şartları Taslağı

*Revizyon: 2025-02-17*

Bu doküman, Aunsorm platformu için yayınlanacak gizlilik politikası ve
hizmet şartları metinlerinin temel bileşenlerini tanımlar. Taslak,
GDPR (Madde 13-14), HIPAA Privacy Rule (§164.520) ve ISO/IEC 27001 Ek A.18
ile uyumlu olacak şekilde yapılandırılmıştır.

## Gizlilik Politikası Bileşenleri
1. **Sorumlu Veri İşleyenler ve İrtibat:**
   - Aunsorm B.V. (Veri Sorumlusu) ve bölgesel temsilci iletişim bilgileri.
   - Veri koruma görevlisi (DPO) için `privacy@aunsorm.dev` adresi.
2. **İşlenen Veri Kategorileri:**
   - Kimlik verileri (müşteri yönetimi)
   - Telemetri ve kullanım analitiği (anonimleştirilmiş)
   - PHI (yalnızca HIPAA sözleşmesi kapsamındaki müşteriler)
3. **İşleme Amaçları ve Hukuki Dayanak:**
   - Sözleşmenin ifası, meşru menfaat, hukuki yükümlülükler.
   - HIPAA kapsamındaki işlemler için Business Associate Agreement (BAA).
4. **Saklama ve İmha:**
   - `docs/src/operations/data-retention-policy.md` referans alınır.
   - İmha planları `runbook-retention.md` ile takip edilir.
5. **Veri Sahibi Hakları:**
   - Erişim, düzeltme, silme, veri taşınabilirliği taleplerinin 30 gün
     içinde yanıtlanacağı taahhüdü.
   - HIPAA kapsamında erişim talepleri için 15 günlük SLA.
6. **Üçüncü Taraf Paylaşımlar:**
   - Alt işlemciler listesi (`config/cloudflare/`, `config/aws/`).
   - Sınır ötesi veri aktarımı için SCC (Standard Contractual Clauses)
     kullanımı.
7. **Güvenlik Önlemleri:**
   - `AunsormNativeRng`, HSM tabanlı anahtar yönetimi ve QUIC üzerinden
     uçtan uca şifreleme stratejisi.

## Hizmet Şartları (Terms of Service) Bileşenleri
1. **Hizmet Tanımı:**
   - `README.md` mimari özetine uygun olarak platform bileşenleri
     (KMS, Blockchain Bridge, Identity Gateway) tanımlanır.
2. **Müşteri Yükümlülükleri:**
   - Kimlik yönetimi entegrasyonlarında MFA ve cihaz uyumluluğu.
   - API rate limit ve erişim token saklama sorumlulukları.
3. **Destek ve SLA:**
   - Olay sınıflandırması ve müdahale süreleri `incident-response-playbook.md`
     ile hizalanır.
   - Destek kanalları: 24/7 on-call, kritik olaylarda 15 dakikalık ilk
     yanıt taahhüdü.
4. **Ücretlendirme ve Faturalandırma:**
   - SLA ihlallerinde kredi mekanizması.
   - Veri saklama uzatımları için ek ücretlendirme.
5. **Sözleşmenin Feshi ve Veri İadesi:**
   - Fesih sonrası 30 günlük veri taşıma penceresi.
   - İmha raporları `certifications/audit/` klasörüne kaydedilir.
6. **Uyuşmazlık Çözümü:**
   - Hollanda yasaları, Amsterdam mahkemeleri yetkili.
   - HIPAA kapsamındaki müşteriler için ABD federal gereksinimlerine uyum.

## Yayın Takvimi ve Onay Süreci
1. **Taslak Hazırlığı:** Bu dosya referans alınarak hukuk ekibi ile ilk taslak
   oluşturulur.
2. **Uyumluluk İncelemesi:** Güvenlik ve operasyon ekipleri GDPR, HIPAA ve
   SOC 2 kontrolleriyle hizayı kontrol eder.
3. **Çok Dilli Yayın:** `apps/web` içerik ekibi İngilizce, Türkçe ve Almanca
   sürümleri üretir; çeviri QA süreci `ops/compliance` etiketiyle takip edilir.
4. **Versiyonlama:** Yayınlanan sürüm `docs/src/appendix/roadmap.md`
   üzerinde işaretlenir ve değişiklikler `CHANGELOG.md` dosyasına eklenir.

## İlgili Kaynaklar
- `docs/src/operations/data-retention-policy.md`
- `docs/src/operations/compliance-checklist.md`
- `certifications/compliance_status.md`
- `certifications/soc2_report_template.md`
