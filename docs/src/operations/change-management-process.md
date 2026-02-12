# Change Management Process

Bu doküman, production değişikliklerinin planlama, onay, yayınlama ve geriye alma
adımlarını standartlaştırır.

## Amaç ve Kapsam

- Production ortamını etkileyen tüm değişikliklerde izlenebilirlik sağlamak
- Riskli değişiklikleri önceden sınıflandırmak ve doğru onay zincirini çalıştırmak
- Yayın sonrası doğrulama, rollback ve kanıt saklama süreçlerini tek çatıda toplamak

Kapsam:

- Uygulama release'leri (API, worker, gateway)
- Altyapı değişiklikleri (Kubernetes, ağ, veri tabanı, secrets)
- Güvenlik ve uyumluluk odaklı konfigürasyon değişiklikleri

## Rol ve Sorumluluklar

| Rol | Sorumluluk |
| --- | --- |
| Change Requester | Değişiklik kaydı açar, risk/etki analizi ekler, test kanıtlarını yükler |
| Service Owner | Teknik doğrulama yapar, rollout/rollback planını onaylar |
| Security Reviewer | Güvenlik etkilerini değerlendirir (auth, crypto, secrets, erişim) |
| CAB (Change Advisory Board) | High/Critical değişiklikler için nihai onay verir |
| Incident Commander | Acil durumda standard süreci emergency akışına geçirir |

## Değişiklik Sınıfları

### Standard Change

- Düşük riskli, tekrar eden ve önceden onaylı değişiklikler
- Örnek: dokümantasyon güncellemesi, feature flag kapalı iken refactor
- Onay: Service Owner

### Normal Change

- Orta riskli değişiklikler; planlı bakım penceresiyle ilerler
- Örnek: yeni endpoint yayını, konfigürasyon değişikliği, dependency güncellemesi
- Onay: Service Owner + Security Reviewer (gerekirse)

### High-Risk / Critical Change

- Müşteri trafiği, veri bütünlüğü veya güvenlik etkisi yüksek değişiklikler
- Örnek: authentication flow değişiklikleri, KMS/HSM entegrasyonu, DB migration
- Onay: CAB zorunlu

### Emergency Change

- Aktif incident veya kritik güvenlik açığı için hızlandırılmış süreç
- Onay: Incident Commander + ilgili Service Owner
- Not: Olay sonrası 24 saat içinde geriye dönük CAB review zorunlu

## CAB İş Akışı

1. Change Request, sprint içinde en az 1 iş günü önce açılır.
2. Risk puanı (Low/Medium/High) ve etki alanı (service, data, security) doldurulur.
3. Rollout + rollback planı ve test kanıtları eklenir.
4. CAB toplantısında karar verilir: `Approved`, `Needs Changes`, `Rejected`.
5. Onaylı kayıt release takvimine işlenir ve sorumlu ekip atanır.

## Zorunlu Değişiklik Kaydı Alanları

Her kayıt aşağıdaki bilgileri içermelidir:

- İlgili task/issue bağlantısı (örn. `PROD_PLAN.md` maddesi)
- Etkilenen servisler ve ortamlar
- Risk değerlendirmesi ve blast radius
- Test kanıtları (unit/integration/manual)
- Monitoring ve alarm doğrulama planı
- Rollback kriterleri ve adımları
- Onay veren roller ve zaman damgaları

## Release Evidence Checklist

Yayın kapatılmadan önce aşağıdaki kanıtlar eklenir:

- CI sonuçları (fmt, clippy, test, deny/audit)
- Deploy manifest/hash ve release notları
- Smoke test sonuçları
- Observability ekran görüntüsü veya metrik linkleri
- Incident oluştuysa postmortem linki

## Rollback Politikası

- Her Normal/High/Critical değişiklik için uygulanabilir rollback planı zorunludur.
- Rollback tetikleyicileri release öncesi tanımlanır:
  - Error rate artışı
  - Latency SLO ihlali
  - Auth/KMS kritik hata oranı
- Rollback sonrası 30 dakika gözlem ve doğrulama yapılır.

## Araçlar ve Kayıt Saklama

- Değişiklik kayıtları issue tracker'da `change-management` etiketiyle tutulur.
- CAB kararları haftalık olarak `docs/src/operations/runbook-retention.md` ile
  çapraz referanslanır.
- Incident kaynaklı emergency değişiklikler
  `docs/src/operations/incident-postmortem-template.md` ile ilişkilendirilir.

## Uyum ve Denetim

- Bu süreç SOC 2 change management ve ISO 27001 değişiklik kontrol gereksinimleri
  ile uyumludur.
- Quarterly sample review yapılır; uygunsuzluklar için düzeltici aksiyon açılır.
