# On-Call Rotation Schedule

Bu doküman, Aunsorm Security Platform için haftalık on-call nöbet planını, rol dağılımını, escalation zincirini ve teslim prosedürlerini tanımlar.

## Amaç

- 7/24 üretim desteğini sürdürülebilir bir ritimde sağlamak
- P1/P2 olaylarda tekil sahipliği netleştirmek
- Alarm yorgunluğunu azaltmak için adil rotasyon uygulamak
- Postmortem ve iyileştirme aksiyonlarını nöbet sürecine bağlamak

## Rotasyon Modeli

- **Cadence:** Haftalık (Pazartesi 09:00 UTC devir)
- **Birincil (Primary):** Anlık alarm sahipliği, ilk müdahale
- **İkincil (Secondary):** Primary yanıt veremezse devralma, teknik eşlik
- **Incident Commander (IC):** P1/P0 durumunda koordine eden rol (haftalık atanır)

### Team Lanes

| Lane | Scope | Primary Ekip |
|---|---|---|
| Platform | API Gateway, Server, Kubernetes | Platform Agent |
| Identity | JWT/X509/KMS/ACME | Identity Agent |
| Crypto | Core/PQC/Packet | Crypto Agent |
| Interop | CI, test, fuzz, benchmark | Interop Agent |

## Haftalık Devir ve El Sıkışma Kontrolü

Her devirde aşağıdaki adımlar zorunludur:

1. Açık P1/P2 olay yokluğu teyidi
2. "Known issues" listesi ve geçici workaround'ların paylaşımı
3. Son 7 gün alarm trendi ve noise kaynaklarının gözden geçirilmesi
4. Riskli deploy pencereleri ve bakım aktivitelerinin devri
5. Nöbet iletişim kanallarının (chat/telefon) doğrulanması

## Yanıt SLO'ları

- **P0 (Major Outage):** İlk yanıt ≤ 5 dk
- **P1 (Critical):** İlk yanıt ≤ 10 dk
- **P2 (High):** İlk yanıt ≤ 30 dk
- **P3 (Medium):** Mesai saatleri içinde triage

> SLA/SLO hedefleriyle tutarlılık için `docs/src/operations/sla-slo-targets.md` referans alınır.

## Escalation Politikası

1. Primary 5 dakika içinde ack etmezse Secondary otomatik devreye girer.
2. P1/P0 olayda Incident Commander en geç 10 dakika içinde atanır.
3. 30 dakikada stabilize edilemeyen P1 olaylarında platform-lead ve security-lead bilgilendirilir.
4. Regülasyon etkisi (GDPR/HIPAA/SOC2) şüphesinde Incident Response Playbook uygulanır.

## Haftalık Örnek Plan Şablonu

| Hafta | Primary | Secondary | IC |
|---|---|---|---|
| 2026-W06 | platform-oncall-1 | identity-oncall-1 | platform-ic-1 |
| 2026-W07 | identity-oncall-2 | crypto-oncall-1 | identity-ic-1 |
| 2026-W08 | crypto-oncall-2 | interop-oncall-1 | crypto-ic-1 |
| 2026-W09 | interop-oncall-2 | platform-oncall-2 | interop-ic-1 |

> Not: Gerçek isimler/hesaplar iç wiki veya alerting sisteminde tutulur; bu doküman süreç standardını tanımlar.

## Olay Sonrası Zorunlu Çıktılar

- P1/P0 olaylar için 48 saat içinde postmortem
- Corrective action maddelerinin PROD_PLAN görevlerine dönüştürülmesi
- Gerekirse runbook güncellemesi (`disaster-recovery`, `troubleshooting`, `incident-response`)

## Uygulama Durumu

- [x] Haftalık nöbet ritmi tanımlandı
- [x] Primary/Secondary/IC rol modeli belirlendi
- [x] Escalation zinciri standardize edildi
- [x] Handover checklist yayımlandı
