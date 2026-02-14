# Backup ve Felaket Kurtarma için RTO/RPO Hedefleri

Bu doküman, Aunsorm platformu için üretim felaket kurtarma hedeflerini resmi olarak tanımlar.

## Tanımlar

- **RTO (Recovery Time Objective):** Kritik bir kesinti sonrası servisin yeniden erişilebilir olması için hedeflenen en yüksek süre.
- **RPO (Recovery Point Objective):** Kurtarma sırasında kaybedilebilecek en fazla veri aralığı.

## Servis Sınıfları

| Servis Sınıfı | Kapsam | RTO | RPO |
|---|---|---:|---:|
| Tier 0 (Kritik Güvenlik) | `server` gateway, `kms`, `jwt`, `x509`, clock attestation | 30 dakika | 5 dakika |
| Tier 1 (Kimlik ve Sertifika Operasyonları) | `acme`, `mdm`, `id`, policy yönetimi | 2 saat | 15 dakika |
| Tier 2 (Destek ve Analitik) | dashboard, raporlama, operasyon yardımcı servisleri | 8 saat | 4 saat |

## Hedef Uygulama Prensipleri

1. Tier 0 için veritabanı WAL/transaction log tabanlı sürekli yedekleme zorunludur.
2. Tier 0 için restore adımları otomatikleştirilmeli ve haftalık doğrulama çalıştırılmalıdır.
3. Tüm kurtarma testleri, `docs/src/operations/disaster-recovery-runbook.md` ile uyumlu kanıt kaydı üretmelidir.
4. RTO/RPO ihlali görüldüğünde olay kaydı açılmalı ve olay sonrası raporda kök neden analizi eklenmelidir.

## Doğrulama Takvimi

- **Günlük:** Yedekleme işi başarısı + bütünlük kontrolü.
- **Haftalık:** Tier 0 örnek restore doğrulaması.
- **Aylık:** Tier 1/Tier 2 tam restore tatbikatı.
- **Çeyreklik:** Bölgesel felaket kurtarma tatbikatı ve RTO/RPO kanıt raporu.

## Ölçüm ve Raporlama

Aşağıdaki metrikler gözlemlenmelidir:

- `backup_job_success_rate`
- `restore_validation_duration_seconds`
- `effective_rpo_seconds`
- `effective_rto_seconds`

Her sprint sonunda operasyon raporuna RTO/RPO uygunluk özeti eklenir.
