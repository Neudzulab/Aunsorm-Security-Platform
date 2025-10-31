# Blockchain Integration Dashboard — 2024-06-17 Reconcile Snapshot

| Metric | Value | Source | Not |
| --- | --- | --- | --- |
| `retention_sync_last_run_at` | `2024-06-17T12:25:05Z` | `tests/blockchain/retention.rs` | Uzlaştırma koşusu başarıyla tamamlandı. |
| `retention_sync_last_success_at` | `2024-06-17T12:25:05Z` | `tests/blockchain/retention.rs` | Alarm kapandı, başarı zaman damgası güncellendi. |
| `retention_sync_last_success_seconds` | `300` | `RetentionSync::seconds_since_last_success` | SLA (<900s) içinde, 5 dk sonra ölçüldü. |
| `retention_policy_mismatch` | `cleared` | `RetentionSync::retention_policy_alarm()` | `retention_sync_reconcile.json` verisi ile alarm temizlendi. |
| `travel_rule_reconcile_pending` | `false` | `certifications/audit/hsm_retention_audit.md` | Travel Rule yeniden yayımı tamamlandı. |

## Org Scope Özeti

| Org Scope | Beklenen Politika | Quorum Versiyonu | Travel Rule Paketi | Fabric Anchor | Durum |
| --- | --- | --- | --- | --- | --- |
| `vasp:europe:de:001` | `ret-2024.06-r5` | `ret-2024.06-r5` | `tr-2024-06-bridge-104` | `cal-2024-06-bridge-015` | ✅ Uyumlu |
| `vasp:apac:sg:014` | `ret-2024.07-r2` | `ret-2024.07-r2` | `tr-2024-07-bridge-208` | `cal-2024-07-bridge-021` | ✅ Uyumlu |

> Dashboard verileri `tests/data/blockchain/retention_sync_reconcile.json`,
> `tests/data/blockchain/retention_sync_status.json` ve
> `certifications/audit/hsm_retention_audit.md` raporundan otomatik olarak
> üretilmiştir. Yeni çalıştırmalar sonrası dosya güncellenmelidir.
