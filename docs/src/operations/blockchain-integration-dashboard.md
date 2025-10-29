# Blockchain Integration Dashboard — 2024-06-17 Snapshot

| Metric | Value | Source | Not |
| --- | --- | --- | --- |
| `retention_sync_last_run_at` | `2024-06-17T12:15:05Z` | `tests/blockchain/retention.rs` | Son drift çalışması alarmı tetikledi. |
| `retention_sync_last_success_at` | `2024-06-17T12:05:05Z` | `tests/blockchain/retention.rs` | 10 dakika önceki çalışma başarılı. |
| `retention_sync_last_success_seconds` | `660` | `RetentionSync::seconds_since_last_success` | SLA (<900s) içinde. |
| `retention_policy_mismatch` | `active` | `RetentionSync::retention_policy_alarm()` | `vasp:apac:sg:014` için versiyon/travel rule drift. |
| `travel_rule_reconcile_pending` | `true` | `certifications/audit/hsm_retention_audit.md` | `tr-2024-07-bridge-412` için manuel replay planlandı. |

## Org Scope Özeti

| Org Scope | Beklenen Politika | Quorum Versiyonu | Travel Rule Paketi | Fabric Anchor | Durum |
| --- | --- | --- | --- | --- | --- |
| `vasp:europe:de:001` | `ret-2024.06-r5` | `ret-2024.06-r5` | `tr-2024-06-bridge-104` | `cal-2024-06-bridge-015` | ✅ Uyumlu |
| `vasp:apac:sg:014` | `ret-2024.07-r2` | `ret-2024.07-r3` | `tr-2024-07-bridge-412` | Eksik anchor | ⚠️ Manuel uzlaştırma |

> Dashboard verileri `tests/data/blockchain/retention_sync_status.json` ve
> `certifications/audit/hsm_retention_audit.md` raporundan otomatik olarak
> üretilmiştir. Yeni çalıştırmalar sonrası dosya güncellenmelidir.
