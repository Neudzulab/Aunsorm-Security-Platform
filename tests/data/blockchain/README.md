# Cross-Network Fixture Inventory

Bu dizin, zincirler arası test harness'i için kullanılacak deterministik veri
kümelerini içerir.

- **Kaynaklar:** Hyperledger Fabric ve Quorum özel ağları ile kontrollü bir
  Ethereum Sepolia köprüsü logları.
- **Amaç:** Zincirler arası köprü operasyonlarının bütünlük ve uyumluluk
  senaryolarını yeniden üretmek.
- **Format:** JSON dosyaları UTF-8 kodlamalıdır ve her kayıt, sahte fakat
  üretim benzeri değerler içerir.

Her veri kümesinin yanındaki `.md` dosyası, fixture'ın nasıl üretildiğini,
hangi güvenlik kontrolünü hedeflediğini ve beklenen doğrulama metriklerini
açıklar.

## Veri Kümeleri
- `fabric_to_quorum_transfers.json`: Fabric → Quorum köprüsü için hash kilidi ve
  Travel Rule kontrolleri.
- `quorum_to_sepolia_settlements.json`: Quorum → Sepolia ödemelerinde hız
  sınırlama ve finalite doğrulaması.
- `retention_policy_audit.json`: Müşteri bazlı saklama/anahtar imha politikasının
  Quorum AuditAsset kayıtları ve KMS imha loglarıyla eşlenmesini kanıtlayan
  kayıtlar.
