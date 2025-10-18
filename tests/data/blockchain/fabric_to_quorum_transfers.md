# Fabric → Quorum Transfer Set

- **Üretim Kaynağı:** Istanbul PoC sırasında kullanılan Fabric kanalındaki zincir dışı bridge logları
  Quorum özel ağına yapılan stablecoin devirleriyle eşleştirildi.
- **Amaçlanan Test:** Zincirler arası köprüde Travel Rule kayıtlarının ve çift imzalı kilit açma
  mekanizmasının doğrulanması.
- **Beklenen Doğrulama Metrikleri:**
  - Hash kilitleme sözleşmesi ile MPC imzası arasındaki `transfer_id` eşleşmesi.
  - KYC referanslarının karşı ağda uyum raporuna aktarılması.
  - 500 ms altında bloklar arası finalite farkı (timestamp kontrolü).
