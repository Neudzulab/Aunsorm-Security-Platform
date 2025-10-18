# Quorum → Sepolia Settlement Set

- **Üretim Kaynağı:** Quorum BaaS pilotundan alınan sınırlandırılmış transfer raporları,
  Sepolia üzerindeki doğrulama kontratı loglarıyla eşleştirildi.
- **Amaçlanan Test:** Oran sınırlama (rate limit) ve finalite checkpoint
  kontrollerinin köprüde doğru tetiklendiğini doğrulamak.
- **Beklenen Doğrulama Metrikleri:**
  - AML vaka referanslarının Sepolia tarafındaki rapor çıktısına
    taşınması.
  - Oracle fiyat snapshot verisinin aynı blok yüksekliğinde bulunması.
  - 5 bloktan kısa sürede finalite sağlanması.
