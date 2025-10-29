# ACME Validation Modülü Yönergeleri

- Bu dizindeki modüller challenge durum makinelerini yönetir; durum
  geçişleri açık enum değerleriyle belgelenmelidir.
- `serde` türevleri gerekiyorsa `kebab-case` kullanın ve durumları
  RFC 8555 terminolojisiyle uyumlu tutun.
- Yeni hata türleri kullanıcıya Türkçe açıklama vermelidir.
