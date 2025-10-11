# Gelecek Yol Haritası

1. **Gelişmiş PQ Sertleştirmesi (Tamamlandı):** ML-DSA için üretim düzeyi
   sertleştirme yardımcıları (`mldsa::validate_*`) ve genişletilmiş istemci
   tarafı denetim listeleri sunuldu. CLI checklist çıktıları yeni kontrolleri
   raporlar.
2. **mdBook Otomasyonu (Tamamlandı):** CI pipeline’ına `mdbook build docs`
   adımı eklendi ve her sürümde statik site çıktısı yayımlanıyor. Bu kalem
   artık bakım aşamasında; gerektiğinde yeni kitap bölümleri CI çıktısına
   otomatik olarak dahil ediliyor.
3. **Uzun Süreli Fuzzing (Tamamlandı):** `cargo fuzz cmin` minimizasyonu gece
   iş akışına otomatikleştirildi; çıktı korpusları ve özet metrikler JSON
   olarak artefakt paketlerine ekleniyor.
4. **Harici KMS Sağlayıcıları:** Yeni conformance fixture’ları ile HSM/PKCS#11
   sertifikasyon raporlarının genişletilmesi. (Tamamlandı; bkz.
   [KMS Conformance Raporu](../operations/kms_conformance.md).)
