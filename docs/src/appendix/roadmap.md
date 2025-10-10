# Gelecek Yol Haritası

1. **Gelişmiş PQ Sertleştirmesi:** ML-DSA için üretim düzeyi destek ve istemci
   tarafı denetim listeleri.
2. **mdBook Otomasyonu (Tamamlandı):** CI pipeline’ına `mdbook build docs`
   adımı eklendi ve her sürümde statik site çıktısı yayımlanıyor. Bu kalem
   artık bakım aşamasında; gerektiğinde yeni kitap bölümleri CI çıktısına
   otomatik olarak dahil ediliyor.
3. **Uzun Süreli Fuzzing:** `cargo fuzz cmin` entegre edilerek minimize edilmiş
   corpus koleksiyonunun nightly pipeline’da saklanması.
4. **Harici KMS Sağlayıcıları:** Yeni conformance fixture’ları ile HSM/PKCS#11
   sertifikasyon raporlarının genişletilmesi.
