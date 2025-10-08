# Gelecek Yol Haritası

1. **Gelişmiş PQ Sertleştirmesi:** ML-DSA için üretim düzeyi destek ve istemci
   tarafı denetim listeleri.
2. **mdBook Otomasyonu:** CI pipeline’ına `mdbook build docs` adımı eklenerek
   her sürümde statik site çıktısının yayımlanması.
3. **Uzun Süreli Fuzzing:** `cargo fuzz cmin` entegre edilerek minimize edilmiş
   corpus koleksiyonunun nightly pipeline’da saklanması.
4. **Harici KMS Sağlayıcıları:** Yeni conformance fixture’ları ile HSM/PKCS#11
   sertifikasyon raporlarının genişletilmesi.
