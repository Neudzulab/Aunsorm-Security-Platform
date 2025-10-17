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
4. **Harici KMS Sağlayıcıları (Tamamlandı):** Yeni conformance fixture’ları
   ve sertifikasyon raporları `tests/data/kms/` ve
   [KMS Conformance ve Sertifikasyon Raporları](../operations/kms-certification.md)
   bölümü ile yayımlandı. CI entegrasyon testleri bu fixture’ları kullanarak
   GCP, Azure ve PKCS#11 sağlayıcılarını doğrular.

## Post-Kuantum Sertifikasyon Hazırlığı

- **NIST Final Algoritmaları:** FIPS 203 (ML-KEM/CRYSTALS-Kyber), FIPS 204
  (ML-DSA/CRYSTALS-Dilithium) ve FIPS 205 (SPHINCS+), üretim geçiş planında
  zorunlu referans alınacak ana kaynaklardır. Kyber-768 ve Dilithium-65
  `aunsorm-pqc` kutusunda varsayılan, Kyber-1024 ve SPHINCS+-SHAKE-128f ise
  yüksek güven profilleri için opsiyonel olarak hedeflenmiştir.
- **ETSI/ENISA Önerileri:** ETSI GR CYBER PQC 001 ve ENISA Post-Quantum
  Cryptography (2023) raporları, hibrit TLS el sıkışmaları ve uzun süreli imza
  zincirleri için kontrol listelerimizi yönlendirir. Bu dokümanlar hibrit
  PQC + klasik geçiş senaryolarında minimum kayıt ve denetim alanlarını
  tanımlar.
- **Hedef Uygulama Alanları:** Karşılıklı TLS oturumları, firmware
  güncelleme imza zincirleri, şeffaflık defteri kanıtları ve müşteri tarafı
  kalibrasyon oturumları post-kuantum sertifikasyonunun öncelikli kapsamıdır.
  Sertifikasyon PoC’leri `certifications/tests/pqc/` dizininde toplanacak ve
  CI pipeline’ındaki opsiyonel iş adımıyla doğrulanacaktır.
