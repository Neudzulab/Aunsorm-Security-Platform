# Post-Kuantum Hazırlık Durumu

## Özet
- Aunsorm varsayılan derlemelerinde `aunsorm-pqc` kutusu ML-KEM-768 ve ML-DSA-65 özelliklerini açarak post-kuantum el sıkışma ve imza akışlarını hazır hâle getirir; ML-KEM-1024, Falcon-512 ve SPHINCS+-SHAKE-128f opsiyonel bayraklarla devreye alınabilir.
- Strict kip `AUNSORM_STRICT=1` ile etkinleşir ve desteklenen bir PQC algoritması bulunmadığında işlemi durdurarak klasik mod degradasyonunu engeller.
- Paketleme ve oturum katmanları PQC kapsüllerini, kalibrasyon kimliklerini ve ratchet koordinatlarını birlikte taşır; böylece hem post-kuantum hem de klasik akışlar aynı doğrulama zincirine bağlanır.

## PQC Bileşenleri
### Anahtar Değişimi ve Kapsülleme
- `KemAlgorithm` ML-KEM-768/1024 ile klasik `None` seçeneğini aynı arayüzde sunar; `negotiate_kem` strict kipte başarısız olarak fail-fast sağlar.
- `KemKeyPair`, `encapsulate` ve `decapsulate` fonksiyonları PQC açık ve gizli anahtar uzunluklarını doğrular, `Zeroizing` kapsayıcılarıyla paylaşılan sırları temizler.

### İmza Sertleştirmesi
- `SignatureAlgorithm` ML-DSA-65, Falcon-512 ve SPHINCS+-SHAKE-128f algoritmalarını listeler; özellik bayrakları devrede değilse otomatik olarak dışlanır.
- `signature::mldsa::validate_*` yardımcıları rho, K ve tr segmentlerini tekdüze entropi ihlallerine karşı kontrol ederek üretim öncesi sertleştirme sağlar.
- `SignatureChecklist` istemci aksiyonları, çalışma zamanı zorunlulukları ve referans metinleriyle operasyon ekiplerinin post-kuantum protokollerini belgeli şekilde uygulamasına yardım eder.

## Entegrasyon Durumu
- `aunsorm-packet` testleri strict kip altındaki PQC kapsüllerinin AES-GCM veri akışlarıyla birlikte çözümlendiğini doğrular; bu sayede oturum ratchet adımları ML-KEM tarafından üretilen sırlarla beslenebilir.
- Kalibrasyon bağlamı (`calib_from_text`) ve koordinat türetimi (`coord32_derive`) PQC anahtarlarıyla aynı header içinde taşınarak dışsal kalibrasyon zorunluluğu korunur.
- CLI ve sunucu katmanları aynı `SessionMetadata` sözleşmesini paylaşarak PQC koordinatlarını loglama ve şeffaflık defterlerine işleme sürecini standartlaştırır.

## Operasyonel Gereklilikler
- Dağıtım notları PQC özellik bayraklarının (örn. `--features pqc,crates/pqc/kem-mlkem-1024`) hangi ortamda açıldığını belgelemeli; CI pipeline’ları bu kombinasyonlar için `cargo clippy` ve `cargo test` koşturmalıdır.
- Strict kip üretimde varsayılan hâle getirilmeden önce servisler `AUNSORM_STRICT=1` ile gözetimli canary rollout’tan geçirilmeli, fallback olmayan senaryolarda hata gözlemi yapılmalıdır.
- `pqcrypto-*` bağımlılıkları güncellendiğinde `SignatureChecklist` referansları ve `mldsa::validate_*` kontrolleri yeniden değerlendirilerek NIST rehberleriyle uyum teyit edilmelidir.

## Açık Riskler ve Sonraki Adımlar
- LibOQS tabanlı HPKE entegrasyonu henüz devreye alınmadığından, hibrit PQC + klasik anahtar anlaşması için `hpke` özelliğinin genişletilmesi planlanmalıdır.
- Uzun vadeli depolama için PQC sertifika zinciri (X.509) henüz yayımlanmadı; `aunsorm-x509`’un PQC imza desteği tamamlanana kadar Ed25519 kökleri ile ML-DSA ara anahtarları paralel tutulmalıdır.
- Tedarik zinciri gözetimi için `cargo audit` çıktıları ve reproducible build gereklilikleri yayın döngülerine eklenerek `pqcrypto` kütüphanelerindeki olası kırılmaları erken yakalama hedeflenmelidir.
