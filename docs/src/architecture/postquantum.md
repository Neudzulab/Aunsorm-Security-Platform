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

### PQC Risk, Uyumluluk ve Performans Değerlendirmesi
- **Risk Analizi:** Kyber kapsüllerinin 1184 bayta kadar çıkması paket büyüklüklerini %25 artırarak MTU sınırlarına yaklaşmamıza neden olur; taşıma katmanında fragmentasyon riskini azaltmak için ETSI GR CYBER PQC 001 ve BSI TR-02102-1 tavsiyelerindeki hibrit profil eşikleri uygulanır. Dilithium imza boyutları log depolama maliyetlerini artırdığından şeffaflık defterlerinde deduplikasyon filtreleri zorunlu hale getirilmiştir.
- **Uyumluluk:** NIST FIPS 203/204 yayınları, BSI TR-02102-1 Bölüm 2, ETSI GR CYBER PQC 001 ve ENISA Post-Quantum Cryptography raporu temel uyumluluk kaynaklarıdır. `certifications/tests/pqc/` senaryoları bu referanslarla eşlenmiş olup, CI pipeline’ındaki opsiyonel PoC işi `ENABLE_PQC_POC=true` olduğunda çalışarak regülasyonlara uyum raporu üretir.
- **Performans:** ML-KEM ve ML-DSA akışları için benchmark’lar Criterion profillerinde tutulur; handshake gecikmeleri klasik ECDHE + Ed25519 akışına göre yaklaşık 1.8x artış gösterir. CI PoC işi, kapsül ve imza doğrulama süresini 50 ms eşiklerinin altında tutan fixture’ların mevcut olduğunu doğrular ve performans regresyonlarına karşı erken uyarı sağlar.

## Açık Riskler ve Sonraki Adımlar
- LibOQS tabanlı HPKE entegrasyonu henüz devreye alınmadığından, hibrit PQC + klasik anahtar anlaşması için `hpke` özelliğinin genişletilmesi planlanmalıdır.
- Uzun vadeli depolama için PQC sertifika zinciri (X.509) henüz yayımlanmadı; `aunsorm-x509`’un PQC imza desteği tamamlanana kadar Ed25519 kökleri ile ML-DSA ara anahtarları paralel tutulmalıdır.
- Tedarik zinciri gözetimi için `cargo audit` çıktıları ve reproducible build gereklilikleri yayın döngülerine eklenerek `pqcrypto` kütüphanelerindeki olası kırılmaları erken yakalama hedeflenmelidir.
