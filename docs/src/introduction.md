# Giriş

Aunsorm güvenlik araç seti; kriptografik çekirdek, paketleme, kimlik ve platform
katmanlarının ortak bir koordinat sistemi altında bütünleştiği bir mimari sunar.
Bu kitap, sürüm 0.4.0 çerçevesinde oluşan bileşenlerin nasıl etkileştiğini,
küresel güvenlik varsayımlarını ve sprint planına bağlı olarak yürütülen sertleştirme
çalışmalarını belgeler.

> **Not:** Bu dokümantasyon `mdBook` kullanılarak hazırlanmıştır. Yerel ortamınızda
> `mdbook serve docs` komutunu çalıştırarak canlı önizleme alabilirsiniz.

## Tasarım İlkeleri

- **Deterministik Kalibrasyon:** Platformlar arası anahtar eşleşmeleri, EXTERNAL
  kalibrasyon bağlamları ve koordinat sindirimleri ile deterministik hale getirilir.
- **Strict Kip Varsayımları:** Üretim konuşlandırmalarında strict kip zorunlu olup
  tüm downgrade ve fallback yolları açık biçimde belgelenir.
- **Sıfırlama ve Zeroization:** Hassas malzeme, zeroize destekli veri yapıları
  üzerinden yaşam döngüsünün sonunda temizlenir.
- **Gözlemlenebilirlik:** OpenTelemetry entegrasyonu ile hem CLI hem de sunucu
  katmanları aynı izleme boru hattına bağlanabilir.

## Bu Kitapta Neler Var?

- Mimari panoramada sprint hedeflerinin katmanlara dağılımını inceleyebilirsiniz.
- Bileşen bazında (core, packet, KMS, platform) kısıtları ve veri akışlarını
  detaylı şekilde bulabilirsiniz.
- Test ve gözlemleme bölümünde yeni fuzz hedefi, soak testleri ve kalite komutlarının
  nasıl devreye alındığını okuyabilirsiniz.
- Yol haritası ekinde 1.0 sürümüne giden yolda planlanan ileri sertleştirme
  adımlarına yer verilmiştir.
