# aunsorm-mdm

`aunsorm-mdm`, Aunsorm platformunun Mobile Device Management (MDM) yetenekleri
 için temel veri yapıları ve iş mantığını sağlar. Cihaz kaydı, politika
yönetimi ve sertifika dağıtım planlarını tek bir API üzerinden sunar.

## Özellikler
- Platforma göre politika depolama ve versiyonlama.
- Cihaz kayıt akışı ile tekrar kayıtların engellenmesi.
- Sertifika dağıtım planı üretimi ve yenileme penceresi hesaplamaları.
- Serde uyumlu veri modelleri ile REST entegrasyonuna hazır çıktı.

## Testler

```
cargo test -p aunsorm-mdm
```
