# Operasyonel Sorun Giderme Rehberi

Bu rehber, Aunsorm dağıtımlarında en sık karşılaşılan hataları hızlıca teşhis edip
çözebilmeniz için belirtiler, olası nedenler ve uygulanabilir adımlar sunar.

## Build ve Araç Zinciri Sorunları

**Belirti**: `cargo build` eski derleyici nedeniyle hata veriyor veya MSRV uyarısı alıyorsunuz.

**Neden**: Proje minimum olarak Rust 1.76 sürümünü hedefler; daha eski toolchain'ler
kodu derleyemez.

**Çözüm**:

1. `rustup show` ile aktif toolchain'inizi doğrulayın.
2. Gerekirse `rustup toolchain install 1.76.0` ve `rustup default 1.76.0` komutlarını
   çalıştırın.
3. Derlemeyi `cargo build --release --all-features` komutuyla tekrar deneyin.

## Strict Kipte Başlatma Hataları

### `AUNSORM_STRICT=1 iken AUNSORM_JTI_DB zorunludur`

**Belirti**: Sunucu strict kipte başlarken yukarıdaki yapılandırma hatasıyla duruyor.

**Neden**: Strict kip etkinleştirildiğinde JTI defterinin kalıcı (SQLite) depoda
saklanması zorunludur.

**Çözüm**:

1. Kalıcı bir yol belirleyin, örneğin `export AUNSORM_JTI_DB=./data/tokens.db`.
2. Docker Compose kullanıyorsanız ilgili volume'ün yazılabilir olduğundan emin olun.
3. Sunucuyu yeniden başlatın; hata devam ederse yolun mutlak olduğundan emin olun.

### `Strict kipte AUNSORM_JWT_SEED_B64 zorunludur`

**Belirti**: Strict kipte başlarken JWT anahtarı oluşturulamadığına dair hata.

**Neden**: Strict kip, deterministik bir Ed25519 anahtarına ihtiyaç duyar.

**Çözüm**:

1. `openssl rand -base64 32` komutuyla 32 baytlık bir tohum üretin.
2. Ortam değişkenini ayarlayın:
   ```bash
   export AUNSORM_JWT_SEED_B64="$(openssl rand -base64 32)"
   export AUNSORM_JWT_KID="server-1"
   ```
3. Hizmeti yeniden başlatın.

## Kalibrasyon ve Saat Doğrulama Hataları

### `AUNSORM_CALIBRATION_FINGERPRINT 64 karakterlik hex dizesi olmalıdır`

**Belirti**: Sunucu başlatılamıyor, hata logu kalibrasyon fingerprint'inin geçersiz
olduğunu belirtiyor.

**Neden**: `AUNSORM_CALIBRATION_FINGERPRINT` değişkeni zorunludur ve 64 karakterlik
hex formatında olmalıdır.

**Çözüm**:

1. Mevcut fingerprint değerini doğrulayın; karakter sayısı ve hex formatı uygunsa hata gider.
2. Gerekirse geçerli bir fingerprint üreterek `.env` dosyanızı güncelleyin.

### `AUNSORM_CLOCK_ATTESTATION` JSON Parse veya `StaleAttestation`

**Belirti**: Loglarda `AUNSORM_CLOCK_ATTESTATION JSON parse edilemedi` veya
`Clock(StaleAttestation { ... })` hataları görülüyor.

**Neden**: Clock attestation JSON'u geçersiz, eksik imza içeriyor veya zaman damgası
maksimum yaş sınırını aşıyor.

**Çözüm**:

1. JSON yapısını `docs/CLOCK_ATTESTATION.md` rehberindeki örneğe göre doğrulayın.
2. StaleAttestation için NTP yenileme hizmeti çalıştırın ya da geliştirme ortamında
   `AUNSORM_CLOCK_MAX_AGE_SECS` değerini geçici olarak artırın.
3. Manüel güncelleme gerekiyorsa attestation JSON'unun `unix_time_ms` alanını güncel
   UTC milisaniye değeriyle değiştirin.

## Docker Compose Dağıtımlarında Sağlık Kontrolleri

**Belirti**: Gateway veya bağımlı servisler sağlıklı görünmüyor.

**Neden**: Mikro servislerden biri başlatılamadı veya sağlık kontrolü başarısız.

**Çözüm**:

1. `docker compose ps` komutuyla konteyner durumlarını kontrol edin.
2. `docker compose logs -f <servis>` ile hatalı servisin loglarını inceleyin.
3. Gateway için `curl http://${HOST:-localhost}:50010/health` isteğiyle sağlık kontrolünü
   manuel doğrulayın.

## Fabric Entegrasyonu Yapılandırma Hataları

**Belirti**: Loglarda `Fabric entegrasyonu için hem AUNSORM_FABRIC_CHANNEL hem de AUNSORM_FABRIC_CHAINCODE gereklidir` mesajı görünüyor.

**Neden**: Hyperledger Fabric entegrasyonu için gerekli kanal veya chaincode değeri eksik.

**Çözüm**:

1. Entegrasyon kullanılacaksa her iki ortam değişkenini de ayarlayın:
   ```bash
   export AUNSORM_FABRIC_CHANNEL=fabric-main
   export AUNSORM_FABRIC_CHAINCODE=did-registry
   ```
2. Entegrasyon devre dışıysa her iki değişkeni de kaldırın; sadece birinin tanımlı olması
   yapılandırma hatasına neden olur.
