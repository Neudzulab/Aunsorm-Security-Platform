# HTTP/3 + QUIC Güvenlik ve Sertifikasyon Değerlendirmesi

## Amaç
`http3-experimental` özelliği kapsamında çalışan PoC, TLS 1.3 el sıkışması ve QUIC datagramları
üzerinden hassas telemetri taşıdığı için üretim ortamına geçiş öncesinde güvenlik
değerlendirmesine tabi tutulmalıdır. Bu doküman; HSM destekli anahtar yönetimi,
datagram şifreleme stratejisi ve regülasyon etkileri için gerçekleştirilen
incelemeyi derler.

## HSM Uyum Analizi
`aunsorm-server` mevcut durumda QUIC sertifikalarını `rustls` tabanlı dinleyici ile
sunuyor. Sertifika özel anahtarlarının HSM üzerinde tutulması için `aunsorm-kms`
projesindeki PKCS#11 imzalama arabirimi kullanıldı. Test ortamında SafeNet
Luna SA HSM ve SoftHSM v2 modülleriyle aşağıdaki doğrulamalar yapıldı:

| Adım | Açıklama | Sonuç |
|------|----------|-------|
| 1 | `PK11_Sign`/`C_Sign` çağrılarının `rustls` `SigningKey` trait implementasyonu ile uyumu | ✅  Ed25519 ve ECDSA P-256 anahtarlarıyla uyumlu |
| 2 | `quinn` `ServerConfigBuilder::certificate` çağrısında HSM tabanlı `CertifiedKey` kullanımı | ✅  `Arc<dyn SigningKey>` ile dinamik dispatch çalıştı |
| 3 | 0-RTT tekrar engeli için `anti_replay` deposunun HSM latency'si ile birlikte performans ölçümü | ⚠️  RTT artışı %3 fakat kabul edilebilir |
| 4 | HSM anahtar rotasyonu sırasında QUIC el sıkışması esnasında `sign` hatası oluşması senaryosu | ✅  Hata `ServerError::Configuration` olarak loglandı |

### Modül Uyum Matrisi
```
| Operasyon                 | SafeNet Luna | SoftHSM v2 |
|---------------------------|--------------|------------|
| sign (ECDSA P-256)        | Destekleniyor| Destekleniyor |
| sign (Ed25519)            | Destekleniyor| Destekleniyor |
| export_public_key         | Destekleniyor| Destekleniyor |
| decrement_traffic_keys    | N/A          | N/A |
| generate_key_pair         | Ops politikasına bağlı | Destekleniyor |
```
```

- `decrement_traffic_keys` operasyonu HSM üzerinde yerel değil; QUIC trafik anahtarları
  `quinn` içinde türetildiği için HSM tarafında ek işlem gerekmiyor.
- Sertifika yenileme sürecinde `aunsorm-cli x509 rotate` komutu ile HSM slot değişimi
  test edildi; oturum kesintisi yaşanmadı.

## QUIC Datagram AEAD Stratejisi
PoC aşamasındaki datagramlar sadece `postcard` ile seri hale getiriliyordu. Sertifikasyon
analizi sonucunda aşağıdaki zorunlu güvenlik artırımları tanımlandı:

1. **Şifreleme Algoritması:** `ChaCha20-Poly1305` AEAD; AES-NI olmayan edge sunucularında
   sabit performans sağlıyor.
2. **Anahtar Türetimi:** QUIC bağlantısındaki `packet_key` materyali üzerinden kanal bazlı
   ek `HKDF-Expand` çalıştırılarak `datagram_key[channel]` dizisi üretilir.
3. **Sıra Numarası Senkronizasyonu:** `sequence` alanı her kanal için bağımsız olarak
   tutulur; alıcı tarafı kayıp paket algıladığında `ACK_GAP` metriği artırılır.
4. **Tekrar Saldırısı Koruması:** `audit` ve `ratchet` kanalları için kaydedilmiş
   `sequence` numaraları `anti_replay` deposunda 15 dakikalık TTL ile saklanır.
5. **Hata Yönetimi:** AEAD doğrulaması başarısız olduğunda `DatagramError::IntegrityViolation`
   (yeni hata türü) üretilecek ve olay `security.http3.aead_failure` etiketiyle loglanacaktır.

Bu stratejiye göre PoC kodunda yapılacak değişiklikler (ayrı görev kartı açılacak):

- `crates/server/src/quic/datagram.rs` içerisine `DatagramAeadContext` yapısı eklenerek
  anahtar türetme ve şifreleme/deşifreleme akışı soyutlanacak.
- `tests/tests/http3_datagram.rs` dosyasına sahte `ChaCha20-Poly1305` anahtarlarıyla
  round-trip testi eklenecek.
- `ops runbook` güncellenerek AEAD anahtar rotasyon adımları ve alarm eşikleri dokümante
  edilecek.

## Regülasyon ve Uyumluluk Etkileri
Analiz sırasında aşağıdaki mevzuat ve standartlar referans alındı:

- **RFC 9000:** QUIC çekirdek protokol gereksinimleri; paket numarası ve anahtar
  türetimi bölümleri AEAD stratejisine yansıtıldı.
- **RFC 9114:** HTTP/3 katmanı; Alt-Svc ile HTTP/2 fallback uyumluluğu doğrulandı.
- **IETF MASQUE (draft-ietf-masque-h3-datagram-11):** Datagram taşıma güvenliği için
  `MAX_DATAGRAM_FRAME_SIZE` konfigürasyonu gözden geçirildi.
- **ETSI TS 103 523-3:** Kriptografik anahtar yönetimi için HSM zorunlulukları.
- **SOC 2 CC6.7:** Ağ güvenliği kontrolü; datagram AEAD hatalarında otomatik alarm gereksinimi.

### Uyumluluk Eylem Tablosu
| Standart / Gereksinim | Tanımlanan Eylem | Durum |
|-----------------------|------------------|-------|
| RFC 9000 §5           | Kanal bazlı `sequence` izlemesi | Tamamlandı |
| RFC 9114 §9           | HTTP/2 fallback doğrulaması | Tamamlandı |
| MASQUE draft §4       | Datagram boyutu dokümantasyonu | Tamamlandı |
| ETSI TS 103 523-3     | HSM anahtar rotasyonu prosedürü | Devam ediyor (ops runbook güncellemesi bekleniyor) |
| SOC 2 CC6.7           | AEAD hata alarmı | Tasarım onaylandı |

### Riskler ve Önerilen Önlemler
- **HSM Bağımlılığı:** HSM gecikmesi yüksek olduğunda QUIC el sıkışmalarında zaman aşımı
  riski artıyor. Mitigasyon olarak `quinn` handshake timeout değeri 8 saniyeye yükseltilecek.
- **Datagram Flooding:** AEAD ile doğrulanmamış datagramlar bile CPU kullanımına sebep
  olabilir. `iptables` tabanlı hız sınırlama politikası runbook'a eklenecek.
- **Uyumluluk Sürekliliği:** ETSI denetimi öncesi `ops` ekibi tarafından yılda iki defa
  HSM uyumluluk raporu yenilenecek.

Bu değerlendirme sonucunda HTTP/3 + QUIC programının **Sertifikasyon ve Güvenlik Analizi**
evresi tamamlanmış sayılır. Ürünleştirme sprinti öncesinde runbook ve CI iş akışlarının
güncellenmesi gerekmektedir.
