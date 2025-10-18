# HTTP/3 ve QUIC Datagram Programı

## Amaç ve Kapsam
HTTP/3 ve QUIC Datagram desteği, Aunsorm sunucusunun modern tarayıcılar ve edge istemcileriyle daha düşük gecikmeli ve kayıp toleranslı iletişim kurabilmesini hedefler. Program;

- OAuth/OIDC uçlarının HTTP/3 üzerinden güvenilir aktarımı,
- Datagram tabanlı telemetri ve olay akışları için QUIC datagram kanallarının açılması,
- Geriye dönük HTTP/2 ve HTTP/1.1 uyumluluğu için şelale fallback stratejisinin sürdürülmesi

Bu hedefler programın kapsamını tanımlar.

## Teslimat Aşamaları
1. **Araştırma & Seçim (Interop Agent)**
   - `quinn`, `h3` ve `quiche` kütüphanelerinin TLS 1.3, 0-RTT ve datagram API desteğini kıyasla.
   - HTTP/3 `alt-svc` keşfi ve ALPN (`h3`, `h3-29`) reklamı için yapılandırma gereksinimlerini belirle.
   - Datagram kullanım senaryoları (otel metrikleri, denetim olayı yayınları) için mesaj formatı ve boyut sınırı belgele.

### 1.1 Kütüphane Kıyaslaması
| Kütüphane | TLS 1.3 / 0-RTT | Datagram API | MSRV Notu | Öne Çıkan Artılar | Belirlenen Riskler |
|-----------|-----------------|--------------|-----------|------------------|--------------------|
| `quinn` 0.11 | Tam TLS 1.3 desteği, 0-RTT yeniden kullanım `enable_0rtt()` ile kontrol ediliyor. | `send_datagram`/`read_datagram` çağrıları istikrarlı. | Sürüm notlarında 1.65 belirtilmiş olsa da 1.76 ile derleme testi yapıldı; bağımlılıklar MSRV hedefimizi karşılıyor. | Saf Rust implementasyon, `rustls` tabanlı güvenli TLS, aktif bakım, QUIC RFC9000 uyumu. | Akış yönetimi için arabellek ayarlarının dikkatli yapılması gerekiyor; varsayılan limitler telemetri patlamalarında yeterli değil. |
| `h3` 0.0.6 | QUIC katmanı `quinn` üzerinden TLS 1.3 kullanıyor; 0-RTT isteğe bağlı olarak iletilebiliyor. | `ReceiveStream::read_datagram` ile HTTP/3 datagram ekleri destekleniyor. | MSRV 1.74; `quinn` + `http` ekosistemi 1.76 üzerinde sorunsuz. | HTTP/3 request/response soyutlaması mevcut `tower` servislerine yakın API sunuyor. | Sunucu tarafı push henüz stabil değil; tasarımda zorunlu tutulmamalı. |
| `quiche` 0.22 | BoringSSL tabanlı TLS 1.3, 0-RTT geniş destek. | `stream_send` yanında `conn.send_datagram`/`recv_datagram`. | Rust binding'leri için `bindgen` + BoringSSL kurulumu gerekiyor; MSRV 1.74 üstünde çalışıyor. | Çok olgunlaştırılmış performans profili, Cloudflare üretiminde kullanılıyor. | Harici C bağımlılıkları CI/CI pipeline'ımıza ek operasyonel yük getiriyor; statik linkleme karmaşık. |

Bu kıyaslama sonucunda Interop Agent, **temel PoC** için `quinn` + `h3` ikilisini öneriyor; `quiche` ise ileri performans testleri ve alternatif TLS yığını gereksinimleri için yedek seçenek olarak dokümante edildi.

### 1.2 Alt-Svc ve ALPN Reklamı
- `apps/server` HTTPS uçları için `http3-experimental` özelliği etkin olduğunda aşağıdaki başlıkların gönderilmesi planlandı:
  - `alt-svc: h3=":443"; ma=3600, h3-29=":443"; ma=3600`
  - `alt-svc` başlığının yanında `server` uçlarında `Alt-Svc` denetimi için bir healthcheck log girdisi tutulacak.
- TLS konfigürasyonu `rustls` tabanlı olarak ALPN listesini `[b"h3", b"h3-29", b"http/1.1"]` şeklinde sırayla reklamlayacak. HTTP/2 desteği `h2` crate'i üzerinden sürdürülecek ve bağlantı müzakeresi başarısız olduğunda otomatik fallback devreye girecek.
- QUIC endpoint'i `0-RTT` oturum kabul ettiğinde sunucu tarafı `anti_replay` deposuna yeni `SessionId` kayıtları açacak; STRICT kipinde 0-RTT yalnızca iç ağlarda açılacak.

### 1.3 QUIC Datagram Mesaj Formatı
- Telemetri ve olay akışları için hafif ve sabit boyutlu bir şema tercih edildi. Datagram yükü `postcard` (Serde tabanlı `no_std` codec) ile kodlanacak.
- Mesaj zarfı: 
  ```text
  struct QuicDatagramV1 {
      version: u8 = 1,
      channel: u8,        // 0 = otel metrikleri, 1 = denetim olayı, 2 = ratchet gözlemi
      sequence: u32,      // sarma mod 2^32, kayıp tespiti için
      timestamp_ms: u64,  // UNIX epoch
      payload: Vec<u8>,   // postcard ile nested struct (örn. CounterSample)
  }
  ```
- `payload` alanları kanal tipine göre ayrı modüllerde belirlendi: 
  - `otel`: Sıkıştırılmış `MetricSnapshot` yapısı (counter, histogram, gauge).
  - `audit`: `AuditEvent` (event_id, principal_id, outcome, resource).
  - `ratchet`: `RatchetProbe` (session_id, step, drift, status).
- En büyük paket boyutu MTU 1350 bayt hedeflenerek hesaplandı; `payload` için üst sınır 1150 bayt olacak şekilde `apps/server` konfigürasyonuna limit kontrolü eklenmesi planlandı. Limit aşımı durumunda olay queue'ya yönlendirilecek.

### 1.4 Karar ve Sonraki Adımlar
- Araştırma aşaması tamamlandı ve sonuç raporu bu dokümana işlendi.
- Platform Agent, `quinn` + `h3` PoC uygulaması için `apps/server` crate'inde `http3-experimental` özelliğini hazırlamakla görevlendirildi.
- Interop Agent, datagram şemasının Rust tiplerini `crates/server/src/quic/datagram.rs` altında tasarlayacak ve property test senaryolarını `tests/http3` klasöründe hazırlayacak.
- Güvenlik notu: 0-RTT tekrar saldırılarına karşı STRICT modda `anti_replay` tablosu zorunlu hale getirilecek; belge revizyonu güvenlik ekibine iletildi.

### 1.5 Değerlendirme Takvimi ve Çıktıları
| Milat | Süre | Sahip | Beklenen Çıktı |
|-------|------|-------|----------------|
| Kitaplık API doğrulaması | 3 gün | Interop Agent | `quinn`/`h3` API'leri ile PoC modül iskeleti (`crates/server/src/quic/listener.rs`). |
| Datagram şeması prototipi | 2 gün | Interop Agent | `QuicDatagramV1` için encode/decode testleri (`tests/tests/http3_datagram.rs`). |
| ALPN + Alt-Svc konfigürasyonu | 2 gün | Platform Agent | `GET /http3/capabilities` uç noktasıyla entegrasyon ve log denetimi. |
| Risk değerlendirme özeti | 1 gün | Security & Identity Agent | 0-RTT, anti-replay ve HSM bağımlılık raporu (`docs/src/operations/http3-quic-security.md`). |

- `Exit criteria`: Tüm çıktılar CI'da `ENABLE_HTTP3_POC=true` koşulu altında yeşile dönmeli, PoC dinleyicisi en az 10k request yük testini tamamlamalı ve datagram encode/decode testleri sıfır hata ile kapanmalıdır.
- `Observation hooks`: `otel` kanalında `pending_auth_requests` ve `active_tokens` metrikleri PoC boyunca %5 sapma sınırını aşmayacak, `audit` kanalında ise tekrar saldırısı girişimleri `DatagramError::IntegrityViolation` log girdisi üretmeyecektir.
- `Dependencies`: `postcard` crate'inin MSRV 1.76 ile uyumu günlük kontrol edilerek sürüm yükseltmelerinde `cargo deny` ve fuzz hedefleriyle regresyon testi yapılacaktır.

2. **PoC Sprinti (Interop + Platform Agent)**
   - `apps/server` içinde HTTP/3 dinleyicisi açan deneysel bir özellik bayrağı (`http3-experimental`) ekle.
   - QUIC datagram kanalını mock telemetri verisiyle besleyen PoC entegrasyonu yaz; `tests/blockchain/` planındaki mock ledger yaklaşımıyla uyumlu olacak şekilde test iskeleti hazırla.
   - Performans karşılaştırması için HTTP/2 ve HTTP/3 isteklerinde p50/p99 gecikme ölçümleri topla.

   **Tamamlanan teslimatlar:**

   - `spawn_http3_poc` fonksiyonu ile `quinn` + `h3` tabanlı UDP dinleyici otomatik açılıyor, self-signed sertifika `rcgen` ile anlık üretiliyor ve bağlantı başına metrik/denetim/ratchet datagramları gönderiliyor.【F:crates/server/src/quic/listener.rs†L21-L170】【F:crates/server/src/state.rs†L741-L811】
   - HTTP/1.1 tarafında `Alt-Svc` başlığı otomatik olarak portu baz alarak ekleniyor; PoC aktifken healthcheck loguna HTTP/3 desteği yazılıyor.【F:crates/server/src/routes.rs†L18-L74】【F:crates/server/src/routes.rs†L95-L123】
   - PoC telemetrisi için üretilen varsayılan datagram yükü 72 bayt; testler hem boyut sınırını hem de kanal eşlemesini doğruluyor.【F:crates/server/src/quic/datagram.rs†L189-L218】【F:tests/tests/http3_datagram.rs†L1-L51】
   - `tests/tests/http3_datagram.rs` entegrasyonu `MAX_WIRE_BYTES` eşiğini korurken OTel snapshot'larının `postcard` üzerinden kararlı şekilde kodlandığını ve aşırı büyük yüklerin reddedildiğini regresyon testi haline getirdi.【F:tests/tests/http3_datagram.rs†L1-L51】

   **Ölçüm Tablosu (PoC senaryosu):**

   | Kanal | İçerik | Ölçülen tel boyutu |
   |-------|--------|---------------------|
   | Telemetry (`DatagramPayload::Otel`) | `pending_auth_requests=3`, `active_tokens=2`, `sfu_contexts=1.0` | 72 bayt (postcard)【F:crates/server/src/quic/datagram.rs†L189-L218】|

   HTTP/2 ve HTTP/3 gecikme kıyasları için üretim ortamında ölçüm yapılması gerekmektedir; PoC kapsamında HTTP/3 yanıtları `/health` ve `/metrics` uçlarında başarıyla servis edilmektedir.【F:crates/server/src/quic/listener.rs†L126-L182】

3. **Sertifikasyon ve Güvenlik Analizi (Security + Identity Agent)**
   - TLS 1.3 gereksinimlerinin HSM destekli anahtar yönetimiyle uyumunu doğrula.
   - QUIC datagram akışlarında bütünlük ve kimlik doğrulama seçeneklerini değerlendir; gerektiğinde paket başına AEAD etiketi zorunluluğu tanımla.
   - RFC 9000, RFC 9114 ve IETF MASQUE önerilerine göre regülasyon ve uyumluluk etkilerini dokümante et.

   **Tamamlanan teslimatlar:**

   - `rustls` istemci sertifikası anahtarlarının HSM (PKCS#11) destekli `aunsorm-kms` imzacısı ile kullanımı doğrulandı; QUIC el
     sıkışması için gerekli `sign` ve `decrement_traffic_keys` çağrıları modül uyumluluk matrisinde belgelenmiştir.【F:docs/src/operations/http3-quic-security.md†L39-L97】
   - QUIC datagramları için `ChaCha20-Poly1305` AEAD katmanı ve kanal bazlı sequence numarası senkronizasyonu tanımlandı; `audit` ve `ratchet` kanalları için tekrar saldırısı koruması zorunlu hale getirildi.【F:docs/src/operations/http3-quic-security.md†L99-L151】
   - Regülasyon iz düşümleri (RFC 9000/9114, ETSI TS 103 523-3) ve SOC 2 denetim maddeleri yeni güvenlik değerlendirme raporunda ilişkilendirildi.【F:docs/src/operations/http3-quic-security.md†L153-L214】

4. **Ürünleştirme ve CI Entegrasyonu (Interop Agent)**
   - CI pipeline’ına `ENABLE_HTTP3_POC` değişkeni altında koşan entegrasyon testleri ekle.
   - Operasyon rehberinde (ops runbook) HTTP/3 aktif etme/geri alma prosedürlerini, gözlemlenebilirlik metriklerini ve hata ayıklama adımlarını güncelle.
   - Canary sürümü sonrasında müşteri geri bildirimleri için Jira/Linear kartlarını bağlayan geri besleme döngüsü oluştur.

   **Tamamlanan teslimatlar:**

   - `ci.yml` içerisine opsiyonel `http3-poc` işi eklendi; değişken `ENABLE_HTTP3_POC=true` olduğunda `aunsorm-server` ve entegrasyon testleri `--features http3-experimental` ile koşturuluyor.【F:.github/workflows/ci.yml†L8-L11】【F:.github/workflows/ci.yml†L117-L140】
   - `docs/src/operations/http3-quic-security.md` runbook bölümü HTTP/3 özelliğini açma/kapatma adımlarını, gözlemlenebilirlik metriklerini ve incident sırasında uygulanacak teşhis rutinlerini belgeliyor.【F:docs/src/operations/http3-quic-security.md†L112-L196】
   - Canary geri besleme akışı için Jira/Linear kartlarının `ops/http3-canary` etiketiyle ilişkilendirilmesi, müşteri raporlarının 24 saat içinde değerlendirilmesi ve sonuçların aynı dokümanda “Feedback Döngüsü” tablosuna işlenmesi kararlaştırıldı.【F:docs/src/operations/http3-quic-security.md†L198-L232】

## Risk ve Bağımlılıklar
- **Kütüphane olgunluğu:** `quiche` ve `h3` sürümlerinin MSRV 1.76 ile uyumluluğu takip edilmelidir.
- **Firewall/NAT engelleri:** UDP tabanlı QUIC trafiğinin kısıtlanabileceği ortamlar için otomatik HTTP/2 geri dönüş mekanizması şarttır.
- **Gözlemlenebilirlik:** QUIC bağlantı istatistiklerinin mevcut OTLP/HTTP metrik boru hattına aktarılması gereklidir; aksi halde gerileme riskleri artar.

## Başarı Ölçütleri
- HTTP/3 PoC testleri CI’da opsiyonel job olarak başarıyla tamamlanır.
- Üretim dışı ortamda 1 hafta boyunca HTTP/3 + QUIC datagram trafiği %99,9 başarıyla ölçülür.
- Sunucu, HTTP/3 desteklemeyen istemcilerde otomatik olarak HTTP/2’ye geri döner ve hata oranı artışı gözlenmez.
