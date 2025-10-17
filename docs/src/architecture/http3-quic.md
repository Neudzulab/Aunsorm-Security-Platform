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

2. **PoC Sprinti (Interop + Platform Agent)**
   - `apps/server` içinde HTTP/3 dinleyicisi açan deneysel bir özellik bayrağı (`http3-experimental`) ekle.
   - QUIC datagram kanalını mock telemetri verisiyle besleyen PoC entegrasyonu yaz; `tests/blockchain/` planındaki mock ledger yaklaşımıyla uyumlu olacak şekilde test iskeleti hazırla.
   - Performans karşılaştırması için HTTP/2 ve HTTP/3 isteklerinde p50/p99 gecikme ölçümleri topla.

3. **Sertifikasyon ve Güvenlik Analizi (Security + Identity Agent)**
   - TLS 1.3 gereksinimlerinin HSM destekli anahtar yönetimiyle uyumunu doğrula.
   - QUIC datagram akışlarında bütünlük ve kimlik doğrulama seçeneklerini değerlendir; gerektiğinde paket başına AEAD etiketi zorunluluğu tanımla.
   - RFC 9000, RFC 9114 ve IETF MASQUE önerilerine göre regülasyon ve uyumluluk etkilerini dokümante et.

4. **Ürünleştirme ve CI Entegrasyonu (Interop Agent)**
   - CI pipeline’ına `ENABLE_HTTP3_POC` değişkeni altında koşan entegrasyon testleri ekle.
   - Operasyon rehberinde (ops runbook) HTTP/3 aktif etme/geri alma prosedürlerini, gözlemlenebilirlik metriklerini ve hata ayıklama adımlarını güncelle.
   - Canary sürümü sonrasında müşteri geri bildirimleri için Jira/Linear kartlarını bağlayan geri besleme döngüsü oluştur.

## Risk ve Bağımlılıklar
- **Kütüphane olgunluğu:** `quiche` ve `h3` sürümlerinin MSRV 1.76 ile uyumluluğu takip edilmelidir.
- **Firewall/NAT engelleri:** UDP tabanlı QUIC trafiğinin kısıtlanabileceği ortamlar için otomatik HTTP/2 geri dönüş mekanizması şarttır.
- **Gözlemlenebilirlik:** QUIC bağlantı istatistiklerinin mevcut OTLP/HTTP metrik boru hattına aktarılması gereklidir; aksi halde gerileme riskleri artar.

## Başarı Ölçütleri
- HTTP/3 PoC testleri CI’da opsiyonel job olarak başarıyla tamamlanır.
- Üretim dışı ortamda 1 hafta boyunca HTTP/3 + QUIC datagram trafiği %99,9 başarıyla ölçülür.
- Sunucu, HTTP/3 desteklemeyen istemcilerde otomatik olarak HTTP/2’ye geri döner ve hata oranı artışı gözlenmez.
