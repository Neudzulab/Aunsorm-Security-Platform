# Zasian × Aunsorm — HTTP/3 QUIC Datagram Entegrasyon Kılavuzu

**Versiyon:** 0.5.0  
**Güncelleme:** 2026-03-14

---

## Özet

Aunsorm `v0.5.0` itibarıyla `aun-auth-service` ve `aun-e2ee-service` aynı TCP portunu UDP/QUIC üzerinden de dinlemektedir. Zasian SFU düşük gecikmeli telemetri ve denetim olaylarını **HTTP/1.1 yerine QUIC datagram kanalı** üzerinden iletebilir.

| Servis            | TCP (HTTP/1.1 + HTTP/2) | UDP (QUIC / HTTP/3) |
|-------------------|------------------------|---------------------|
| `aun-auth-service`  | `:50011`                 | `:50011/udp`          |
| `aun-e2ee-service`  | `:50021`                 | `:50021/udp`          |

---

## 1. Keşif — `/http3/capabilities`

QUIC bağlantısı kurmadan önce aktif port ve datagram limitlerini HTTP/1.1 üzerinden sorgulayın:

```
GET http://aun-e2ee-service:50021/http3/capabilities
```

Örnek yanıt (`enabled: true` ise HTTP/3 aktif):

```json
{
  "enabled": true,
  "status": "active",
  "alt_svc_port": 50021,
  "alt_svc_max_age": 3600,
  "datagrams": {
    "supported": true,
    "max_payload_bytes": 1150,
    "channels": [
      { "channel": 0, "label": "telemetry", "purpose": "OpenTelemetry metrik anlık görüntüsü" },
      { "channel": 1, "label": "audit",     "purpose": "Yetkilendirme denetim olayları" },
      { "channel": 2, "label": "ratchet",   "purpose": "Oturum ratchet ilerleme gözlemleri" }
    ],
    "max_payload_bytes": 1150
  }
}
```

`enabled: false` dönerse HTTP/3 derlenip etkinleştirilmemiş demektir — TCP/HTTP/1.1 akışına devam edin.

---

## 2. Alt-Svc Başlığı ile Otomatik Upgrade

Her HTTP/1.1 yanıtında Aunsorm aşağıdaki başlığı gönderir:

```
alt-svc: h3=":50021"; ma=3600, h3-29=":50021"; ma=3600
```

HTTP/3 destekli bir istemci bu başlığı görünce aynı host:port çiftine QUIC bağlantısı açar. ALPN müzakeresi `h3` veya `h3-29` ile tamamlanır.

---

## 3. QUIC Datagram Formatı

Tüm datagramlar **postcard** codec (Serde tabanlı, `no_std` uyumlu) ile serileştirilir.

### Zarf Yapısı (`QuicDatagramV1`)

```
┌─────────────────────────────────────────────────────────────┐
│ version    : u8   — sabit 1                                 │
│ sequence   : u64  — monoton artan sıra numarası             │
│ timestamp  : u64  — Unix ms (sistem saati)                  │
│ channel    : u8   — 0=Telemetry, 1=Audit, 2=Ratchet         │
│ payload    : enum — kanal türüne göre değişen yük           │
└─────────────────────────────────────────────────────────────┘
```

**Boyut limitleri:**
- Maksimum yük: **1150 bayt**
- Maksimum toplam tel boyutu: **1350 bayt** (başlık dahil)
- Limit aşılırsa `DatagramError::PayloadTooLarge` üretilir ve datagram gönderilmez.

### Kanal 0 — Telemetry (`OtelPayload`)

OpenTelemetry uyumlu metrik anlık görüntüsü. Her 5 saniyede bir otomatik yayınlanır.

```
counters[]  : { name: String, value: u64 }
gauges[]    : { name: String, value: f64 }   ← NaN/Inf reddedilir
histograms[]: { name: String, buckets: [{le: f64, count: u64}], sum: f64, count: u64 }
```

Aunsorm'un yayınladığı ölçümler:

| Metrik adı                     | Tür    | Açıklama                              |
|--------------------------------|--------|---------------------------------------|
| `pending_auth_requests`        | gauge  | Bekleyen PKCE yetkilendirme istekleri |
| `active_tokens`                | gauge  | Aktif erişim belirteci sayısı         |
| `sfu_contexts`                 | gauge  | Aktif SFU oturum bağlamı sayısı       |
| `mdm_registered_devices`       | gauge  | Kayıtlı MDM cihazı sayısı             |

### Kanal 1 — Audit (`AuditEvent`)

```
event_type   : String  — örn. "token_issued", "auth_failed"
subject_hash : String  — SHA-256(subject), PII içermez
outcome      : u8      — 0=Success, 1=Failure, 2=Blocked
timestamp_ms : u64     — olay zamanı
```

### Kanal 2 — Ratchet (`RatchetProbe`)

```
context_id : String  — SFU oturum kimliği
step       : u64     — ratchet adım sayacı
status     : u8      — 0=Ok, 1=Stale, 2=Expired
```

---

## 4. Zasian SFU'nun Datagram Göndermesi

Aunsorm şu an **sadece sunucu → istemci** yönünde datagram yayınlamaktadır. SFU'dan Aunsorm'a datagram gönderimi `v0.6.0` yol haritasındadır.

Mevcut akış:
1. SFU, `aun-e2ee-service:50021` adresine QUIC bağlantısı açar.
2. QUIC bağlantısı `h3` ALPN ile tamamlanır.
3. Aunsorm her 5 saniyede `channel=0` (Telemetry) datagramları gönderir.
4. SFU bu datagramları decode edip Prometheus/Grafana'ya aktarabilir.

### Rust ile Datagram Decode Örneği

```rust
use aunsorm_server::{QuicDatagramV1, DatagramPayload};

fn handle_datagram(raw: &[u8]) {
    match QuicDatagramV1::decode(raw) {
        Ok(dg) => match dg.payload {
            DatagramPayload::Otel(otel) => {
                for g in &otel.gauges {
                    println!("gauge {} = {}", g.name, g.value);
                }
            }
            DatagramPayload::Audit(ev) => {
                println!("audit: {} outcome={}", ev.event_type, ev.outcome as u8);
            }
            DatagramPayload::Ratchet(p) => {
                println!("ratchet step {} status={}", p.step, p.status as u8);
            }
        },
        Err(e) => eprintln!("datagram decode error: {e}"),
    }
}
```

---

## 5. Compose Entegrasyonu (Zasian SFU Tarafı)

Zasian SFU'nun `docker-compose.yml` dosyasına eklenecekler:

```yaml
services:
  sfu:
    # ...mevcut config...
    networks:
      - aunsorm-network
    environment:
      # HTTP/1.1 endpoint'leri (mevcut)
      ZASIAN_WS_AUNSORM_URL: http://aun-auth-service:50011
      ZASIAN_E2EE_URL:        http://aun-e2ee-service:50021

      # HTTP/3 QUIC endpoint'leri (yeni)
      ZASIAN_QUIC_AUTH_URL:   https://aun-auth-service:50011
      ZASIAN_QUIC_E2EE_URL:   https://aun-e2ee-service:50021

networks:
  aunsorm-network:
    external: true
    name: aunsorm-network
```

> ⚠️ QUIC bağlantısı **self-signed sertifika** kullanır (her başlatmada yeniden üretilir).
> İstemci tarafında sertifika doğrulamasını `skip_verify` veya custom trust anchor ile devre dışı bırakın.

---

## 6. Güvenlik Notları

| Konu | Detay |
|------|-------|
| TLS versiyonu | TLS 1.3 zorunlu — eski versiyonlar reddedilir |
| ALPN | `h3`, `h3-29` — müzakere başarısız olursa bağlantı düşer |
| 0-RTT | Sadece iç ağda etkin — dış erişimde devre dışı |
| Sertifika | Ephemeral Ed25519 self-signed — production'da CA sertifikası gelecek (`v0.6.0`) |
| Datagram replay | Sequence numarası monotondur; tekrar oynatma kontrolü istemci sorumluluğundadır |
| Yük boyutu | 1150 bayt üstü reddedilir; fragmentation yoktur |

---

## 7. Hızlı Doğrulama

Servisler ayaktayken HTTP/3 durumunu kontrol edin:

```bash
# E2EE servisinin HTTP/3 kapasite raporu
curl http://localhost:50021/http3/capabilities

# Auth servisinin HTTP/3 kapasite raporu  
curl http://localhost:50011/http3/capabilities

# Beklenen yanıt: "enabled": true, "status": "active"
```

---

## 8. Yol Haritası

| Versiyon | Hedef |
|----------|-------|
| `v0.5.0` ✅ | HTTP/3 PoC dinleyicisi, Alt-Svc başlığı, 3 datagram kanalı |
| `v0.6.0` | SFU → Aunsorm yönlü datagram (çift yönlü), CA sertifikası, Kubernetes UDP |
| `v1.0.0` | Üretim HTTP/3, 0-RTT dış ağ desteği, HSM sertifika imzalama |

---

## İlgili Dosyalar

| Dosya | Konu |
|-------|------|
| [`crates/server/src/quic/listener.rs`](../crates/server/src/quic/listener.rs) | QUIC endpoint ve datagram akış döngüsü |
| [`crates/server/src/quic/datagram.rs`](../crates/server/src/quic/datagram.rs) | `QuicDatagramV1` encode/decode |
| [`tests/tests/http3_poc_ci.rs`](../tests/tests/http3_poc_ci.rs) | Canary entegrasyon testi |
| [`tests/tests/http3_datagram.rs`](../tests/tests/http3_datagram.rs) | Datagram property testleri |
| [`docs/src/architecture/http3-quic.md`](../docs/src/architecture/http3-quic.md) | Mimari dokümantasyon |
| [`docker/compose.zasian-stack.yaml`](../docker/compose.zasian-stack.yaml) | Zasian minimum stack |
