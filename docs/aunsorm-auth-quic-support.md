# REQUEST: Auth Service HTTP/3 QUIC Desteği

**Tarih**: 2026-03-17  
**Talep Eden**: SFU Router (zas-sfu-router-ws)  
**Hedef Servis**: `aun-auth-service` (port 50011)  
**Öncelik**: Orta (HTTP fallback çalışıyor, QUIC audit/telemetry eksik)  
**Referans**: E2EE service (`aun-e2ee-service:50021`) — zaten çalışıyor, aynı pattern

---

## Sorun

```
WARN [AUNSORM-QUIC] Capabilities check failed for http://aun-auth-service:50011:
  HTTP 404 Not Found from http://aun-auth-service:50011/http3/capabilities
```

SFU Router her başlatmada auth service'e QUIC upgrade deniyor ama `/http3/capabilities` endpoint'i yok.
Backoff ile 5s→10s→20s→... denemeye devam ediyor. Auth JWT doğrulaması HTTP ile çalışıyor
ama QUIC datagram channel'ları (telemetry, audit, ratchet) auth tarafında aktif değil.

---

## Yapılacak: 1 Endpoint + 1 Listener

### 1. `GET /http3/capabilities` Endpoint'i

**URL**: `http://aun-auth-service:50011/http3/capabilities`  
**Method**: GET  
**Response**: `200 OK` + `Content-Type: application/json`

```json
{
  "enabled": true,
  "status": "active",
  "alt_svc_port": 50011,
  "alt_svc_max_age": 3600,
  "datagrams": {
    "supported": true,
    "max_payload_bytes": 1150,
    "channels": [
      { "channel": 0, "label": "telemetry", "purpose": "OTel metrics" },
      { "channel": 1, "label": "audit", "purpose": "Auth events" },
      { "channel": 2, "label": "ratchet", "purpose": "Session probes" }
    ]
  }
}
```

**Alanlar:**

| Alan | Tip | Zorunlu | Açıklama |
|------|-----|---------|----------|
| `enabled` | bool | evet | QUIC desteği aktif mi |
| `status` | string | evet | `"active"` veya `"degraded"` |
| `alt_svc_port` | u16 | evet | QUIC UDP dinleme portu (genelde HTTP ile aynı) |
| `alt_svc_max_age` | u32 | hayır | Alt-Svc cache TTL, default 3600 |
| `datagrams.supported` | bool | evet | Datagram desteği var mı |
| `datagrams.max_payload_bytes` | usize | evet | Max datagram boyutu (1150 önerilen) |
| `datagrams.channels` | array | evet | Kanal listesi (3 standart) |

### 2. QUIC UDP Listener

Auth service aynı port (50011) üzerinde QUIC bağlantıları kabul etmeli:

- **ALPN**: `h3` veya `h3-29`
- **TLS**: Self-signed sertifika (Docker internal — router zaten `danger_accept_invalid_certs` kullanıyor)
- **Datagram desteği**: `transport_config.max_datagram_frame_size(Some(1200))`

**Bağlantı sonrası** router şu datagram'ları gönderir:

```
[channel: u8][sequence: u64 BE][payload_type: u64 BE][outcome: u8][subject_len: u8][subject: UTF-8]
```

- **Channel 0 (telemetry)**: OTel metric ölçümleri
- **Channel 1 (audit)**: Auth event logları (login/logout/token refresh)
- **Channel 2 (ratchet)**: Session sağlık probeları

---

## Referans: E2EE Service (Çalışan Örnek)

E2EE service zaten bu pattern'i uyguluyor ve başarılı:

```
INFO [AUNSORM-QUIC] Capabilities OK: status=active alt_svc_port=50021
INFO [AUNSORM-QUIC] Datagram channels: 0=telemetry, 1=audit, 2=ratchet
INFO [AUNSORM-QUIC] Connecting to https://aun-e2ee-service:50021
INFO [AUNSORM-QUIC] Connected! ALPN=Some("h3") RTT=1ms
INFO [AUNSORM-QUIC][e2ee] audit seq=2 type=... outcome=0 subject=system@aunsorm
```

E2EE service kodunu birebir kopyalayabilirsiniz.

---

## Hızlı Çözüm (Sadece 404'ü Susturmak)

QUIC desteği hemen gerekmiyorsa, sadece capabilities endpoint'i `enabled: false` döndürsün:

```json
{
  "enabled": false,
  "status": "not_implemented",
  "alt_svc_port": 0
}
```

Router `enabled: false` gördüğünde QUIC upgrade denemez ve WARN logları durur.

---

## Router Tarafı (Zaten Hazır)

Router'da yapılacak bir şey yok. Client kodu hazır:

| Bileşen | Durum | Kod |
|---------|-------|-----|
| Capabilities discovery | Hazır | `router/src/aunsorm_quic.rs` L345-365 |
| QUIC connect | Hazır | `router/src/aunsorm_quic.rs` L467-530 |
| Datagram loop | Hazır | `router/src/aunsorm_quic.rs` L550+ |
| Retry/backoff | Hazır | 5s→10s→20s→40s (exponential) |
| JSON parsing | Hazır | `Http3Capabilities` struct L163-182 |

---

## Docker Compose (Zaten Ayarlı)

```yaml
# compose.yaml - mevcut ayarlar
ZASIAN_QUIC_AUTH_URL: https://aun-auth-service:50011
AUNSORM_AUTH_URL: http://aun-auth-service:50011
```

Ek port expose gerekmez — aynı 50011 portu TCP (HTTP) + UDP (QUIC) kullanır.

---

## Test

Auth service deploy edildikten sonra:

```bash
# 1. Capabilities check
curl http://aun-auth-service:50011/http3/capabilities
# Beklenen: {"enabled":true,"status":"active","alt_svc_port":50011,...}

# 2. Router loglarını kontrol et
docker logs zas-sfu-router-ws 2>&1 | grep "AUNSORM-QUIC"
# Beklenen: "Capabilities OK: status=active alt_svc_port=50011"
# Beklenen: "Connected! ALPN=Some(\"h3\")"
# Beklenen: "[auth] audit seq=..." (datagram akışı)

# 3. WARN logları gitmeli
docker logs zas-sfu-router-ws 2>&1 | grep "Capabilities check failed"
# Beklenen: Yeni logda artık yok
```

---

## Zaman Tahmini

| İş | Süre |
|----|------|
| `GET /http3/capabilities` endpoint | 30dk |
| QUIC listener (Quinn/h3 crate) | 2-4 saat |
| Datagram handler (3 channel) | 1-2 saat |
| Test + Docker rebuild | 1 saat |
| **Toplam** | **~1 gün** |

Hızlı çözüm (sadece `enabled: false` dönmek) = 15 dakika.
