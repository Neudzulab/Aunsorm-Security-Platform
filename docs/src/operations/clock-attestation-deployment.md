# Clock Attestation Server Deployment Runbook

## 🎯 Amaç

Bu runbook, Aunsorm üretim ortamında clock attestation hizmetinin hatasız şekilde devreye alınması için gereken adımları, kontrol listelerini ve doğrulama prosedürlerini tanımlar. Clock attestation sunucusu, tüm zaman damgası doğrulamalarının tek güvenilir kaynağıdır ve JWT, KMS, ACME ile PQC iş akışlarının tamamında kritik bağımlılıktır.

## 🧱 Mimari Bileşenler

| Bileşen | Rol | Kritik Notlar |
| --- | --- | --- |
| **NTP Attestation Service** | Yetkili zaman damgası üretir ve NEUDZ-PCS + AACM karması ile imzalar. | Container tabanlı dağıtım, `AUNSORM_NATIVE_RNG` entropisini kullanır. |
| **Clock Refresh Service** | Sunucudan taze attestation çeker, `crates/core/src/clock.rs` ile paylaşılan snapshot deposunu günceller. | 15 saniyelik yenileme döngüsü, 30 saniye üstü snapshot'ları reddeder. |
| **Secrets Store** | NTP imzalama anahtarını, kalibrasyon sertifikasını ve bootstrap entropisini saklar. | HSM veya donanım destekli vault önerilir; disk üzerinde düz metin yasaktır. |
| **Monitoring Pipeline** | Attestation tazelenme süresi, imza doğrulama hataları ve stratum sapmalarını izler. | Prometheus exporter + Grafana pano gerektirir. |

## ✅ Ön Koşullar

1. `aunsorm-ntp-server` container imajının registry'de imzalı sürümü (`>=0.5.0`).
2. Üretim `calibration_cert.pem` dosyası ve SHA-256 parmak izi.
3. Vault'ta saklanan `ntp-signing-key.pem`; yalnızca init konteyneri tarafından okunabilir.
4. `AUNSORM_CLOCK_MAX_AGE_SECS=30` politikası için orkestrasyon düzeyi konfigürasyonu.
5. `AUNSORM_CLOCK_REFRESH_URL` ve `AUNSORM_CLOCK_REFRESH_INTERVAL_SECS` değerleri için production ortam değişkenleri (yalnızca HTTPS URL'leri kabul edilir).
6. Prometheus ve Loki endpoint'lerinin yazma izinleri doğrulanmış olmalıdır.

## 🚀 Docker Compose Dağıtımı

```yaml
services:
  ntp-attestation:
    image: registry.aunsorm.local/aunsorm-ntp-server:0.5.2
    restart: always
    user: "1001:1001"
    environment:
      AUNSORM_NATIVE_RNG_SEED_PATH: /secrets/bootstrap-seed.bin
      NTP_AUTHORITY_ID: ntp.prod.aunsorm
      NTP_SIGNING_KEY_PATH: /run/keys/ntp-signing-key.pem
      NTP_STRATUM: "1"
      REFRESH_INTERVAL_SECS: "15"
    secrets:
      - ntp_signing_key
      - rng_bootstrap_seed
    configs:
      - calibration_cert
    healthcheck:
      test: ["CMD", "curl", "-f", "https://127.0.0.1:5443/health"]
      interval: 10s
      timeout: 2s
      retries: 3
    ports:
      - "5443:5443"

  auth-service:
    environment:
      AUNSORM_NTP_URL: https://ntp-attestation:5443/attestation
      AUNSORM_CLOCK_MAX_AGE_SECS: "30"
      AUNSORM_CLOCK_REFRESH_URL: https://ntp-attestation:5443/attestation
      AUNSORM_CLOCK_REFRESH_INTERVAL_SECS: "15"
      AUNSORM_CALIBRATION_FINGERPRINT: "${CALIBRATION_FP}"
    depends_on:
      ntp-attestation:
        condition: service_healthy
secrets:
  ntp_signing_key:
    file: ./secrets/vault-export/ntp-signing-key.pem
  rng_bootstrap_seed:
    file: ./secrets/vault-export/bootstrap-seed.bin
configs:
  calibration_cert:
    file: ./configs/calibration_cert.pem
```

### Dağıtım Adımları

1. **Secret Hazırlığı**: Vault'tan `ntp-signing-key.pem` ve `bootstrap-seed.bin` dosyalarını `./secrets/vault-export` altına çekin; dosya izinlerini `600` olarak ayarlayın.
2. **Kalibrasyon Sertifikası**: Sürüm kontrolünde yer almayan `configs/calibration_cert.pem` dosyasını `scp` ile node'a kopyalayın.
3. **Ortam Değişkenleri**: Compose için `CALIBRATION_FP` değerini `sha256sum configs/calibration_cert.pem` çıktısından alın.
4. **Yayın**: `docker compose --project-name aunsorm-clock up -d` komutu ile servisleri başlatın.
5. **Doğrulama**: `docker compose logs ntp-attestation` çıktısında `Clock attestation ready (max_age=30s)` satırını kontrol edin.

## ☸️ Kubernetes Dağıtımı

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ntp-attestation
  namespace: security
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ntp-attestation
  template:
    metadata:
      labels:
        app: ntp-attestation
      annotations:
        checksum/config: "{{ include \"calibration-config-hash\" . }}"
    spec:
      serviceAccountName: ntp-attestation
      containers:
        - name: server
          image: registry.aunsorm.local/aunsorm-ntp-server:0.5.2
          args: ["--listen", "0.0.0.0:5000"]
          env:
            - name: AUNSORM_NATIVE_RNG_SEED_PATH
              value: /var/run/keys/bootstrap-seed.bin
            - name: NTP_AUTHORITY_ID
              value: ntp.prod.aunsorm
            - name: NTP_SIGNING_KEY_PATH
              value: /var/run/keys/ntp-signing-key.pem
            - name: REFRESH_INTERVAL_SECS
              value: "15"
          volumeMounts:
            - name: signing-key
              mountPath: /var/run/keys
              readOnly: true
            - name: calibration-cert
              mountPath: /etc/aunsorm
              readOnly: true
          ports:
            - containerPort: 5000
          readinessProbe:
            httpGet:
              path: /health
              port: 5000
            periodSeconds: 5
            failureThreshold: 3
      volumes:
        - name: signing-key
          secret:
            secretName: ntp-signing-key
        - name: calibration-cert
          configMap:
            name: calibration-cert
---
apiVersion: v1
kind: Service
metadata:
  name: ntp-attestation
  namespace: security
spec:
  selector:
    app: ntp-attestation
  ports:
    - port: 5000
      targetPort: 5000
      name: http
```

### Helm Values Kontrol Listesi

- `image.tag`: `0.5.2` veya güvenlik güncellemesi içeren daha yeni sürüm.
- `maxAgeSeconds`: `30` (override edilmesi yasak).
- `replicaCount`: `>=2` (aynı availability zone içinde farklı nodlar).
- `podSecurityContext.fsGroup`: `1001`.
- `networkPolicy`: yalnızca yetkili servis hesaplarına 5000/TCP erişimine izin verir.

## 🔐 Güvenlik Kontrolleri

1. **İmzalama Anahtarı**: Sadece init container tarafından okunur; çalışma sırasında bellekte `mlock` ile kilitlenir.
2. **Entropi**: `bootstrap-seed.bin` dosyası `AunsormNativeRng` tarafından tek seferlik seed olarak kullanılır; işletim sistemi RNG'sine doğrudan çağrı yapılmaz.
3. **Kayıt Zinciri**: Tüm attestation yanıtları için `Loki` üzerinden immutable log tutulur.
4. **Yetkilendirme**: Kubernetes servis account'ı `security` namespace'i dışına istek yapamaz.
5. **Saldırı Tespit**: Prometheus alert'i `AttestationStale` metrikleri 20 saniyeyi aşarsa `pagerduty` tetiklenir.

## 📊 Gözlemleme ve Alarmlar

| Metrik | Eşik | Alarm | Açıklama |
| --- | --- | --- | --- |
| `ntp_attestation_round_trip_ms` | > 40 ms (5 dk) | Uyarı | Ağ gecikmesi arttı, mesh kontrol edin. |
| `ntp_attestation_age_ms` | > 30000 ms (3 örnek) | Kritik | Clock Refresh Service güncel snapshot alamıyor. |
| `ntp_attestation_signature_valid` | 0 | Kritik | İmza doğrulaması başarısız oldu; anahtar sızıntısı ihtimali. |
| `ntp_attestation_stratum` | != 1 | Uyarı | Yetkili stratum kaybı, upstream NTP sunucusu doğrulanmalı. |

## 🧪 Doğrulama Adımları

1. `curl -s http://ntp-attestation.security.svc.cluster.local:5000/attestation | jq .` çıktısının `authority_id` alanı `ntp.prod.aunsorm` olmalıdır.
2. `crates/core/src/clock.rs` içindeki `ClockSnapshot::validate_age` fonksiyonu 30 saniyeden eski attestation'ı reddetmelidir; entegrasyon testinde `Clock(StaleAttestation { ... })` beklenir.
3. Uygulama podlarında `AUNSORM_CLOCK_MAX_AGE_SECS=30` değeri için `kubectl exec` ile doğrulama yapın.
4. Loki loglarında `Clock attestation validated` mesajı 15 saniyeden sık görünmelidir.
5. `curl -s http://auth-service.security.svc.cluster.local:50011/health | jq .clock` çıktısında `status="ok"` ve `refreshEnabled=true` değerlerini doğrulayın.

## 🆘 Olay Müdahale

- **Stale Attestation**: Clock Refresh Service yeniden başlatılır, başarısız olursa attestation servisi ölçeklenir.
- **İmza Hatası**: İlgili anahtar derhal `vault` üzerinden revoke edilir, yeni anahtar rotate edilir, servisler `helm upgrade` ile güncellenir.
- **Stratum Drift**: Upstream NTP kaynakları kontrol edilir, `ntpq -p` ile offset analiz edilir.
- **Servis Kesintisi**: `kubectl rollout restart deployment/ntp-attestation -n security` komutu uygulanır; kesinti sırasında uygulamalar `ClockUnavailable` hatası üretir ve işlemler askıya alınır.

## 📎 İlgili Kaynaklar

- `docs/CLOCK_ATTESTATION.md`: Geliştirici rehberi ve yapılandırma örnekleri.
- `crates/core/src/clock.rs`: Attestation doğrulama mantığı.
- `crates/server/src/clock_refresh.rs`: Clock Refresh Service implementasyonu.
- `port-map.yaml`: Attestation servisi için rezerve portlar.
