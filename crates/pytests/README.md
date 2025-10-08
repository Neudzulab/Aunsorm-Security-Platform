# aunsorm-pytests

`aunsorm-pytests` cratesi, Rust implementasyonunun Python tabanlı Aunsorm v1.01 referansı ile
uyumluluğunu takip eden bilinen cevap testlerini sağlar. Vektörler `vectors/reference.json`
dosyasından yüklenir ve şifre çözme sonuçlarını doğrular.

## Özellikler

- AES-GCM ve ChaCha20-Poly1305 için referans paketleri.
- Strict kip ve ML-KEM-768 ile üretilmiş PQC senaryosu.
- Yanlış kalibrasyon metni ve parola saltı için negatif testler.

## Testleri Çalıştırma

```bash
cargo test -p aunsorm-pytests
```

Tüm testler deterministiktir ve dış bağımlılığa ihtiyaç duymaz.
