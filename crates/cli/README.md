# aunsorm-cli

`aunsorm-cli`, Aunsorm güvenlik araç takımının uçtan uca senaryolarını terminalden
çalıştırmak için sağlanan referans komut satırı aracıdır. EXTERNAL kalibrasyon bağlamını
zorunlu kılar ve üretilen paketleri deterministik zarf dosyalarında saklar.

## Özellikler
- EXTERNAL kalibrasyon metni olmadan paketleri çözemeyen tek-atım şifreleme/deşifre akışı
- PQC anahtarı sunulduğunda ML-KEM kapsüllemeli paket üretimi
- `strict` kip desteği ve AAD sağlama
- Üretilen paketlerin JSON zarf formatında saklanması

## Kullanım
```
cargo run -p aunsorm-cli -- encrypt \
  --password "CorrectHorseBatteryStaple" \
  --in message.bin \
  --out packet.json \
  --org-salt V2VBcmVLdXQuZXU= \
  --calib-text "Neudzulab | Prod | 2025-08"

cargo run -p aunsorm-cli -- decrypt \
  --password "CorrectHorseBatteryStaple" \
  --in packet.json \
  --out plaintext.bin \
  --org-salt V2VBcmVLdXQuZXU= \
  --calib-text "Neudzulab | Prod | 2025-08"
```

## Zarf Formatı
CLI, şifrelenmiş paketi, parola tuzlarını ve kalibrasyon tuzlarını içeren bir JSON
zarfı üretir. Zarf yalnızca deşifre için gereken meta verileri taşır; kalibrasyon metni
ve parola kullanıcı sorumluluğundadır.
