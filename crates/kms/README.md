# aunsorm-kms

## Servisin Görevi
KMS servisi, anahtar üretimi, rotasyonu ve erişim kontrolünü `BackendKind` arabirimi üzerinden sunar. Strict kipte kalibrasyon ve fingerprint doğrulaması zorunlu tutulur.

## Portlar
- **50014** — KMS API

## Örnek İstek/Response
```bash
curl -X POST http://localhost:50014/kms/keys \
  -H "Content-Type: application/json" \
  -d '{"keyType":"ed25519","strict":true}'
```

```json
{
  "id": "kms-key-01HXXX",
  "algorithm": "ed25519",
  "publicKey": "MCowBQYDK2VwAyEAc0Zq..."
}
```

## Güvenlik Notları
- `AunsormNativeRng` ile üretilen anahtarlar zeroization dostu yapılardan geçirilir.
- Fallback yalnızca `AUNSORM_KMS_FALLBACK=1` ve strict kapalı olduğunda denenir; aksi durumda anlamlı hata döner.
- JSON yapılandırma hataları açıklayıcı mesajlarla raporlanır.
- Rustdoc örnekleri ve testler hem yerel backend'i hem strict kipini kapsar.
