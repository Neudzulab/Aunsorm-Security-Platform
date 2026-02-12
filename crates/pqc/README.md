# aunsorm-pqc

## Servisin Görevi
PQC servisi, ML-KEM anahtar kapsülleme ve SLH-DSA / ML-DSA imzalama/verifikasyon işlemlerini sağlar. Algoritmalar `ml-kem-*`, `slh-dsa-*`, `ml-dsa-*` biçiminde isimlendirilir ve strict kipte desteklenmeyen seçenekler reddedilir.

## Portlar
- **50018** — PQC HTTP API

## Örnek İstek/Response
```bash
curl -X POST http://${HOST:-localhost}:50018/pqc/encapsulate \
  -H "Content-Type: application/json" \
  -d '{"algorithm":"ml-kem-768","publicKey":"BASE64_PUBLIC_KEY"}'
```

```json
{
  "algorithm": "ml-kem-768",
  "ciphertext": "BASE64_CIPHERTEXT",
  "sharedSecret": "BASE64_SECRET"
}
```

## Güvenlik Notları
- Paylaşılan sırlar `Zeroizing` yapılarıyla tutulur; düz metin bırakılmaz.
- Strict kip etkinse fallback kabul edilmez ve `StrictRequired` hatası döner.
- Tüm rastgelelik `AunsormNativeRng` ile üretilir; HTTP veya stdlib RNG'leri yasaktır.
- Pozitif ve negatif senaryolar için kapsamlı testler zorunludur.
