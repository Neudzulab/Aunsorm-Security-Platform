# KMS Conformance Raporu

Bu rapor, harici sağlayıcılar için oluşturulan Ed25519 conformance
fixture'larını ve beklenen sonuçları özetler. Tüm vektörler
`crates/kms/tests/data/` dizininde JSON olarak sunulmuş ve entegrasyon
testleri ile doğrulanmıştır.

## Özet Tablosu

| Sağlayıcı | Fixture Dosyası | Mesaj (Base64) | İmza (Base64) | KID (SHA-256) |
| --- | --- | --- | --- | --- |
| GCP Cloud KMS | `gcp_conformance.json` | `QXVuc29ybSBHQ1AgS01TIENvbmZvcm1hbmNlIDIwMjU=` | `X/Mbr+jQGlNYEtCaetB54+c5HBB4j+RQtgg14FPUxe90nn+G6MdYtsKhLgqBFLoNKgKme4GTgKKW3zFATF7iDw==` | `10ba682c8ad13513971e8b56881aab8bd702bb807796eca81932c735a94d6e6d` |
| Azure Key Vault | `azure_conformance.json` | `QXVuc29ybSBBenVyZSBLTVMgQ29uZm9ybWFuY2UgMjAyNQ==` | `uwCf6uB0mFD7CJdYN4qyr6Hm2pG6blVjTV0tqwOVutxqQn13KRizBxQ1cJ7IbINtJ4bxIX8wzNMXcWHcILC3Bw==` | `1325b850c2871916eae203f0efc3c8987f64e5e3cdb27679e6d1fa97808357e6` |
| PKCS#11 HSM | `pkcs11_conformance.json` | `QXVuc29ybSBQS0NTMTEgS01TIENvbmZvcm1hbmNlIDIwMjU=` | `OgEo0b9unObsHgKjZv2PbfHUUhgRKd6fR09tUnJ5/0+fk0Fvuu2cYm0ka9PuUUKa9Q8uDMpitKYB7nl/v85uBg==` | `6c8f8607dbe87077a62a2990ce07d94aaf749df76f87b98eb786a6d10f030765` |

## Sertifikasyon Notları

- Vektörler PyNaCl referans implementasyonu ile üretildi ve
aunsorm-kms testleri tarafından yeniden imzalanarak doğrulandı.
- `azure_conformance.json` örneği, Azure REST API'nin `sign`
  uç noktasıyla birebir uyumlu alanlar içerir.
- `pkcs11_conformance.json`, HSM üreticilerinin conformance
  testlerinde tekrar kullanılabilecek deterministik bir seed
  ve beklenen `kid` özetini sağlar.
- Her fixture dosyası, tam mesaj heksadesimal gösterimini de
  içererek çevrimdışı incelemelerde kolaylık sağlar.
