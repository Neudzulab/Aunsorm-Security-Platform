# KMS/HSM Conformance Raporu

Aunsorm dış KMS ve HSM sağlayıcılarıyla entegre olurken doğrulama ekiplerinin
kullanması için JSON tabanlı fixture setleri ve bunları destekleyen otomatik
rapor üretildi. Fixture dosyaları `tests/fixtures/kms/` dizininde tutulur ve
her biri sağlayıcının FIPS/PCI sertifikasyon kayıtlarına referans verir.

## Fixture Özeti

| Sağlayıcı | Yetkinlik | Sertifikasyon Kaynağı |
| --- | --- | --- |
| Google Cloud KMS | Ed25519 imzalama | [CMVP #4382](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4382) |
| Microsoft Azure Key Vault | AES-256 anahtar sarma | [CMVP #3575](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3575) |
| PKCS#11 HSM (nShield 5) | Ed25519 imzalama | [CMVP #4429](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4429), [PCI HSM v3 raporu](https://example.com/certifications/pci-hsm-v3-aunsorm.pdf) |

Ek olarak `kms_certification_report.json` dosyası, oluşturulan fixture'ların
tam listesini ve üretim zaman damgasını içerir. Bu rapor CI pipeline'larında
yeni fixture eklemeleri için otomatik doğrulama noktası olarak kullanılabilir.

## Doğrulama Akışı

Aşağıdaki komut, fixture dosyalarının kriptografik tutarlılığını test eder:

```bash
cargo test -p aunsorm-tests --test kms_conformance
```

Testler Ed25519 imza vektörlerini doğrular, AES-256-GCM ile sarılmış
anahtarların geri açılabildiğini denetler ve sertifikasyon raporunun tüm
fixture dosyalarını içerdiğini teyit eder.
