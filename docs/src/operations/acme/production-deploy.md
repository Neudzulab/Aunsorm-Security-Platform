# ACME Production Deployment & Rate Limiting Guide

Bu rehber, staging ortamından production'a geçiş sırasında ACME entegrasyonunun
nasıl doğrulanacağını ve Let’s Encrypt rate limit sınırlarına takılmadan nasıl
operasyon yapılacağını açıklar. Rehber; CI pipeline'ı, staging smoke testleri ve
sertifika dağıtım otomasyonuna bağlanan runbook adımlarını içerir.

## Önkoşullar

- `ACME_STAGING_DIRECTORY` — Let’s Encrypt staging directory URL'i.
- `ACME_STAGING_ACCOUNT_KEY` — Base64 (veya URL-safe base64) olarak kodlanmış
  32 baytlık Ed25519 hesap anahtarı seed değeri.
- `ACME_STAGING_CONTACT` — Virgülle ayrılmış `mailto:` veya `tel:` önekli
  iletişim adresleri.
- CI ortamında bu üç değer GitHub Secrets olarak tanımlanmalı; eksik
  konfigurasyonda `.github/workflows/ci/acme.yml` job'u erken hata verir.
- `scripts/deploy_gateway_cert.sh` — Gateway sertifikasını staging veya
  production ortamına dağıtmak için otomasyon betiği.

## Staging Doğrulama Akışı

1. Secrets doğrulaması: `ACME STAGING Smoke` job'u workflow başında gerekli
   secrets değerlerini kontrol eder; eksik değerler `Missing required ACME
   staging secrets` hatası üretir.
2. Mock regression: `cargo test -p aunsorm-tests mock_server -- --nocapture`
   ile deterministik mock server senaryoları çalıştırılır.
3. Staging account roundtrip: `tests/tests/acme_staging.rs` dosyası Let’s Encrypt
   staging API’sine karşı `newAccount` ve POST-as-GET hesabı doğrulaması yapar.
   Test `#[ignore]` olarak işaretlidir; CI job'u `--ignored` parametresiyle
   tetikler. Tüm secrets ayarlanmadıysa test erken `Skipping` mesajıyla çıkar.
4. Başarılı sonuç, staging hesap kontaklarının secrets ile eşleştiğini ve
   nonce rotasyonunun beklendiği gibi çalıştığını garanti eder.

## Production Sertifika Dağıtımı

1. `scripts/deploy_gateway_cert.sh` betiğini staging üzerinde çalıştırarak order
   → finalize → sertifika indirme akışını gözlemleyin.
2. Staging sertifikası beklenen SAN değerlerini içeriyorsa aynı betiği
   production directory URL’i ile (Let’s Encrypt production) tekrar çalıştırın.
3. Yeni sertifikayı gateway’e dağıttıktan sonra aşağıdaki kontrolleri yürütün:
   - `curl https://gateway.example.com/.well-known/acme-challenge/...` HTTP-01
     doğrulamasının temizlendiğini doğrulayın.
   - `openssl s_client -connect gateway.example.com:443 -servername
     gateway.example.com` komutu ile zinciri inceleyin.
4. Dağıtım sonrası `cargo test -p aunsorm-tests --test acme_staging -- --ignored
   --nocapture` komutu (staging secrets ile) tekrar çalıştırılarak regresyon
   doğrulaması yapılabilir.

## Rate Limit Rehberi

Let’s Encrypt production ortamı aşağıdaki başlıca rate limitleri uygular:

| Limit | Açıklama | Politika |
|-------|----------|----------|
| Certificates per Registered Domain | Haftada 50 sertifika | Aynı FQDN için gereksiz order yaratmayın; wildcard kullanımıyla SAN sayısını optimize edin. |
| Duplicate Certificate Limit | Haftada 5 (aynı SAN seti) | Sertifika yenileme otomasyonunda hash karşılaştırması yaparak gereksiz finalize çağrılarını engelleyin. |
| Failed Validation Limit | Saatte 5 (aynı account, aynı domain) | DNS/HTTP otomasyonunda dry-run yaparak doğrulamaya hazır olduğunuzdan emin olun. |
| Account Creation Limit | IP başına 3 yeni hesap/saat | CI pipeline'ı aynı hesap anahtarını kullanarak gereksiz hesap oluşturmayı engeller. |

**Operasyon İpuçları**

- Wildcard SAN'lar ile sertifika sayısını düşürün; staging testleri wildcard
  senaryolarını da kapsayacak şekilde genişletin.
- `tests/tests/acme_staging.rs` testi aynı account key'i tekrar kullanarak rate
  limitlere takılmadan POST-as-GET doğrulaması yapar; production dağıtımı öncesi
  bu davranışı staging üzerinde gözlemleyin.
- Rate limit uyarıları aldığınızda `docs/src/operations/acme/troubleshooting.md`
  belgesindeki `RateLimitExceeded` yanıt analizi bölümüne bakın.

## İzlenebilirlik

- Mock ve staging sonuçları `CHANGELOG.md` dosyasındaki "Added" bölümünde
  not edilir.
- CI job log'ları GitHub Actions üzerinde saklanır; deployment sonrası en az 30
  gün boyunca saklanması önerilir.
- Production sertifika yenilemeleri için order ID ve sertifika URL'lerini
  `certifications/` altındaki audit kayıtlarına ekleyin.
