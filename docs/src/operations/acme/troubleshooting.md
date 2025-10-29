# ACME Sorun Giderme Rehberi

Bu bölüm, ACME order ve yenileme süreçlerinde karşılaşılabilecek tipik
hataları, tespit yöntemlerini ve çözüm adımlarını listeler. Mock sunucu testleri
ve staging job’ı, sorunların erken tespiti için güvenlik ağı sağlar.

## Yaygın Hatalar

| Belirti | Olası Neden | Çözüm |
| --- | --- | --- |
| `urn:ietf:params:acme:error:rejectedIdentifier` | Domain whitelist’e eklenmemiş veya DNS kaydı hatalı | `tests/src/acme/mock_server.rs` sad path senaryosu aynı hatayı üretir. Domain’i `MockAcmeServer::with_allowed_domains` listesine ekleyin veya gerçek sistemde doğrulanmış alanı order’a ekleyin. |
| `urn:ietf:params:acme:error:userActionRequired` | Kullanım şartları kabul edilmedi | CLI’da `--accept-terms` parametresini ekleyin; mock happy path testinde bu bayrak zorunludur. |
| `Replay-Nonce` eksik | Reverse proxy başlığı sıyırıyor veya yanıt cache’leniyor | Proxy’de `Replay-Nonce` başlığını koruyacak kural ekleyin; `.github/workflows/ci/acme.yml` secrets kontrolü sonrası `cargo test ... mock_server` ile doğrulayın. |
| Finalize sonrası `pending` durumunda kalma | Challenge tamamlanmadı veya DNS propagation gecikmesi | `docs/src/operations/acme/domain-validation.md` adımlarını tekrar gözden geçirin, DNS TTL değerlerini düşürün. |
| Sertifika indirilemedi (`404`) | Order finalize edilmedi veya storage backend erişilemiyor | `aunsorm-server` loglarında `storage_outcome` alanını kontrol edin; finalize adımı tekrar çalıştırın. |

## Log İnceleme

- **Server Logları:** `crates/server` ACME modülü `acme_flow` etiketi ile log yazar.
  `nonce_issue`, `order_create`, `challenge_status` alanları zaman damgası ile
  birlikte gelir.
- **CLI Logları:** `--verbose` parametresi protected header ve payload’ları
  (maskelenmiş) gösterir.
- **CI Pipeline:** ACME staging job’ı başarısız olduğunda `Validate staging secrets`
  adımı eksik konfigurasyon isimlerini raporlar.

## Doğrulama Checklist’i

1. Directory belgesi `https` şeması ile döndü mü?
2. `Replay-Nonce` header’ı 22 karakterlik base64url mi?
3. `Location` başlığı account/order URL’leri için doğru base path’i içeriyor mu?
4. `authorizations[]` sayısı beklenen domain adedine eşit mi?
5. Challenge tamamlandıktan sonra `status=pending` devam ediyorsa finalize
   isteği doğru CSR’i içeriyor mu?

## Kurtarma Prosedürleri

- **Nonce Hataları:** `NonceManager::refresh` çağrıları başarısız olursa cache’i
  temizleyip yeni nonce talep edin. Mock testleri bu akışı doğrular.
- **Order Yeniden Deneme:** ACME API `Retry-After` döndürürse süreye uyun; CLI
  otomasyonu exponential backoff uygular.
- **Hesap Anahtarı Kaybı:** Yeni hesap açıp domain doğrulamasını yeniden yapın.
  Eski account ile imzalanmış order’lar finalize edilemez.
- **CI Sekmeleri:** Staging job’ı secrets eksikliği nedeniyle başarısızsa
  repository Settings → Secrets altında ilgili değerleri güncelleyin ve
  workflow’u yeniden çalıştırın.

## Referanslar

- [ACME Protokol Rehberi](protocol-guide.md)
- [ACME Domain Doğrulama Kılavuzu](domain-validation.md)
- [ACME Gateway Otomasyonu](../acme-gateway-automation.md)
