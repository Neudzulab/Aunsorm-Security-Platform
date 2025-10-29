# ACME Domain Doğrulama Kılavuzu

Bu kılavuz, ACME order’larında domain doğrulamasını (HTTP-01, DNS-01, TLS-ALPN-01)
adım adım nasıl yöneteceğinizi ve otomasyonu nasıl devreye alacağınızı açıklar.
Mock sunucu testleri (`tests/src/acme/mock_server.rs`) ve staging pipeline’ı
(`.github/workflows/ci/acme.yml`) aynı akışları doğrulamak için kullanılır.

## Önkoşullar

- ACME hesabı oluşturulmuş ve state dosyası (`account.json`) güncel.
- Domain için sahiplik kanıtı sağlayabileceğiniz HTTP veya DNS altyapısı hazır.
- `aunsorm-cli` sürümü ACME komutlarını destekler (`aunsorm-cli acme --help`).
- DNS-01 için API erişimi olan bir DNS sağlayıcısı (örn. Cloudflare, Route53).

## HTTP-01 Doğrulaması

1. `aunsorm-cli acme order --domain example.org --validation http-01` komutu ile
   order oluşturun.
2. CLI çıktısındaki `authorizations[]` URL’lerini takip edin; her biri bir token
   döndürür.
3. Token için dosya oluşturun:
   ```bash
   TOKEN="<mock-server-token>"
   PAYLOAD="<key-authorization>"
   mkdir -p /var/www/html/.well-known/acme-challenge
   echo "$PAYLOAD" > /var/www/html/.well-known/acme-challenge/$TOKEN
   ```
4. Web sunucusu (nginx/apache) üzerinden dosyanın HTTP ile servis edildiğini
   doğrulayın: `curl http://example.org/.well-known/acme-challenge/$TOKEN`.
5. Validation API’si (`POST /acme/validation/http-01`) ile yayın durumunu ACME
   sunucusuna bildirin. Mock testleri bu uç noktayı pending → valid akışı için
   doğrular.

## DNS-01 Doğrulaması

1. Order oluştururken `--validation dns-01` parametresini kullanın.
2. CLI çıktısında `_acme-challenge.example.org` için TXT kayıt değeri
   (`base64url(key-authorization-digest)`) gösterilir.
3. DNS sağlayıcınızda TXT kaydını oluşturun. Örnek Cloudflare API çağrısı:
   ```bash
   cfcli dns create --type TXT \
     --name _acme-challenge.example.org \
     --content "$TOKEN_VALUE" \
     --ttl 60
   ```
4. Kayıt yayınlandıktan sonra `dig TXT _acme-challenge.example.org` ile TTL ve
   içerik doğrulaması yapın.
5. `POST /acme/validation/dns-01` uç noktası ile ACME sunucusuna bildirip
   challenge’i pending → valid konumuna taşıyın.

## TLS-ALPN-01 Doğrulaması

1. Order oluştururken `--validation tls-alpn-01` seçeneğini ekleyin.
2. CLI, SNI eşleşmesi için self-signed bir sertifika (ACME extension OID) üretir.
3. Sertifikayı `openssl` veya `aunsorm-cli acme tls-alpn-publish` komutu ile
   hedef sunucuya yükleyin.
4. Port 443 üzerinde ALPN `acme-tls/1` desteğinin aktif olduğunu `openssl s_client`
   komutu ile test edin:
   ```bash
   openssl s_client -alpn acme-tls/1 -connect example.org:443
   ```
5. Challenge doğrulaması sonrası sertifika finalize adımına geçin.

## Otomasyon Stratejileri

- **Webhook Tetikleme:** Order oluşturma çıktısı CI pipeline’ına aktarılır ve
  challenge’lar infrastructure-as-code (Terraform, Pulumi) ile otomatik yayınlanır.
- **Secret Yönetimi:** DNS API token’larını `ACME_DNS_TOKEN_*` olarak GitHub
  secrets içinde saklayın; `.github/workflows/ci/acme.yml` secret kontrolü
  eksik konfigurasyonları yakalar.
- **Temizlik:** Challenge tamamlandıktan sonra HTTP dosyalarını ve TXT kayıtlarını
  kaldırın. Mock sunucudaki sad path testi, silinmeyen kayıtların yeni order’larda
  çakışmaya yol açmamasını sağlar.

## İzleme ve Alerting

- DNS TTL değerleri 60 saniye üzerinde ise propagation gecikmesi yaşanabilir;
  finalize öncesi `Retry-After` yanıtlarını gözlemleyin.
- HTTP-01 için CDN cache devre dışı bırakılmalı veya bypass kuralı eklenmelidir.
- Challenge süreci boyunca `aunsorm-server` loglarında `challenge_status` alanı
  takip edilmelidir (`pending`, `processing`, `valid`).
