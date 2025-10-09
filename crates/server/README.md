# aunsorm-server

`aunsorm-server`, Aunsorm güvenlik aracının OAuth/OIDC benzeri uçlarını sağlayan HTTP sunucusudur. PKCE S256 akışını,
EXTERNAL kalibrasyon bağlamını zorunlu kılan JWT üretimini ve JTI tabanlı tekrar saldırısı korumasını bir araya getirir.

## Özellikler
- `/oauth/begin-auth`: PKCE S256 doğrulaması ile yetkilendirme isteği oluşturur.
- `/oauth/token`: Yetkilendirme isteğini koda çevirir ve Ed25519 imzalı erişim belirteci üretir.
- `/oauth/introspect`: Erişim belirtecinin geçerliliğini kontrol eder.
- `/oauth/jwks.json`: Sunucunun JWKS anahtar kümesini döndürür.
- `/health`: Durum kontrolü.
- `/metrics`: Temel metrikler (bekleyen yetkilendirme istekleri ve aktif belirteç sayısı).
- `/sfu/context`: Zasian SFU gibi ortamlar için uçtan uca şifreleme hazır oturum bağlamı üretir.
- `/sfu/context/step`: Mevcut SFU bağlamı için yeni ratchet anahtarını türetir.

## Çalıştırma
Sunucu yapılandırması ortam değişkenlerinden okunur. Minimum yapılandırma örneği:

```bash
export AUNSORM_JWT_SEED_B64="$(openssl rand -base64 32)"
export AUNSORM_JWT_KID="server-1"
export AUNSORM_ISSUER="https://aunsorm.local"
export AUNSORM_AUDIENCE="aunsorm-clients"
cargo run -p aunsorm-server
```

Strict kip (`AUNSORM_STRICT=1`) etkinleştirildiğinde kalıcı bir JTI veritabanı yolu (`AUNSORM_JTI_DB`) belirtilmelidir.

## SFU ve Uçtan Uca Şifreleme Hazırlığı

Gerçek zamanlı medya yönlendirme çözümlerinde (ör. Zasian SFU) istemciler için uçtan uca anahtar
rotasyonunu yönetmek üzere aşağıdaki REST uçlarını kullanabilirsiniz:

- `POST /sfu/context` — `room_id`, `participant` ve isteğe bağlı `enable_e2ee` (varsayılan `true`)
  alanlarını içeren JSON gövdesi ile yeni bir bağlam üretir. Yanıtta bağlam kimliği, süresi
  ve ilk ratchet anahtarı base64url kodlu olarak yer alır.
- `POST /sfu/context/step` — `context_id` alanı ile çağrıldığında aynı bağlam için bir sonraki
  mesaj anahtarını ve nonce değerini döndürür. Bağlam süresi dolduysa RFC 6749 uyumlu hata alırsınız.

Yanıtlarda dönülen anahtarlar direkt olarak SRTP/SFrame benzeri katmanlarda kullanılabilecek
32 baytlık sırlardır; nonce alanı 12 bayttır.

## Gözlemlenebilirlik
- `AUNSORM_LOG` (veya `RUST_LOG`) ortam değişkeni ile log seviyesi yapılandırılabilir.
- `aunsorm-server` varsayılan olarak renkli, RFC3339 zaman damgalı loglar üretir.
- `otel` özelliği etkinleştirildiğinde ve `AUNSORM_OTEL_ENDPOINT` (ya da `OTEL_EXPORTER_OTLP_ENDPOINT`)
  tanımlandığında, OTLP/HTTP üzerinden OpenTelemetry izleri yayımlanır.

## Docker ile Dağıtım

Depo kökünde yer alan `Dockerfile` ile sunucuyu konteyner olarak paketleyebilirsiniz:

```bash
docker build -t aunsorm-server .
docker run --rm -p 8080:8080 \
  -e AUNSORM_JWT_SEED_B64="$(openssl rand -base64 32)" \
  -e AUNSORM_ISSUER="https://aunsorm.local" \
  -e AUNSORM_AUDIENCE="aunsorm-clients" \
  aunsorm-server
```

Konteyner varsayılan olarak `0.0.0.0:8080` adresinde dinler ve loglar `RUST_LOG=info` seviyesindedir.
