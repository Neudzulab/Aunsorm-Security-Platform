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

## Gözlemlenebilirlik
- `AUNSORM_LOG` (veya `RUST_LOG`) ortam değişkeni ile log seviyesi yapılandırılabilir.
- `aunsorm-server` varsayılan olarak renkli, RFC3339 zaman damgalı loglar üretir.
- `otel` özelliği etkinleştirildiğinde ve `AUNSORM_OTEL_ENDPOINT` (ya da `OTEL_EXPORTER_OTLP_ENDPOINT`)
  tanımlandığında, OTLP/HTTP üzerinden OpenTelemetry izleri yayımlanır.
