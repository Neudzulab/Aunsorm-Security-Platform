# Endpoint Validator

`endpoint-validator`, Aunsorm altyapısındaki uzak API servislerini otomatik
olarak keşfetmek ve güvenle çağırmak için tasarlanmış asenkron bir kütüphanedir.
Keşif katmanı OpenAPI belgeleri, sitemap dosyaları ve HTML bağlantılarından
uçları toplarken, yürütme katmanı her uç için `OPTIONS` kontrolü yapar, güvenli
metodları önceliklendirir ve isteklere uygun gövdeleri üretir.

## Temel Yetkinlikler

- OpenAPI 3 şemalarından zorunlu alanları içeren örnek JSON gövdesi üretimi.
- Sitemap ve HTML taramasıyla `/api/*` benzeri yolları otomatik ekleme.
- `OPTIONS` cevabından alınan `Allow` başlığına göre metod seti oluşturma.
- Zaman aşımı, yeniden deneme ve artan geri çekilme (exponential backoff)
  mekanizmaları.
- `text/event-stream` içerik türleri için sınırlı örnek veri toplama.
- Failover raporlaması: durum kodu, gecikme, alıntı ve önerilen düzeltme.

## Kullanım

```rust
use endpoint_validator::{validate, ValidatorConfig};
use url::Url;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let base_url = Url::parse("https://api.example.com")?;
let config = ValidatorConfig::with_base_url(base_url);
let report = validate(config).await?;
println!("{} kontrol tamamlandı", report.results.len());
# Ok(())
# }
```

Daha gelişmiş senaryolarda `ValidatorConfig` üzerinden eş zamanlılık, rate
limit, allowlist, özel `User-Agent` ve ek HTTP başlıkları yapılandırılabilir.

## Yapılandırma Rehberi

`ValidatorConfig::with_base_url` aşağıdaki varsayılanlarla başlar:

- **Eşzamanlılık:** `4` (asgari 1 olacak şekilde ayarlanır).
- **Zaman aşımı:** Her istek için `10s`.
- **Yeniden deneme:** `2` deneme ve `500ms` tabanlı üstel geri çekilme.
- **Rate limit:** Devre dışı (`None`), `Some(0)` verilirse yine devre dışı
  bırakılır.
- **Destructive metodlar:** `false`; `POST/PUT/PATCH/DELETE/CONNECT` istekleri
  yalnızca `include_destructive` `true` olduğunda gönderilir.
- **User-Agent:** `aunsorm-endpoint-validator/0.1`.

Özelleştirmenin tamamı zincirlenebilir setter'lar yerine yapı alanlarını doğrudan
ayarlayarak yapılır. Örnek gelişmiş kullanım:

```rust
use endpoint_validator::{validate, AllowlistedFailure, ValidatorConfig};
use reqwest::header::{HeaderName, HeaderValue};
use url::Url;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let mut config = ValidatorConfig::with_base_url(Url::parse("https://api.example.com")?);
config.include_destructive = true; // Test ortamında tüm metodları dene
config.concurrency = 8;            // Daha yüksek eşzamanlılık
config.rate_limit_per_second = Some(20);
config.additional_headers.push((
    HeaderName::from_static("x-trace-id"),
    HeaderValue::from_static("validator-run"),
));
config.allowlist.push(AllowlistedFailure {
    method: "GET".into(),
    path: "/healthz".into(),
    statuses: vec![503],
});

let report = validate(config).await?;
println!("{} uç kontrol edildi", report.results.len());
# Ok(())
# }
```

İsteğe bağlı olarak `seed_paths` alanına eklenen yollar, keşif katmanından
bağımsız şekilde test kuyruğuna eklenir ve `Allow` yanıtı alınamayan uçlarda bile
istek denenmesine izin verir.
