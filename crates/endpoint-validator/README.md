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
limit, allowlist ve ek HTTP başlıkları yapılandırılabilir.
