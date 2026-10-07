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

## Keşif verisi ve HTTP origin sınırları

XML okuyucu `roxmltree 0.21.1` kullanır (paketin ilan ettiği MSRV: 1.60).
`quick-xml` bağımlılığı kaldırılmıştır. Bu, tüm çalışma alanının 1.76 ile
artık derlendiği anlamına gelmez; mevcut bağımlılık MSRV görevleri sürüyor.

- OpenAPI, HTML ve her sitemap HTTP yanıtı, gzip açıldıktan sonraki baytlar dahil
  **1 MiB** ile sınırlıdır. UTF-8 dışı keşif metni hata döndürür.
- XML ayrıştırmadan önce ham `<` / `=` sayıları 32.768 / 16.384 ile sınırlanır;
  okuyucunun tahmini kapasite ayırmaları da bu kontrole dahildir.
- Her XML etiketi en çok 4.096 bayt ve 32 öznitelik; iç içe derinlik en çok 32,
  DOM düğümleri en çok 32.768 olabilir. DTD ve dış entity çözümleme kapalıdır.
- `urlset` / `sitemapindex`, namespace olmadan veya standart sitemap 0.9
  namespace'iyle okunur. Escaped karakterler ve CDATA korunur; yinelenen/nested
  `loc`, boş konum ve 2.048 karakteri aşan URL hata döndürür.
- İndeks taraması başlangıç adayları dahil en çok 16 belge, 4 indeks derinliği,
  toplam 8 MiB ve 4.096 benzersiz URL kabul eder. Döngüler yeniden çağrılmaz.
  Zorunlu alt belge başarısızsa kısmi keşif başarı gibi raporlanmaz.
- İndeks ve sitemap URL'leri yapılandırılmış origin içinde olmalı ve URL içine
  kullanıcı/parola koymamalıdır. Aynı-origin yönlendirmeler istek başına en çok
  10 adımla izlenir; diğer origin veya URL credential yönlendirmeleri durdurulur.
- Tohum/OpenAPI/HTML yolları OPTIONS ve doğrulama istekleri başlamadan kontrol
  edilir. Baş slash'larının kaldırılmasıyla `/http://...` gibi bir yolun mutlak
  URL'ye dönüşüp authentication/custom header'ları dışarı taşıması engellenir.
  Geçerli göreli hedefler önceki base-path çözümlemesini korur.

Normal endpoint yanıtları da açılmış veri üzerinden **1 MiB** ile sınırlıdır.
Content-Length ön kontrolüne ek olarak chunked/gzip akışları parça parça okunur;
sınır aşıldığında `ResponseTooLarge` başarısızlığı kaydedilir. Aktarım hatası veya
isteğin toplam `timeout` süresinin dolması `Network` başarısızlığıdır; boş gövde
olarak kabul edilmez. Hata raporu endpoint/method/status bilgisini korur.
HEAD, 204 ve 205 yanıtlarında JSON gövdesi aranmaz.

SSE doğrulaması tam akış doğrulaması değildir: en çok **1.024 bayt** tutulur.
Sınıra ulaşan örnek JSON'da `body_sample: {bytes: 1024, limit: 1024}` ile,
Markdown'da açık bir örnekleme satırıyla raporlanır. Sınırdan önce EOF olursa
örnekleme alanı eklenmez. EOF veya örnek sınırına ulaşmadan takılan SSE isteği
başarısızdır; kısmi örnek hatayı başarıya dönüştürmez. SSE olay semantiği ve
sunucu/backpressure davranışı bu istemci gövde sınırıyla doğrulanmış sayılmaz.
Tutulan buffer sınırlıdır; HTTP/decompression katmanının tek chunk için geçici
ayırmaları bu buffer bütçesine dahil değildir.

```powershell
cargo test -p endpoint-validator --locked -j1
cargo build -p endpoint-validator --example sitemap_fuzz_stdin --locked -j1
python -B fuzz/sitemap_corpus.py
cargo check --manifest-path fuzz/Cargo.toml --bin fuzz_sitemap --locked -j1
```

Fuzz hedefi `fuzz/fuzz_targets/fuzz_sitemap.rs`, kararlı stdin girişi
`examples/sitemap_fuzz_stdin.rs` dosyasıdır. Deterministik korpus uzun süreli
coverage-guided fuzzing yerine geçmez. HTTP regresyonları gerçek yerel
sunucularda aynı-origin/çapraz-origin, namespace, query escape, indeks döngüsü,
zorunlu belge hatası, Content-Length/chunked/gzip boyut ve yol kaçışını sınar.
