# aunsorm-id

`aunsorm-id`, Git HEAD bilgisinden türetilmiş, projeler arası paylaşılabilir
benzersiz kimlikler üretmek için kullanılacak yardımcı kütüphanedir. Jeneratör,
HEAD karmasını parmak izi olarak kodlar, mikro saniye hassasiyetli zaman damgası
ve süreç entropisi ile çakışmayı engeller. Kimlikler `aid.<namespace>.<head>.<payload>`
biçiminde URL dostu olarak üretilir.

## Özellikler

- HEAD karmasını baz alan deterministik parmak izi.
- Monotonik mikro saniye zaman damgası ve atomik sayaç ile çakışmasız üretim.
- Ortak API ile ortam değişkenlerinden HEAD bilgisini çekme desteği.
- Kimliklerin çözümlenmesi ve doğrulanması için `HeadStampedId::parse` yardımı.

## Kullanım

```rust
use aunsorm_id::HeadIdGenerator;

let generator = HeadIdGenerator::with_namespace("0123456789abcdef", "inventory").unwrap();
let head_id = generator.next_id().unwrap();
assert!(head_id.as_str().starts_with("aid.inventory."));
```

Daha fazla örnek için [rustdoc](https://docs.rs/aunsorm-id/latest) belgelerine
bakabilirsiniz.
