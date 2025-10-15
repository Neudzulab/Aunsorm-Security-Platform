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
- Üretilen kimliklerin belirli bir HEAD karması ile eşleştiğini doğrulamak için
  `HeadStampedId::matches_head` denetimi.
- Opsiyonel `serde` özelliği ile kimlikleri JSON stringleri olarak serileştirip
  tekrar çözümlenebilir hale getirme.

## Kullanım

```rust
use aunsorm_id::HeadIdGenerator;

let generator = HeadIdGenerator::with_namespace("0123456789abcdef", "inventory").unwrap();
let head_id = generator.next_id().unwrap();
assert!(head_id.as_str().starts_with("aid.inventory."));
```

Serde desteğini aktifleştirmek için crate'i `serde` özelliği ile derleyebilir
ve kimlikleri doğrudan metin olarak taşıyabilirsiniz:

```rust
use aunsorm_id::HeadStampedId;

# fn demo(id: &HeadStampedId) -> Result<(), serde_json::Error> {
let json = serde_json::to_string(id)?;
let decoded: HeadStampedId = serde_json::from_str(&json)?;
assert_eq!(&decoded, id);
# Ok(())
# }
```

Daha fazla örnek için [rustdoc](https://docs.rs/aunsorm-id/latest) belgelerine
bakabilirsiniz.
