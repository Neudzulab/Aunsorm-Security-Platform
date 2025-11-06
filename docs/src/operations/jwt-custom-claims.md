# JWT Özel Claim Uyumluluk Rehberi

Bu rehber, Aunsorm Kimlik Servisinin (JWT) "extras" alanında taşınan
özel claim verilerinin nasıl modellenmesi gerektiğini ve doğrulama
motorunun hangi koşullarda isteği reddedeceğini açıklar. Gereksiz
hataları önlemek için burada listelenen kurallara uymanız gerekir.

## Temel İlkeler

- **Standart claim adları** (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`,
  `jti`) "extras" alanında tekrar kullanılamaz. Bu alanlardan herhangi
  biri özel claim haritasında görüldüğünde imzalama ve doğrulama işlemi
  `reserved claim name must not appear in extras` hatası ile durdurulur.
- **Anahtar biçimi:** Tüm özel claim anahtarları camelCase biçiminde ve
  alfasayısal olmalıdır. Alt çizgi (`_`) veya büyük harfle başlamak
  `custom claim keys must be camelCase alphanumeric` hatasını tetikler.
- **JSON derinliği:** İç içe nesne ve dizilerdeki tüm anahtarlar aynı
  camelCase kuralına tabidir. Diziler karma veri türleri içerebilir ancak
  her bir nesnenin anahtarları doğrulanır.
- **Sadece doğrulanmış veriler:** JWT üretmeden önce `Claims::validate_custom_claims`
  çağrılmalıdır. `JwtSigner` ve `JwtVerifier` bileşenleri bunu otomatik
  yapar; elle kullanımda atlanmamalıdır.

## Güvenlik Gerekçesi

1. **İsim çakışmalarını engelleme:** Standart claim isimlerinin
   "extras" alanında yer alması, doğrulama katmanında beklenmeyen
   değerlerin okunmasına neden olabilir. Bu risk, reserved claim
   doğrulaması ile ortadan kaldırılır.
2. **Tutarlı anahtar söz dizimi:** Platform ve istemci SDK'ları camelCase
   sözleşmesini kullanır. Farklı yazım şekilleri serileştirme hataları ve
   imza uyuşmazlıklarına yol açabilir.
3. **Şematik doğruluk:** Derin JSON nesnelerindeki anahtarların da
   denetlenmesi, yalnızca üst seviye anahtar kontrolü yapan legacy
   sistemlere karşı ek koruma sağlar.

## Hata Mesajları

Aşağıdaki tabloda doğrulama sırasında dönebilecek başlıca hata mesajları
ve bunların tetiklendiği koşullar yer alır:

| Hata Mesajı | Koşul |
| --- | --- |
| `reserved claim name must not appear in extras` | Standart claim adı "extras" anahtarları içinde bulunur. |
| `custom claim keys must be camelCase alphanumeric` | Anahtar camelCase değildir veya alfasayısal olmayan karakter içerir. |
| `custom claim keys must be camelCase alphanumeric` | İç içe nesnelerdeki anahtar camelCase değildir. |

> Not: Aynı hata mesajı farklı ihlal türleri için tekrar kullanılır;
> bu nedenle loglarda beraberindeki bağlam (`extras`) alanına dikkat
> edilmelidir.

## Önerilen İş Akışı

1. Claim nesnesini oluşturun ve tüm standart alanları (`iss`, `sub`,
   `aud`, `exp`, `nbf`, `iat`, `jti`) ayarlayın.
2. Özel claim'leri camelCase anahtarlarla `extras` haritasına ekleyin.
3. `Claims::validate_custom_claims` veya `JwtSigner::sign` ile otomatik
   doğrulama yürütüldüğünden emin olun.
4. Hata alırsanız anahtar adlarını ve iç içe nesne yapılarını gözden
   geçirip tekrar deneyin.

Bu rehber, kimlik katmanındaki bütünleşik doğrulama davranışını
belgelendirir ve üretim ortamında log analizi yaparken referans olarak
kullanılmalıdır.
