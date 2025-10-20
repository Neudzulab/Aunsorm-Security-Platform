# OAuth Web Entegrasyonu Rehberi

Aunsorm Server'ın `/oauth` uçları RFC 6749 (Authorization Code) ve RFC 7636
(PKCE) gereksinimlerine göre uygulanır. Bu rehber, web istemcilerinin yeni
`AunsormOAuthClient` yardımcı sınıfını kullanarak güvenli bir şekilde
state/PKCE üretmesi, yetkilendirme kodlarını alması ve erişim belirtecine
çevirmesi için adım adım yönergeler sunar.

## Gereksinimler

- HTTPS üzerinden barındırılan bir Aunsorm Server örneği
- Yetkili bir `client_id` ve kayıtlı `redirect_uri`
- Tarayıcı veya Node.js ortamında `fetch`, `crypto.subtle` ve
  `crypto.getRandomValues` desteği
- Opsiyonel ancak tavsiye edilen: `sessionStorage` veya eşdeğer bir
  anahtar-değer deposu

## Yardımcı Sınıfın Genel Yapısı

`apps/web/lib/oauth-client.ts` dosyası aşağıdaki bileşenleri sağlar:

- `generateCodeVerifier` ve `computeCodeChallenge`: PKCE `S256` değerlerini üretir.
- `generateState`: CSRF koruması için base64url `state` üretir.
- `MemoryStore`: Testler veya sunucu-side render senaryoları için basit bir
  anahtar-değer deposu.
- `AunsormOAuthClient`: PKCE + state akışını ve token saklamayı orkestre eder.

Tüm fonksiyonlar deterministik testler yazılabilmesi için dış bağımlılıkları
(crypto, random, fetch, storage) enjekte edilebilir şekilde tasarlanmıştır.

## Hızlı Başlangıç

```typescript
// Monorepo yolu örnektir; kendi proje yapınıza göre import yolunu değiştirin.
import { AunsormOAuthClient, MemoryStore } from './apps/web/lib/oauth-client.js';

const oauth = new AunsormOAuthClient({
  baseUrl: 'https://auth.example.com',
  storage: typeof window === 'undefined' ? new MemoryStore() : sessionStorage,
});

async function beginLogin() {
  const { state, code } = await oauth.beginAuthorization({
    clientId: 'webapp-123',
    redirectUri: 'https://app.example.com/callback',
    scope: 'read write',
  });

  console.info('PKCE flow started', { state, code });
}

function handleCallback(url: string) {
  const { code } = oauth.handleCallback(url);
  return oauth.exchangeToken({
    code,
    clientId: 'webapp-123',
    redirectUri: 'https://app.example.com/callback',
  });
}
```

### Adım 1 — Yetkilendirme İsteği

`beginAuthorization` çağrısı aşağıdaki işlemleri otomatik yapar:

1. 64 karakterlik PKCE `code_verifier` oluşturur ve `code_challenge`
   (SHA-256 + base64url) hesaplar.
2. 32 karakterlik base64url `state` üretir ve depoya yazar.
3. `/oauth/begin-auth` uç noktasına RFC 6749 uyumlu payload gönderir.
4. Yanıttaki `state` değerinin beklenenle eşleştiğini doğrular.

### Adım 2 — Callback Doğrulaması

`handleCallback`, URL sorgu parametrelerindeki `state` değerini depoda tutulan
beklenen değer ile karşılaştırır. Eşleşmezse CSRF şüphesiyle hata yükseltilir.
Başarılı senaryoda yetkilendirme kodu döndürülür.

### Adım 3 — Token Değişimi

`exchangeToken`, depoda saklanan `code_verifier` ile `/oauth/token` uç
noktasına `authorization_code` isteği gönderir. Başarılı yanıt sonrası:

- `access_token` varsayılan olarak `aunsorm.oauth.access_token` anahtarıyla
  depoda tutulur.
- `state` ve `code_verifier` kayıtları temizlenir (tekrar kullanım engeli).

## Güvenlik Tavsiyeleri

- `baseUrl` yalnızca HTTPS olmalıdır; sadece yerel geliştirme için `http://localhost`
  istisnası desteklenir.
- `sessionStorage` yerine HttpOnly cookie tercih edilmek istenirse `storage`
  adaptörünü uygulayan özel bir sınıf yazılabilir.
- Her yetkilendirme kodu tek kullanımlıktır; `exchangeToken` başarıyla döndükten
  sonra depolanan veriler otomatik temizlenir.

## Testler

- Frontend birim testleri: `npm test` komutu `apps/web/lib/oauth-client.test.ts`
  dosyasındaki Vitest senaryolarını çalıştırır. Testler state uyumsuzluğu ve
  token saklama davranışını doğrular.
- Sunucu entegrasyon testleri: `cargo test --all-features` çalıştırıldığında
  `tests/tests/oauth_rfc_compliance.rs` içindeki `state_is_bound_to_authorization_code`
  senaryosu, state bilgisinin yetkilendirme kodu ile birlikte saklandığını ve
  tekrar kullanımın engellendiğini doğrular.

## İlgili Belgeler

- [OAuth API OpenAPI Şeması](./oauth-openapi.md)
- [OAuth + PKCE istek analizi](../oauth-aunsorm-integration-request.md)
- [Sunucu README OAuth bölümü](../../README.md)
