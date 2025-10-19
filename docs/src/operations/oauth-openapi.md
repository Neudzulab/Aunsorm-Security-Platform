# OAuth API OpenAPI Şeması

Aunsorm Server'ın OAuth 2.0 yetkilendirme uçları RFC 6749 ve RFC 7636 (PKCE)
kurallarına göre uygulanır. Bu belge, istemci entegrasyon ekiplerinin
(`/oauth/begin-auth`, `/oauth/token`, `/oauth/introspect`, `/oauth/jwks.json`
ve `/oauth/transparency`) uçlarını tek bir OpenAPI 3.1 şeması üzerinden tüketip
otomatik istemci üretimi yapabilmesi için hazırlanmıştır.

## Redirect URI Kayıt Süreci

Redirect URI doğrulaması `ServerState` yapılandırması sırasında tanımlanan
istemci kayıtlarına dayanır. Varsayılan konfigürasyon, `aunsorm-server`
çalıştırılırken `ServerConfig::new` çağrısı ile yüklenir ve her kayıt aşağıdaki
parametreleri içerir:

- `client_id`: RFC 6749 §2.2 tanımıyla eşleşen istemci kimliği.
- `allowed_redirects`: HTTPS kökenli (ve yalnızca yerel geliştirme için HTTP
  localhost) geri dönüş URL'leri listesi.
- `allowed_scopes`: Yetkilendirme isteği sırasında talep edilebilecek kapsamlar.

Yeni bir istemci eklemek için yapılandırma dosyanıza veya `ServerConfig`
oluşturma kodunuza aşağıdaki örnekle aynı kalıpta bir kayıt ekleyin:

```rust
let mut clients = HashMap::new();
clients.insert(
    "docs-client".to_owned(),
    OAuthClient::new(
        vec![
            "https://docs.example.com/oauth/callback".to_owned(),
            "http://localhost:5173/callback".to_owned(),
        ],
        vec!["read".to_owned(), "write".to_owned()],
    ),
);
```

Sunucu tarafında kayıt altına alınmayan bir `redirect_uri` değeri ile
`/oauth/begin-auth` çağrıldığında yanıt `400 Bad Request` ve
hata kodu `invalid_redirect_uri` olacaktır.

## OpenAPI 3.1 Şeması

Aşağıdaki şema istemci oluşturma araçları (Swagger Codegen, Stoplight Studio,
auto-generated SDK'lar vb.) tarafından doğrudan kullanılabilir.

```yaml
openapi: 3.1.0
info:
  title: Aunsorm OAuth API
  version: 0.4.5
  description: |
    OAuth 2.0 Authorization Code + PKCE uçları ile JWKS ve şeffaflık günlüklerine
    erişim sağlar. Tüm yanıtlar JSON formatındadır ve RFC 6749 hata şemaları
    izlenir.
servers:
  - url: https://aunsorm.example.com
    description: Production Aunsorm Server
  - url: https://localhost:8080
    description: Local development server
paths:
  /oauth/begin-auth:
    post:
      tags: [OAuth]
      summary: Başlatılmış PKCE yetkilendirme isteği oluştur
      description: |
        RFC 6749 §4.1 ve RFC 7636 gereğince PKCE (`S256`) destekli
        yetkilendirme kodu üretir. `redirect_uri` değeri istemci kaydında listelenmiş
        olmalıdır.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/BeginAuthRequest'
      responses:
        '200':
          description: Authorization code başarıyla oluşturuldu
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/BeginAuthResponse'
        '400':
          description: RFC 6749 uyumlu doğrulama hatası (örn. scope, redirect_uri)
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '401':
          description: İstemci kaydı bulunamadı (`invalid_client`)
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '422':
          description: JSON gövdesi eksik alanlar nedeniyle ayrıştırılamadı
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
  /oauth/token:
    post:
      tags: [OAuth]
      summary: Authorization code'u erişim belirtecine çevir
      description: |
        Tek kullanımlık yetkilendirme kodunu doğrular, PKCE `code_verifier`
        kontrolünü yapar ve Bearer erişim belirteci üretir.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/TokenRequest'
      responses:
        '200':
          description: Bearer access token üretildi
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TokenResponse'
        '400':
          description: Yetkilendirme kodu veya PKCE doğrulaması başarısız
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '401':
          description: İstemci kimliği eşleşmedi (`invalid_client`)
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '422':
          description: JSON gövdesi eksik alanlar nedeniyle ayrıştırılamadı
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
  /oauth/introspect:
    post:
      tags: [OAuth]
      summary: Erişim belirtecinin geçerliliğini sorgula
      description: |
        RFC 7662'ya benzer şekilde token doğrulaması yapar. Token geçerliyse
        kapsam ve konu bilgilerini döner, süresi dolmuş token için `active=false`
        yanıtı üretir.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/IntrospectRequest'
      responses:
        '200':
          description: Introspection sonucu
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/IntrospectResponse'
        '400':
          description: Token doğrulanamadı
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
  /oauth/jwks.json:
    get:
      tags: [OAuth]
      summary: JSON Web Key Set'i döndür
      description: RFC 7517 uyumlu JWK anahtar listesini sağlar.
      responses:
        '200':
          description: JWKS listesi
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Jwks'
  /oauth/transparency:
    get:
      tags: [OAuth]
      summary: Şeffaflık günlüğü anlık görüntüsünü döndür
      description: Yetkilendirme günlük kayıtlarını ve yayınlanan JWK'ları içerir.
      responses:
        '200':
          description: Şeffaflık günlüğü verileri
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TransparencySnapshot'
components:
  schemas:
    BeginAuthRequest:
      type: object
      required:
        - client_id
        - redirect_uri
        - code_challenge
        - code_challenge_method
      properties:
        subject:
          type: string
          description: Kullanıcıya ait opsiyonel konu ipucu.
          example: alice
        client_id:
          type: string
          minLength: 1
          description: Kayıtlı OAuth istemci kimliği.
          example: demo-client
        redirect_uri:
          type: string
          format: uri
          description: Kayıtlı bir redirect URI.
          example: https://app.example.com/callback
        state:
          type: string
          description: CSRF koruması için istemci tarafından sağlanan opaque değer.
          example: csrf-token-123
        scope:
          type: string
          description: Boşlukla ayrılmış izin listesi.
          example: read write
        code_challenge:
          type: string
          minLength: 43
          maxLength: 86
          description: Base64url kodlu SHA-256 PKCE challenge değeri.
        code_challenge_method:
          type: string
          enum: [S256]
          description: Yalnızca S256 yöntemi desteklenir.
    BeginAuthResponse:
      type: object
      required:
        - code
        - expires_in
      properties:
        code:
          type: string
          description: Tek kullanımlık authorization code.
          example: 4f2d5a4e9b1c4a6f
        state:
          type: string
          nullable: true
          description: İstemci tarafından gönderilen state değeri.
        expires_in:
          type: integer
          format: int64
          description: Kodun saniye cinsinden geçerlilik süresi.
          example: 600
    TokenRequest:
      type: object
      required:
        - grant_type
        - code
        - code_verifier
        - client_id
        - redirect_uri
      properties:
        grant_type:
          type: string
          enum: [authorization_code]
        code:
          type: string
          description: `/oauth/begin-auth` tarafından döndürülen authorization code.
        code_verifier:
          type: string
          minLength: 43
          maxLength: 128
          description: PKCE verifier değeri.
        client_id:
          type: string
          description: Kayıtlı OAuth istemci kimliği.
        redirect_uri:
          type: string
          format: uri
          description: Authorization isteğinde kullanılan redirect URI.
    TokenResponse:
      type: object
      required:
        - access_token
        - token_type
        - expires_in
      properties:
        access_token:
          type: string
          description: Bearer token (JWT).
        token_type:
          type: string
          enum: [Bearer]
        expires_in:
          type: integer
          format: int64
          description: Tokenin saniye cinsinden geçerlilik süresi.
    IntrospectRequest:
      type: object
      required:
        - token
      properties:
        token:
          type: string
          description: Doğrulanacak Bearer erişim belirteci.
    IntrospectResponse:
      type: object
      required:
        - active
      properties:
        active:
          type: boolean
          description: Token hâlen geçerli mi?
        scope:
          type: string
          nullable: true
        client_id:
          type: string
          nullable: true
        username:
          type: string
          nullable: true
          description: Subject claim değeri.
        token_type:
          type: string
          nullable: true
          enum: [Bearer]
        exp:
          type: integer
          format: int64
          nullable: true
          description: UNIX epoch saniye cinsinden son kullanma zamanı.
        iat:
          type: integer
          format: int64
          nullable: true
        iss:
          type: string
          nullable: true
        aud:
          type: string
          nullable: true
        sub:
          type: string
          nullable: true
        jti:
          type: string
          nullable: true
    ErrorResponse:
      type: object
      required:
        - error
        - error_description
      properties:
        error:
          type: string
          description: RFC 6749 hata kodu.
          example: invalid_redirect_uri
        error_description:
          type: string
          description: İnsan tarafından okunabilir hata mesajı.
    Jwks:
      type: object
      required:
        - keys
      properties:
        keys:
          type: array
          items:
            $ref: '#/components/schemas/JsonWebKey'
    JsonWebKey:
      type: object
      description: RFC 7517 JWK tanımı (Ed25519 anahtarları dahil).
      required:
        - kty
        - use
        - crv
        - x
        - kid
      properties:
        kty:
          type: string
          example: OKP
        use:
          type: string
          example: sig
        crv:
          type: string
          example: Ed25519
        x:
          type: string
          description: Base64url kodlu genel anahtar değeri.
        kid:
          type: string
          description: Anahtar tanımlayıcısı.
        alg:
          type: string
          nullable: true
          description: Kullanılan imza algoritması (örn. EdDSA).
    TransparencySnapshot:
      type: object
      properties:
        transcript_hash:
          type: string
          nullable: true
          description: Günlüğün opsiyonel transcript karması.
        entries:
          type: array
          items:
            $ref: '#/components/schemas/TransparencyLogEntry'
    TransparencyLogEntry:
      type: object
      required:
        - index
        - timestamp
        - event
        - hash
      properties:
        index:
          type: integer
          format: int64
        timestamp:
          type: integer
          format: int64
          description: UNIX epoch saniyesi.
        event:
          $ref: '#/components/schemas/TransparencyEvent'
        hash:
          type: string
          description: Kayıt karması (hex).
        previous_hash:
          type: string
          nullable: true
          description: Zincirdeki bir önceki kaydın karması.
    TransparencyEvent:
      oneOf:
        - type: object
          required: [kind, jwk]
          properties:
            kind:
              type: string
              const: key_published
            jwk:
              $ref: '#/components/schemas/JsonWebKey'
        - type: object
          required: [kind, jti, expires_at]
          properties:
            kind:
              type: string
              const: token_issued
            jti:
              type: string
            subject_hash:
              type: string
              nullable: true
            audience:
              type: string
              nullable: true
            expires_at:
              type: integer
              format: int64
```
