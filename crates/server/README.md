# aunsorm-server

## Servisin Görevi
Aunsorm Server, gateway rolüyle OAuth2/PKCE, JWT üretimi, JTI doğrulaması, cihaz/ID işlemleri ve kalibrasyon kontrollü RNG uçlarını tek bir HTTP katmanında sunar. Tüm yanıtlar JSON veya `text/plain` olarak döner ve kalibrasyon başlıkları zorunlu kılınır.

## Portlar
- **50010** — Genel gateway ve HTTP API

## Örnek İstek/Response
```bash
curl -X POST http://${HOST:-localhost}:50010/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"authorization_code","code":"sample","code_verifier":"verifier","client_id":"cli","redirect_uri":"https://client/callback"}'
```

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile",
  "jti": "example-jti"
}
```

## Güvenlik Notları
- PKCE yalnızca `S256` ile desteklenir; diğer yöntemler reddedilir.
- JTI deposu zorunludur; yoksa doğrulama hatası döner.
- Tüm rastgelelik `AunsormNativeRng` ile üretilir, `OsRng` kullanımına izin verilmez.
- Clock attestation `AUNSORM_CLOCK_MAX_AGE_SECS` ve `AUNSORM_CALIBRATION_FINGERPRINT` ile doğrulanır.

## HTTP/3 ve PCM datagramları
`GET /http3/capabilities` kimlik doğrulaması gerektirmeyen yetenek keşfidir.
`http3-experimental` ile 200, özellik kapalıyken 501 döner; aynı ETag için
`If-None-Match` 304 döndürür. Alan isimleri snake_case olarak korunur.
[OpenAPI sözleşmesi](../../openapi/auth-service.yaml) profili ve yanıtları tanımlar.

Audio kanal 3: 96 kHz, mono PCM S16LE, 960 örnek/10 ms, kare başına 1920 bayt.
`QuicDatagramV1::from_pcm_frame` kareyi iki adet 960 baytlık parçaya böler;
`reassemble_pcm_frame` sıralama değişse bile tam bayt dizisini korur. Eksik,
yinelenen veya akış/zaman/sekans tabanı farklı parçaları reddeder. Bağlantı ve
oturum ayrımı çağıranın sorumluluğudur; yeniden birleştirme yalnız doğrulanmış,
çözülmüş veriye uygulanır. Parça metaverisini AEAD AAD ile doğrulama kapsamına alın.
Şifreli parça gövdesi opaktır; codec PCM örneği gibi yorumlamaz. Bu yardımcılar
resampling veya kayıp tahmini yapmaz. Encode/decode sabit profil, kanal/yük,
parça sınırları, son ek baytlar ve sonlu gauge değerlerini doğrular.

PCM için `QuicDatagramV1::from_pcm_frame_with_fragment_bytes` metodu, çağıranın
nonce/tag/zarf alanını ayırmasına olanak verir. Plaintext parça bütçesi çift sayı
ve **8..=960** bayt olmalıdır; en küçük bütçe bile u8 fragment sayısına sığar.
12 bayt nonce + 16 bayt AES-GCM tag için bütçe **932** olur ve 1.920 baytlık frame
üç parçaya bölünür. Varsayılan `from_pcm_frame` iki 960 baytlık parçayı korur;
bu parçalara ayrıca zarf eklemek mevcut shard sınırını aşar.

Gerçek AES-GCM ve AunsormNativeRng testleri zarf bütçesini, yeniden sıralama/
sequence wrap, eksik parça ve metadata/oturum bağlamı değişikliklerini doğrular.
Testin domain-separated AAD düzeni üretim protokolü değildir. Üretimde oturum
kimliği, key/nonce yaşam döngüsü ve replay durumu ayrıca gözden geçirilmelidir;
AEAD doğrulaması tek başına daha önceki geçerli frame'in tekrarını engellemez.

## QUIC reconnect grace kimliği
Grace kaydı yalnız bellekte tutulur. Alanlar ayraçlarla birleştirilmez; typed
anahtar `None` ile literal değerleri ve JTI'ın tam baytlarını ayırır. Kayıt
issuer, doğrulanan audience ve normalize edilmiş imzalı token'ın SHA-256
özetine bağlıdır. Aynı JTI'a sahip farklı geçerli imzalı token grace kullanamaz;
aynı token'ın izin verilen bağlamdaki retry işlemi mevcut süre kuralını korur.
Grace kabulünden hemen önce aktif ledger tekrar kontrol edilir; iptal/süre dolumu
ve ledger hatası kabulü engeller. İkinci imza kontrolü store tüketimi yapmaz;
nonblank JTI, önceki tüketim ve aynı token grace kaydı yine zorunludur.
Kalıcı JTI ledger kodlaması bu düzeltmeyle değiştirilmez. Kalıcı geçiş tasarımı
[replay-ledger-migration-design.md](../../docs/research/replay-ledger-migration-design.md)
dosyasındadır; eski kayıtları silmek veya yalnız yeni anahtar yazmak güvenli bir
geçiş değildir. Process restart grace kayıtlarını kaybeder ve retry reddedebilir;
kalıcı tüketim kaydı bundan ayrı kalır.

Grace tracker en çok **4.096** kayıt tutar. Global map yalnız 32 baytlık,
domain-separated SHA-256 kimlikleri ve sabit boyutlu kabul/deadline alanları
saklar; ham token/claim metinleri map'e konmaz. Tuple alanları option etiketi
ve little-endian u64 bayt uzunluğuyla hashlenir. Gerçek doğrulama scope'u
(audience, request purpose, transport) claim'den çözülen purpose'dan ayrı bağlanır.
Metin hashleme global mutex dışında yapılır. Kimlik ayrımı SHA-256 çakışma
dayanımına bağlıdır; bu bir kalıcı ledger kodlaması değildir.

Deadline ilk kabulde kaydedilir. Daha uzun retry isteği veya yinelenen kayıt
çağrısı süreyi yenilemez; kısa retry diğer kayıtları temizlemez. Süre bitimi,
saat geri dönüşü, zaman taşması ve sıfır grace kabulü engeller. Kapasite dolunca
canlı kayıtlar atılmaz ve yeni grace kaydı oluşturulmaz: ilk normal doğrulama
başarılı kalabilir, sonraki replay ise grace kullanamaz. Bu sınır HTTP istek
kotası değildir. Çok worker'lı dağıtımda tracker paylaşılmaz; üretim yükü ve
retry kullanılabilirliği ayrıca ölçülmelidir.
