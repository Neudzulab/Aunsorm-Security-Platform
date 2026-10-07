# aunsorm-kms

## Servisin Görevi
KMS servisi, anahtar üretimi, rotasyonu ve erişim kontrolünü `BackendKind` arabirimi üzerinden sunar. Strict kipte kalibrasyon ve fingerprint doğrulaması zorunlu tutulur.

## Portlar
- **50014** — KMS API

## Örnek İstek/Response
```bash
curl -X POST http://${HOST:-localhost}:50014/kms/keys \
  -H "Content-Type: application/json" \
  -d '{"keyType":"ed25519","strict":true}'
```

```json
{
  "id": "kms-key-01HXXX",
  "algorithm": "ed25519",
  "publicKey": "MCowBQYDK2VwAyEAc0Zq..."
}
```

## Güvenlik Notları
- `AunsormNativeRng` ile üretilen anahtarlar zeroization dostu yapılardan geçirilir.
- Fallback yalnızca `AUNSORM_KMS_FALLBACK=1` ve strict kapalı olduğunda denenir; aksi durumda anlamlı hata döner.
- JSON yapılandırma hataları açıklayıcı mesajlarla raporlanır.
- Rustdoc örnekleri ve testler hem yerel backend'i hem strict kipini kapsar.


## PKCS#11 EC nokta doğrulaması

Ed25519 `CKA_EC_POINT` yalnızca tam, kanonik DER OCTET STRING olarak kabul
edilir: `04 20 <32 bayt>` veya mevcut çift sarmalama için
`04 22 04 20 <32 bayt>`. Boş/yanlış/çoklu öznitelik listeleri, uzun/kanonik
olmayan DER uzunlukları, eksik/ek baytlar ve üçüncü sarmalama hata döndürür.
Ayrıştırıcı sabit uzunluk eşleştirmesiyle çalışır; güvenilmeyen uzunluk alanında
toplama/kaydırma veya tahsis yapmaz. Üst Cryptoki çağrısının tahsislerini veya
HSM sağlayıcısının güvenilirliğini bu kontrol doğrulamaz.

`cargo test -p aunsorm-kms --all-features --locked` gerçek Ed25519 imza
doğrulaması ve öznitelik/DER kontrollerini çalıştırır. Paylaşılan kaynak
`fuzz_pkcs11_point` hedefinde ve `pkcs11_point_stdin` örneğinde kullanılır.
Saf ayrıştırıcı/stdin kaynağı gerçek Rust 1.76 ile derlenmiştir; bu, bütün
workspace bağımlılık grafiğinin 1.76 uyumlu olduğu anlamına gelmez.

Cryptoki 0.6.2 bağımlılığı
[RUSTSEC-2026-0286](https://rustsec.org/advisories/RUSTSEC-2026-0286.html)
kapsamında hâlâ savunmasızdır. Düzeltilmiş 0.10.1 hattı Rust 1.77 ister;
MSRV politikası çözümlenmeden bağımlılık yükseltmesi yapılmadı. Yerel EC nokta
hatasının düzeltilmesi `CKA_ALLOWED_MECHANISMS` açığını gidermez.


## Sarılmış yazılım seed’i

`kms-pkcs11` yapılandırmasının `module: null` yazılım yolu, key-id AAD’sine
bağlı AES-256-GCM seed zarfını açar: 12 bayt nonce + 32 bayt seed + 16 bayt
etiket = 60 bayt; standart base64 karşılığı 80 bayttır. Bu uzunluklar
base64 çözme/AEAD işleminden önce denetlenir. `AUNSORM_KMS_PKCS11_WRAP_KEY`,
kırpılmış 44 baytlık standart base64 içinde tam 32 bayt anahtar içermelidir.

Ortamdan okunan anahtar metni, çözme için kullanılan sabit 33 baytlık tampon
(kısmi çözme hata yolları dahil) ve sabit 32 baytlık yerinde-açılan seed tamponu `Zeroizing` ile
temizlenir. KMS, Ed25519 `zeroize` özelliğini açıkça etkinleştirir; başka
crate’lerin özellik birleşimine ihtiyaç duymaz. Bu kontrol bütün kütüphane/OS
kopyalarının veya AES iç durumunun bellek denetimi olduğu anlamına gelmez.

Gerçek sarılmış-seed testleri Native RNG nonce’ları ve gerçek AES-GCM/Ed25519
işlemleri kullanır; yanlış key-id/anahtar, nonce/şifreli veri/etiket değişiklikleri
ve boyut/encoding hataları reddedilir. Test ortam değişkeni mutex altında
saklanır ve scope sonunda eski değere döndürülür. Önceki geçersiz ve ertelenmiş
fixture yerine bu yazılım testi çalışır. Bu, gerçek HSM çağrısı veya strict
hardware `public_key` denetiminin kanıtı değildir; onlar ayrı doğrulama
gereksinimleridir.


Üretim zarf decoder’ı `src/wrapped_seed.rs` içinde paylaşılır.
`fuzz_wrapped_seed` aynı kaynağı Cryptoki olmadan derler; KMS sınırı hata türünü
key-id bağlamıyla `KmsError::Config` biçimine dönüştürür. AES-GCM çözme yerinde
yapılır; base64 zarf için sabit 60 bayt, seed için temizlenen sabit 32 bayt
tampon kullanılır ve plaintext `Vec` ayırılmaz.

`cargo build -p aunsorm-kms --example wrapped_seed_stdin --locked` sonrasında
`python -B fuzz/wrapped_seed_corpus.py target/debug/examples/wrapped_seed_stdin.exe
scripts/data/pkcs11-wrapped-seed-native-fixture.bin` kayıtlı sentetik fixture
üzerinde 656 vakayı tekrarlar. Fixture anahtarı/seed’i bilinen test verisidir;
nonce gerçek Native RNG ile üretilmiştir. Yeni fixture için `--generate-fixture`
ve mevcut olmayan bir çıktı yolu kullanılır; mevcut dosya üzerine yazılmaz.


## Public-key kimlik bağlaması

Sarılmış yazılım seed’i ile `public_key` verilirse, anahtar tam 32 bayt
standart base64 olarak çözülür ve seed’den türeyen gerçek public key ile
eşleşmelidir. Yanlış, bozuk, aşırı büyük veya weak Ed25519 anahtarlar
yapılandırma hatasıdır; normal/strict yazılım kiplerinde alan artık göz ardı
edilmez. Alan yoksa mevcut seed’den türetme davranışı devam eder.

HSM `sign` yanıtı istemciye verilmeden önce, saklanan seçili public key ve
istenen mesajla `verify_strict` üzerinden doğrulanır. Tam 64 bayt olmayan,
noncanonical scalar içeren veya yanlış anahtar/mesaja ait yanıtlar HSM hatası
döndürür. Donanım oturumu kilidi kriptografik doğrulamadan önce bırakılır.
Bu denetim HSM anahtarın donanımda tutulduğunu veya cihaz/oturumun gerçekten
güvenilir olduğunu kanıtlamaz; canlı HSM ve gecikme doğrulaması gerekir.

`src/pkcs11_identity.rs`, üretim ve `fuzz_pkcs11_identity` hedefinde aynıdır.
`pkcs11_identity_stdin` örneği ile kayıtlı fixture üzerinde 987 bozulma vakası
çalışır: geçerli imza kabul edilir, 986 değişiklik reddedilir. Fixture bilinen
sentetik seed’den gerçek Ed25519 imzasıdır; bir HSM oturumu yerine geçmez.

## PKCS#11 özel anahtar etiketinin tekilliği

Donanım özel anahtar araması tam bir eşleşme gerektirir. Sıfır eşleşme
`not found`, birden fazla eşleşme `ambiguous` HSM hatası verir; aynı handle
iki kez dönse de ilk nesne seçilmez. Böylece sağlayıcının nesne sırası
anahtar seçimini değiştiremez.

Bu kontrol sonuçların alınmasından sonra uygulanır. Cryptoki 0.6.2
`find_objects` API’si tüm sonuçları bir vektörde toplar; sınırlı donanım
sorgulaması için sağlayıcı/MSRV geçişi hâlâ gereklidir. Üç seçim politikası
testi gerçek donanım oturumu veya satıcı uyumluluğu kanıtı değildir.
