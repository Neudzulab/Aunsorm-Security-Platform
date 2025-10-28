# aunsorm-acme

`aunsorm-acme`, Aunsorm ekosistemi için ACME (RFC 8555) protokolünün
temel yapı taşlarını sağlar. Crate, ACME directory uç noktalarının
ayrıştırılması ve doğrulanması için tip güvenli modeller sunar. Ayrıca
Replay-Nonce başlıklarını doğrulayan ve yeniden kullanım riskini azaltan
hafif bir nonce havuzu içerir. Gelecek sprintlerde eklenecek hesap
oluşturma ve domain doğrulama iş akışları için temel taş olarak
kullanılacaktır.

## Özellikler

- ACME directory JSON belgelerini güçlü tiplerle ayrıştırır.
- Zorunlu uç noktaların (newNonce, newAccount, newOrder, revokeCert,
  keyChange) varlığını doğrular.
- Zorunlu uç noktaların HTTPS üzerinden yayımlandığını doğrular, yanlış
  yapılandırılmış HTTP şemalarını reddeder.
- Opsiyonel uç noktalar ve meta alanlarını saklar; bilinmeyen uç
  noktaları deterministik sırada raporlar ve HTTPS dışı şemaları
  reddeder.
- Hatalı URL veya meta alanlarında ayrıntılı hata mesajları üretir.
- Replay-Nonce başlıklarını doğrular ve kapasite kontrollü FIFO havuzunda
  saklar.
- `NonceManager`, ACME `newNonce` uç noktasını çağırıp taşınabilir bir
  istemci soyutlamasıyla nonce havuzunu otomatik doldurur.
- `NewAccountRequest` builder'ı ACME hesap oluşturma istekleri için
  `mailto:`/`tel:` iletişim URI doğrulaması ve `externalAccountBinding`
  kontrolleri sağlar.
- ACME `newOrder` istekleri için tip güvenli identifier doğrulaması ve
  zaman aralığı (`notBefore`/`notAfter`) içeren builder sağlar.
- `newOrder` identifier doğrulaması IDNA normalizasyonu sayesinde
  uluslararası alan adlarını ve wildcard kombinasyonlarını destekler.
- ACME authorization kaynaklarını ayrıştırır; HTTP-01/DNS-01/TLS-ALPN-01
  challenge girdilerini RFC 8555 kurallarıyla doğrular ve token
  değerlerini güvenli biçimde doğrular.
- HTTP-01 domain doğrulamaları için key-authorization üretimi,
  beklenen dosya yolu (`/.well-known/acme-challenge/<token>`) ve yanıt
  gövdesi doğrulama yardımcıları sağlar; basit dosya sunucusu
  dağıtımlarında sondaki newline karakterlerini tolere eder.
- Ed25519, ECDSA P-256 ve RSA (RS256) hesap anahtarlarıyla ACME JWS
  (`protected`, `payload`, `signature`) üretir; `kid` veya JWK tabanlı
  başlık bağlamını destekler.
- Hesap anahtarı üretimi için Ed25519, ECDSA P-256 ve RSA (varsayılan
  2048-bit) algoritmalarıyla RNG enjeksiyonunu destekleyen yardımcılar
  sunar; CLI/servis tüketicileri tek adımda güvenli anahtar üretebilir.
- ACME hesap anahtarları için RFC 7638 uyumlu JWK thumbprint değerleri
  üretir; key-authorization hesaplamalarında kullanılabilir.

## Testler

Tüm testler ağ bağlantısı olmadan çalışır ve örnek Let's Encrypt
endpointleri üzerinden deterministik fixture'lar kullanır.

## Lisans

Apache-2.0 lisansı altında dağıtılır. Detaylar için [LICENSE](../../LICENSE)
dosyasına bakın.
