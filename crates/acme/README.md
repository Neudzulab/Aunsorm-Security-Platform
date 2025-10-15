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
- Opsiyonel uç noktalar ve meta alanlarını saklar, bilinmeyen uç
  noktaları deterministik sırada raporlar.
- Hatalı URL veya meta alanlarında ayrıntılı hata mesajları üretir.
- Replay-Nonce başlıklarını doğrular ve kapasite kontrollü FIFO havuzunda
  saklar.

## Testler

Tüm testler ağ bağlantısı olmadan çalışır ve örnek Let's Encrypt
endpointleri üzerinden deterministik fixture'lar kullanır.

## Lisans

Apache-2.0 lisansı altında dağıtılır. Detaylar için [LICENSE](../../LICENSE)
dosyasına bakın.
