# Katmanlar ve Bileşenler

## Çekirdek ve PQC

- `SessionRatchet`, `SessionStore` ve `derive_keys` fonksiyonları deterministik
  ilerleme sağlar.
- `Salts::new` girdileri zeroize edilmeden önce uzunluk kontrollerinden geçer.
- PQC köprüsü strict kipte ML-KEM-768 ve isteğe bağlı ML-DSA’yı doğrular.

## Paketleme

- `encrypt_one_shot` ve `decrypt_one_shot` birincil el sıkışma kanalını kurar.
- `session_store_roundtrip` fuzz hedefi, yeni mesaj numaraları ve AAD digest
  hesaplamalarını doğrulamak için ratchet akışını tekrar tekrar işletir.
- `SessionStore::register` tekrarlanan mesajları engelleyerek replay koruması sunar.
- Her paket için `TranscriptHash`, başlık + AAD + ciphertext + PMAC
  kombinasyonunu hex olarak raporlayarak olay kayıtlarında kullanılacak
  deterministik bir özet üretir.

## Kimlik

- `KmsClient` yapılandırması strict kipte fallback kararlarını açık biçimde uygular.
- Yeni testler; Azure ve GCP konfigürasyonlarında boş/tekrarlı `key_id` değerlerini
  yakalar ve anlamlı `KmsError::Config` mesajları üretildiğini doğrular.
- Yerel store senaryoları için soak testi, Ed25519 ve RSA imzalarının
  doğruluğunu ve AES-256 anahtar sarma/dalma adımlarını binlerce kez
  tekrarlar.

## Platform

- CLI, server ve wasm katmanları aynı `SessionMetadata` sözleşmesini kullanarak
  koordinatları paylaşır.
- OpenTelemetry entegrasyonu `AUNSORM_OTEL_ENDPOINT` üzerinden yapılandırılabilir.
- `aunsorm-server` başlangıçta yayınladığı JWKS anahtarını şeffaflık defterine
  işler ve `/transparency/tree` uç noktası üzerinden Merkle benzeri ağaç
  başlığını JSON olarak sunar.

## ACME

- `aunsorm-acme` crate'i ACME directory uç noktalarını ayrıştırıp doğrulamak
  için tip güvenli veri modelleri sunar.
- Zorunlu uç noktalar (newNonce, newAccount, newOrder, revokeCert, keyChange)
  eksiksiz doğrulanır; opsiyonel alanlar deterministik sırada raporlanır.
- Meta alanlarındaki Terms of Service ve CAA identity listeleri sonraki
  hesap oluşturma ve domain doğrulama iş akışlarında yeniden kullanılır.

## Dokümantasyon ve Gözlemlenebilirlik

- Bu mdBook, sprint’lerin gerektirdiği güvenlik kontrollerini tek kaynakta toplar.
- `docs/book.toml` ile üretim derlemesi `mdbook build docs` komutuna hazırdır.
