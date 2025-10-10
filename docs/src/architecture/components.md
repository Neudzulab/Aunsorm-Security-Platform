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

## Kimlik

- `KmsClient` yapılandırması strict kipte fallback kararlarını açık biçimde uygular.
- Yeni testler; Azure ve GCP konfigürasyonlarında boş/tekrarlı `key_id` değerlerini
  yakalar ve anlamlı `KmsError::Config` mesajları üretildiğini doğrular.
- Yerel store senaryoları için soak testi, Ed25519 imzalarının doğruluğunu
  ve AES-256 anahtar sarma/dalma adımlarını binlerce kez tekrarlar.

## Platform

- CLI, server ve wasm katmanları aynı `SessionMetadata` sözleşmesini kullanarak
  koordinatları paylaşır.
- OpenTelemetry entegrasyonu `AUNSORM_OTEL_ENDPOINT` üzerinden yapılandırılabilir.
- OAuth sunucusu, `GET /oauth/transparency` uç noktasıyla JWK yayınlarını ve
  token üretimlerini hash zinciri olarak raporlayarak transcript doğrulaması
  sağlar.

## Dokümantasyon ve Gözlemlenebilirlik

- Bu mdBook, sprint’lerin gerektirdiği güvenlik kontrollerini tek kaynakta toplar.
- `docs/book.toml` ile üretim derlemesi `mdbook build docs` komutuna hazırdır.
