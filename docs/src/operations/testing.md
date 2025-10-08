# Operasyonel Testler

Bu bölüm, kalite komutlarıyla birlikte genişletilen fuzz ve soak senaryolarını
özetler.

## Genişletilmiş Fuzz Kapsamı

- `cargo fuzz run session_store_roundtrip` komutu oturum ratchet’ı, mesaj numarası
  eşitlemesini ve `SessionStore` kayıtlarını doğrular.
- Girdi vektörleri UTF-8 değilse otomatik olarak Base64’e dönüştürülür ve
decrypt akışı beklenmedik panik üretmeden hataları yüzeye çıkarır.
- Fuzzer çıktıları `fuzz/artifacts/session_store_roundtrip/` altında saklanır.

## Soak Testleri

- `cargo test -p aunsorm-tests -- --ignored session_ratchet_roundtrip_soak`
  uzun süreli oturum testi için kullanılır. Varsayılan iterasyon 256’dır; `AUNSORM_SESSION_SOAK`
  değişkeni ile özelleştirilebilir.
- `cargo test -p aunsorm-tests -- --ignored kms_local_roundtrip_soak` KMS yerel store
  doğrulamasını 128 iterasyon boyunca tekrar eder. `AUNSORM_KMS_SOAK` ile iterasyon
  sayısı artırılabilir.

## Kalite Komutları

```bash
cargo fmt --all
cargo clippy --all-targets --all-features
cargo test --all-features
```

- Clippy uyarıları `#![deny(warnings)]` nedeniyle derleme engeline dönüşür.
- Soak testleri varsayılan olarak `#[ignore]` etiketine sahiptir; pipeline’larda
  ayrı bir aşamada tetiklenmelidir.
