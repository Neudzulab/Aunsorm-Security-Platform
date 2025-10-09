# Operasyonel Testler

Bu bölüm, kalite komutlarıyla birlikte genişletilen fuzz ve soak senaryolarını
özetler.

## Genişletilmiş Fuzz Kapsamı

- `cargo fuzz run session_store_roundtrip` komutu oturum ratchet’ı, mesaj numarası
  eşitlemesini ve `SessionStore` kayıtlarını doğrular.
- Girdi vektörleri UTF-8 değilse otomatik olarak Base64’e dönüştürülür ve
decrypt akışı beklenmedik panik üretmeden hataları yüzeye çıkarır.
- Fuzzer çıktıları `fuzz/artifacts/session_store_roundtrip/` altında saklanır.

## Gece (Nightly) Corpus Minimizasyonu

- `.github/workflows/nightly-fuzz.yml` iş akışı her gece 02:00 UTC’de tetiklenir.
- `cargo fuzz run` komutlarını her hedef için 5 dakikalık `-max_total_time=300`
  parametresiyle çalıştırarak korpusları ısıtır.
- Ardından `cargo fuzz cmin` ile her hedefin korpusunu `fuzz/corpus-min/<hedef>`
  dizinine minimize eder ve `nightly-corpus.tar.gz` artefaktı olarak yükler.
- Yeni korpus dosyalarını yerel çalışma alanına almak için artefaktı indirip
  `tar -xzf nightly-corpus.tar.gz -C fuzz` komutuyla açabilirsiniz.

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
