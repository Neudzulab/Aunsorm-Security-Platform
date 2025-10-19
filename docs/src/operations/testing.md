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

## Interop Sağlamlık Anlık Görünümü (2025-10-19)

- `scripts/interop-sanity.sh` betiği; interop benchmark’larını, 10k çalıştırımlı
  fuzz sanity kontrollerini ve Python referans testlerini tek seferde
  orkestre eder. 【F:scripts/interop-sanity.sh†L1-L17】
- `cargo +nightly fuzz run fuzz_packet -- -runs=10000 -detect_leaks=0` komutu
  569 kapsam noktası ve 739 kenar keşfiyle 10k yürütmeyi başarıyla
  tamamlamıştır. 【8ab49d†L1-L102】
- `cargo +nightly fuzz run fuzz_session -- -runs=10000 -detect_leaks=0` artık
  önceden hesaplanan el sıkışma (handshake) metadatasını kullanarak 10k yürütmeyi
  saniyede ~10k hızla bitirebilmektedir. 【581004†L1-L26】
- Benchmark sonuçları:
  - `coord32_derive`: ~4.62 µs p50. 【dc4279†L1-L3】
  - `session_ratchet_next`: ~39.7 µs p50. 【b36634†L1-L4】
  - `x509_root_generation` (Ed25519 / RSA2048 / RSA4096): ~87 µs, ~213 ms,
    ~3.08 s. 【e42377†L1-L5】【0d79c4†L1-L2】【7a1697†L1-L2】
  - `x509_server_signing` (Ed25519 / RSA2048 / RSA4096): ~130 µs, ~184 ms,
    ~7.13 s. 【d5174e†L1-L2】【a99a78†L1-L2】【3f3fec†L1-L3】

## Soak Testleri

- `cargo test -p aunsorm-tests -- --ignored session_ratchet_roundtrip_soak`
  uzun süreli oturum testi için kullanılır. Varsayılan iterasyon 256’dır; `AUNSORM_SESSION_SOAK`
  değişkeni ile özelleştirilebilir.
- `cargo test -p aunsorm-tests -- --ignored kms_local_roundtrip_soak` KMS yerel store
  doğrulamasını 128 iterasyon boyunca tekrar eder. `AUNSORM_KMS_SOAK` ile iterasyon
  sayısı artırılabilir.
- `cargo test -p aunsorm-tests --features "kms-remote" -- --ignored kms_remote_live_soak`
  GCP/Azure uzak anahtarlarını `AUNSORM_KMS_GCP_CONFIG`/`AUNSORM_KMS_AZURE_CONFIG`
  ortam değişkenlerinde tanımlanan JSON yapılandırmalarla test eder. Döngü sayısı
  `AUNSORM_KMS_REMOTE_SOAK`, hedef filtrelemesi `AUNSORM_KMS_REMOTE_KEYS` ile
  kontrol edilir. Sonuçlar `AUNSORM_KMS_REMOTE_REPORT` değişkeni ile belirtilen
  dosyaya JSON olarak kaydedilebilir; rapor girdileri public anahtarın hex
  gösterimini ve beklenen `kid` özetini içerir.

## PQC Sertleştirme Kontrol Listesi

- `cargo run -p aunsorm-cli -- pq checklist --algorithm ml-dsa-65 --format text`
  komutu, seçilen imza algoritması için NIST kategorisi, anahtar boyları ve zorunlu
  çalışma zamanı kontrollerini insan tarafından okunur biçimde raporlar.
- `--format json` seçeneği ile aynı rapor CI pipeline’larına veya harici denetim
  araçlarına JSON olarak aktarılabilir.
- Kontrol listeleri strict kip etkinken eksik özellik bayraklarını belirgin
  uyarılarla bildirir; bu sayede PQc downgrade girişimleri devreye alınmadan önce
  yakalanabilir.

## Kalite Komutları

```bash
cargo fmt --all
cargo clippy --all-targets --all-features
cargo test --all-features
```

- Clippy uyarıları `#![deny(warnings)]` nedeniyle derleme engeline dönüşür.
- Soak testleri varsayılan olarak `#[ignore]` etiketine sahiptir; pipeline’larda
  ayrı bir aşamada tetiklenmelidir.
