# aunsorm-cli

`aunsorm-cli`, Aunsorm güvenlik araç takımına ait komut satırı
arabirimidir. EXTERNAL kalibrasyon bağlamını zorunlu tutarak
paket üretme ve çözme iş akışlarını otomatikleştirir.

## Özellikler

- Deterministik salt türetimi ile `encrypt` ve `decrypt` komutları.
- KDF profilleri (`mobile`, `low`, `medium`, `high`, `ultra`) ve
  AEAD seçimleri (`aes-gcm`, `chacha20poly1305`).
- Opsiyonel ek bağlamsal AAD girişi (metin ya da dosya).
- KEM alanlarını manuel besleme desteği (ileri sürümler için)
  ve strict kipinin ortam/parametre ile yönetimi.

## Kullanım

```bash
cargo run -p aunsorm-cli -- encrypt \
  --password "correct horse battery staple" \
  --in plaintext.bin \
  --out packet.b64 \
  --org-salt V2VBcmVLdXQuZXU= \
  --calib-text "Neudzulab | Prod | 2025-08"
```

```bash
cargo run -p aunsorm-cli -- decrypt \
  --password "correct horse battery staple" \
  --in packet.b64 \
  --out recovered.bin \
  --org-salt V2VBcmVLdXQuZXU= \
  --calib-text "Neudzulab | Prod | 2025-08"
```

Her komutun ayrıntılı yardım sayfasına `--help` ile erişilebilir.
