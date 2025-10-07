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
- Oturum ratchet akışları için `session-encrypt` ve
  `session-decrypt` komutları; ratchet durumu ile replay store
  JSON dosyaları otomatik güncellenir.

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

# Oturum Kullanımı

```bash
cargo run -p aunsorm-cli -- decrypt \
  --password "correct horse battery staple" \
  --in bootstrap.b64 \
  --out bootstrap.bin \
  --org-salt V2VBcmVLdXQuZXU= \
  --calib-text "Neudzulab | Prod | 2025-08" \
  --metadata-out session-metadata.json

cargo run -p aunsorm-cli -- session-encrypt \
  --metadata session-metadata.json \
  --state sender-state.json \
  --ratchet-root Fho1...== \
  --session-id AbCd...== \
  --in message.bin \
  --out session-packet.b64

cargo run -p aunsorm-cli -- session-decrypt \
  --metadata session-metadata.json \
  --state receiver-state.json \
  --store receiver-store.json \
  --ratchet-root Fho1...== \
  --session-id AbCd...== \
  --in session-packet.b64 \
  --out plain.bin
```

Her komutun ayrıntılı yardım sayfasına `--help` ile erişilebilir.
