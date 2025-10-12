# aunsorm-cli

`aunsorm-cli`, Aunsorm güvenlik araç takımına ait komut satırı
arabirimidir. EXTERNAL kalibrasyon bağlamını zorunlu tutarak
paket üretme ve çözme iş akışlarını otomatikleştirir.

## Özellikler

- Deterministik salt türetimi ile `encrypt` ve `decrypt` komutları.
- Parola girdileri için CLI geçmişine yazmayan `--password-file`
  seçeneği (dosya sonundaki satır sonları kırpılır).
- KDF profilleri (`mobile`, `low`, `medium`, `high`, `ultra`) ve
  AEAD seçimleri (`aes-gcm`, `chacha20poly1305`).
- Kalibrasyon metnini komut satırından veya `--calib-file` ile dosyadan
  güvenle okuma (satır sonları temizlenir).
- Kalibrasyon raporlarını JSON ya da metin formatında üretme (`--format text`).
- Opsiyonel ek bağlamsal AAD girişi (metin ya da dosya).
- KEM alanlarını manuel besleme desteği (ileri sürümler için)
  ve strict kipinin ortam/parametre ile yönetimi.
- Oturum ratchet akışları için `session-encrypt` ve
  `session-decrypt` komutları; ratchet durumu ile replay store
  JSON dosyaları otomatik güncellenir.
- `--out` benzeri çıktı parametrelerinde `-` değeri desteklenir;
  böylece Base64 paketler, raporlar veya JWT çıktıları doğrudan
  stdout üzerinden boru hatlarına yönlendirilebilir.
- JWT anahtar üretimi, imzalama/doğrulama ve JWKS dışa aktarımı.
- Kalibrasyon uzantılı Ed25519 öz-imzalı X.509 sertifika üretimi.

## Kullanım

```bash
cargo run -p aunsorm-cli -- encrypt \
  --password-file secret.txt \
  --in plaintext.bin \
  --out packet.b64 \
  --org-salt V2VBcmVLdXQuZXU= \
  --calib-text "Neudzulab | Prod | 2025-08"
```

Kalibrasyon metni bir dosyada tutuluyorsa, aynı komut
`--calib-file calib.txt` seçeneği ile de çalıştırılabilir; dosya
sonundaki boş satırlar otomatik kırpılır.

```bash
cargo run -p aunsorm-cli -- decrypt \
  --password-file secret.txt \
  --in packet.b64 \
  --out recovered.bin \
  --org-salt V2VBcmVLdXQuZXU= \
  --calib-text "Neudzulab | Prod | 2025-08"
```

`decrypt` komutu için de aynı şekilde `--calib-file` kullanılabilir.

Raporları insan tarafından okunur biçimde almak için `calib` alt
komutlarına `--format text` parametresini ekleyebilirsiniz.

# Oturum Kullanımı

```bash
cargo run -p aunsorm-cli -- decrypt \
  --password-file secret.txt \
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

Parola dosyaları yalnızca satır sonu karakterlerinden arındırılır;
dosya boşsa komut hata döndürür.
