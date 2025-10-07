# aunsorm-wasm

`aunsorm-wasm`, Aunsorm çekirdek kriptografisini tarayıcı ve WebAssembly ortamlarına taşıyan binding
katmanıdır. `wasm-bindgen` aracılığıyla üç temel fonksiyon sunar:

- `encrypt_with_calib_text(request)` — Parola, EXTERNAL kalibrasyon metni ve opsiyonel parametrelerle
  paket üretir. Çıktı Base64 kodlu paket stringidir.
- `decrypt_with_calib_text(request)` — Kalibrasyon metni olmadan açılmayan paketleri çözer ve düz
  metni `Uint8Array` olarak döndürür.
- `peek_header(packet_b64)` — Şifreli paket başlığını JSON olarak inceler.

Varsayılanlar:

- KDF profili belirtilmezse `"medium"` kullanılır.
- AEAD algoritması belirtilmezse `"aes-gcm"` seçilir.
- `strict` alanı belirtilmezse `AUNSORM_STRICT` çevre değişkeni dikkate alınır ("1", "true"
  değerleri aktiftir).

Tüm parametreler JSON benzeri nesneler olarak `serde_wasm_bindgen` ile (de)serileştirilir. Örnek
kullanım için `examples` dizinindeki web istemci prototipine bakabilirsiniz.
