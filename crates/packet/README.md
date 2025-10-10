# aunsorm-packet

`aunsorm-packet`, Aunsorm çekirdek kütüphanesinin ürettiği kalibrasyon ve oturum sırlarına dayalı
paket formatını uygular. Başlık alanları HMAC-SHA256 ile, gövde ise AES tabanlı P-MAC ile korunur.
Hem tek-atım (bootstrap) akışını hem de `SessionRatchet` tabanlı ileri gizlilik oturumlarını
sağlar.

## Özellikler
- AES-GCM ve ChaCha20-Poly1305 AEAD desteği
- EXTERNAL kalibrasyon metni olmadan deşifre başarısızlığı
- Oturum bazlı ratchet şifreleme/çözme API'ları
- Replay engelleme için `SessionStore`
- JSON başlık + Base64 kabı ile taşınabilir paket formatı
- Paket başlık/AAD/gövde P-MAC birleşiminden `TranscriptHash` üretimi
  ile denetlenebilir kayıt zinciri

## Kullanım
```
use aunsorm_core::{calib_from_text, salts::Salts, KdfPreset, KdfProfile};
use aunsorm_packet::{encrypt_one_shot, decrypt_one_shot, EncryptParams, DecryptParams, AeadAlgorithm};

let profile = KdfProfile::preset(KdfPreset::Low);
let password_salt = b"password-salt";
let salts = Salts::new(b"calib-salt".to_vec(), b"chain-salt".to_vec(), b"coord-salt".to_vec())?;
let (calibration, _) = calib_from_text(b"org-salt", "note")?;
let packet = encrypt_one_shot(EncryptParams {
    password: "correct horse battery staple",
    password_salt,
    calibration: &calibration,
    salts: &salts,
    plaintext: b"secret",
    aad: b"header",
    profile,
    algorithm: AeadAlgorithm::AesGcm,
    strict: false,
    kem: None,
})?;
let decrypted = decrypt_one_shot(DecryptParams {
    password: "correct horse battery staple",
    password_salt,
    calibration: &calibration,
    salts: &salts,
    profile,
    aad: b"header",
    strict: false,
    packet: packet.to_base64(),
})?;
assert_eq!(decrypted.plaintext, b"secret");
# Ok::<_, Box<dyn std::error::Error>>(())
```
