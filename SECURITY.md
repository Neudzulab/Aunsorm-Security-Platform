# Security Policy

## Supported Versions

| Version | Destek Durumu |
| ------- | -------------- |
| `main`  | Güvenlik düzeltmeleri düzenli olarak uygulanır |
| `0.1.x` | Kritik güvenlik yamaları için desteklenir |

Semantik sürümleme uygulanır; yeni minör sürümler geriye dönük uyumlu kalırken güvenlik düzeltmeleri `PATCH` sürümlerinde yayınlanır.

## Vulnerability Reporting

Güvenlik açığı bildirmek için `security@aunsorm.example` adresine PGP şifreli bir e-posta gönderin. 48 saat içinde alınan raporlar teyit edilir, 5 iş günü içerisinde etkilenen sürümler ve geçici çözümler hakkında yanıt verilir. Gerekliyse koordineli açıklama takvimi belirlenir.

## Threat Model

Aunsorm; kalibrasyon metinleri ve organizasyon tuzları olmadan mesajların çözülememesini, oturum anahtarlarının her adımda yenilenmesini ve Strict kipte downgrade girişimlerinin engellenmesini hedefler.

- **Kimlik Bağı**: `aunsorm-core` EXTERNAL kalibrasyon metnini `calib_from_text` fonksiyonu ile deterministik olarak kalibrasyon kimliği üretip KDF zincirine bağlar.
- **Anahtar Türetimi**: Parolalar Argon2id ile profillere göre sertleştirilir; `KdfProfile::auto` sistem kaynaklarına göre preset seçer ve HKDF etiketi `Aunsorm/1.01/*` namespace'iyle bağlanır.
- **Paket Bütünlüğü**: `aunsorm-packet` JSON başlıkları HMAC-SHA256 ile imzalar, gövdeyi AES-PMAC ile korur ve AEAD (AES-GCM veya ChaCha20-Poly1305) kullanır. Strict kipte başlık alanları ve boyutlar sıkı doğrulanır.
- **Post-Kuantum Dayanıklılık**: `aunsorm-pqc` ML-KEM ve imza şemalarını sarmalar. Strict kip açıkken PQC özellikleri devre dışıysa `KemSelection` fallback'e izin vermez.
- **Oturum Ratcheti**: `SessionRatchet` her mesaj numarası için HKDF ile adım sırrı üretir, tekrar kullanımını engeller.
- **Kimlik Katmanı**: JWT bileşeni Ed25519 imzası ve sqlite tabanlı JTI deposuyla replay saldırılarını engeller; Strict kipte kalıcı depo zorunludur.

## Operational Guidance

- `AUNSORM_STRICT=1` değişkenini üretim ortamlarında varsayılan olarak etkinleştirin.
- PQC bağımlılıklarını doğrulayın; Strict kipte gerekli `kem-*` özellikleri etkin değilse işlemler hatayla sonuçlanacaktır.
- KMS fallback senaryolarında `AUNSORM_KMS_FALLBACK=0` ile kapalı mod çalıştırın.
- JWT JTI deposu için sqlite WAL modunu aktif tutun ve periyodik vacuum uygulayın.
- Kayıtlar (`audit` ve `error` logları) hassas materyal içermeyecek şekilde yapılandırılmıştır; yine de log seviyesini `info` veya daha düşükte tutun.

## Disclosure Process

1. Raporunuzu aldıktan sonra etkilenme durumunu doğrularız.
2. Geçici çözüm veya yama çıkarılana dek raporu gizli tutarız.
3. Çözüm yayınlandığında `CHANGELOG.md` ve `SECURITY.md` güncellenir, gerekirse CVE başvurusu yapılır.
4. Açık kapatıldıktan sonra rapor sahibine atıf yapılır (isteğe bağlı).

Topluluk, güvenliğin sürdürülebilir olması için geri bildirimlerinizi bekler.
