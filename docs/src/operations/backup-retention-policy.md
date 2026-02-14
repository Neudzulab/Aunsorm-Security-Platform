# Backup Retention Policy

Bu politika, Aunsorm üretim yedeklerinin saklama sürelerini ve imha kurallarını tanımlar.

## Saklama Seviyeleri

| Yedek Tipi | Sıklık | Saklama Süresi | Kullanım |
|---|---|---:|---|
| Snapshot | Saatlik | 48 saat | Hızlı geri dönüş ve kısa süreli olaylar |
| Incremental | Günlük | 35 gün | Operasyonel geri yüklemeler |
| Full | Haftalık | 12 hafta | Planlı felaket kurtarma tatbikatı |
| Full (Arşiv) | Aylık | 13 ay | Denetim, uyumluluk ve adli inceleme |

## Şifreleme ve Erişim

- Tüm yedekler aktarımda TLS ile, beklemede AES-256 ile şifrelenir.
- Anahtar yönetimi yalnızca KMS üzerinden yapılır; plaintext anahtar saklanmaz.
- Yedek erişimi en az ayrıcalık ilkesi ile sınırlandırılır ve erişim denetim logları 13 ay tutulur.

## İmha Politikası

1. Saklama süresi dolan yedekler otomatik iş ile silinir.
2. Silme işlemleri doğrulama raporuyla kanıtlanır.
3. Hukuki saklama (legal hold) işaretli yedekler otomatik imhadan muaftır.
4. İmha sonrası artık metadata kayıtları operasyon denetiminde en az 13 ay saklanır.

## Uyum Gereksinimleri

- SOC 2 ve ISO 27001 denetimleri için aylık saklama raporu üretilir.
- GDPR veri minimizasyon ilkesi için gereksiz kişisel veri içeren snapshot'lar erken imhaya alınır.
- Retention değişiklikleri CAB onayı olmadan üretime uygulanamaz.

## Operasyonel Kontroller

- Günlük yedek başarısı ve toplam hacim alarm eşikleri ile izlenir.
- Haftalık restore denemelerinde retention katmanlarından rastgele örnek seçilir.
- Politika ihlali, olay yönetimi sürecinde `severity-high` olarak sınıflandırılır.
