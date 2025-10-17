# Blockchain İnovasyon Programı

## Temel Vizyon
Aunsorm ekosisteminde blockchain teknolojisini kullanarak güvenilirlik, şeffaflık ve denetlenebilirlik katmanını güçlendirmek amaçlanmaktadır. Program; mevcut güvenlik ürün ailesini tamamlayacak şekilde ölçeklenebilir, uyumlu ve regülasyon dostu çözümler üretmeyi hedefler. Özellikle kalibrasyon bağlamı, sıfırlanabilir bellek ve sıfır güven mimarisi ile uyumlu, kurum içi ve kurumlar arası süreçlerde sürdürülebilir bir altyapı sunmak ana hedeftir.

## Hedef Kullanım Alanları
- **Dağıtılmış Kimlik (DID) ve Yetkilendirme:** Aunsorm kimlik çözümleri (JWT, X.509, KMS) ile uyumlu DID kayıtları ve zincir üstü yetkilendirme verileri.
- **Denetim İzi ve Uyumluluk Kaydı:** KMS ve paket katmanlarının ürettiği kritik olayları değiştirilemez bir defterde saklama; dış denetim ve regülasyon raporlamasını kolaylaştırma.
- **Tokenizasyon ve Varlık Yönetimi:** Güvenli token ihracı, erişim kontrolü ve anahtar saklama için Aunsorm çekirdek kripto birimlerinin kullanıldığı yönetilebilir bir varlık katmanı.
- **Tedarik Zinciri ve Donanım Güvenliği:** Kalibrasyon metinleri ve oturum ratchet çıktılarının cihaz seri numaralarıyla eşleştirilmesi; saha operasyonlarında doğrulanabilir tedarik zinciri adımları.
- **Interop Odaklı Entegrasyonlar:** Harici blockchain ağlarıyla (ör. Hyperledger Fabric, Quorum) köprü oluşturma ve Aunsorm paket formatı ile zincir üstü mesaj doğrulamaları.

## Regülasyon Çerçevesi
- **AB Regülasyonları:** eIDAS 2.0, MiCA ve DORA kapsamında dijital kimlik, tokenizasyon ve operasyonel dayanıklılık gereksinimlerine uyum.
- **Küresel Finans Standartları:** FATF Travel Rule, ISO 20022 mesajlaşması ve SOC 2 denetimleriyle uyumlu denetim izleri.
- **Veri Koruma:** GDPR, KVKK ve CCPA gibi veri koruma regülasyonlarına uygun kişisel veri minimizasyonu ve zincir dışı güvenli saklama stratejileri.
- **Uyumluluk Mekanizmaları:** Zincir üstü ve zincir dışı kayıtların tutarlılığı için denetim raporları, imzalı kontroller ve zaman damgası otoriteleriyle entegrasyon.

## Ekip Görev Paylaşımı ve Koordinasyon
| Ekip     | Sorumluluklar | Bağımlılıklar | Risk Azaltma Adımları |
|----------|----------------|----------------|-----------------------|
| Crypto   | Token ve defter imza algoritmalarının seçimi, mock ledger API tasarımı, veri bütünlüğü kontrolleri için kriptografik yapı taşlarının hazırlanması. | `crates/core`, `crates/pqc`, `tests/blockchain` test iskeleti, mock ledger referans implementasyonu. | Seçilen algoritmaların MSRV 1.76 ile uyumunu doğrulayan PoC’ler, formal dokümantasyon ve fuzz test planlarının erken hazırlanması. |
| Identity | DID şemaları, yetkilendirme kayıt modelleri ve kimlik kanıtı akışlarının tasarımı; zincir üstü/off-chain verilerin bağlanması. | `crates/jwt`, `crates/x509`, `crates/kms`, interop için API sözleşmeleri. | Regülasyon haritalaması, veri minimizasyonu checklistleri ve erişim kontrol politikalarının erken revizyonu. |
| Interop  | Hyperledger/Quorum entegrasyon araştırmaları, CI iş akışları, örnek config ve test harness otomasyonları. | `tests/blockchain`, CI pipeline kaynakları, dış ağ simülasyonları. | Entegrasyon prototiplerinde ağ izolasyonu, güvenlik duvarı kuralları ve kimlik doğrulama mock’ları; hatalı yapılandırma riskine karşı otomatik lint kontrolleri. |

## Bağımlılıklar ve Risk Yönetimi
- Mock ledger arayüzünün erken tanımlanması, tüm ekiplerin aynı API ile ilerlemesini sağlayacaktır.
- Regülasyon uyumundaki belirsizlikler için Hukuk/Uyum danışmanlarıyla aylık gözden geçirme oturumları planlanmıştır.
- Zincir üstü veri hacminin artması durumunda ölçeklenebilirlik için Layer-2 ve arşiv düğümü gereksinimleri değerlendirilecektir.
- PoC aşamasında ortaya çıkabilecek gecikmeleri azaltmak için Interop ekibine ayrılmış CI kaynakları ve otomatik hata bildirimleri kurulacaktır.

## Çıktılar ve Ölçümleme
- PoC aşaması sonunda: Mock ledger, veri bütünlüğü testleri ve regülasyon uyum checklisti.
- Entegrasyon aşamasında: DID ve denetim izi akışlarının E2E demo’su, tokenizasyon modülleri için performans ölçümleri.
- Sertifikasyon aşamasında: SOC 2 ve eIDAS uygunluk paketleri, bağımsız denetçi raporlarının entegrasyonu.
