# Regülasyon Uyumluluk Kontrol Listesi

*Revizyon: 2025-10-18*

Bu kontrol listesi, Aunsorm platformunun eIDAS, SOC 2 ve FATF gibi standartlarla uyumunu sürdürmek için her sprint sonunda gözden geçirilmesi gereken maddeleri derler.

## Çapraz Referanslanan Programlar
- **HTTP/3 & QUIC:** [HTTP/3 QUIC Güvenlik Değerlendirmesi](http3-quic-security.md) dokümanı, QUIC datagram trafiği için AEAD gereksinimlerini ve 0-RTT kısıtlarını içerir.
- **Blockchain İnovasyon Programı:** [Blockchain İnovasyon Programı](../innovation/blockchain.md) teslimatları, zincir üstü kayıtların gizlilik ve denetlenebilirlik hedeflerini tanımlar.

## Kontrol Maddeleri
1. **Veri Sınıflandırması**
   - Zincir dışı saklanan veriler ile blokzincire taahhüt edilen veriler arasındaki ayrım belgelenmiş mi?
   - GDPR/KVKK kapsamındaki kişisel veriler hash veya taahhüt formuna dönüştürülmüş mü?
2. **Anahtar Yönetimi**
   - `aunsorm-kms` üzerinden kullanılan HSM anahtarları için rotasyon kayıtları güncel mi?
   - Ledger imzaları için kullanılan anahtarların yaşam döngüsü (oluşturma, kullanım, imha) loglanmış mı?
3. **Erişim Kontrolleri**
   - Blockchain PoC testleri (`cargo test -p aunsorm-tests --test blockchain_poc`) IAM entegrasyon gereksinimlerini doğruluyor mu?
   - CI ortamında `BLOCKCHAIN_POC_ENABLED` bayrağıyla koşan iş sonuçları gözlemlenip raporlandı mı?
4. **Denetim ve Raporlama**
   - SOC 2 için gerekli denetim izleri `certifications/` altında toplanan şablonlarla eşleşiyor mu?
   - FATF Travel Rule gereksinimleri için zincir üstü izleme planı güncellendi mi?
5. **DID ve Tokenizasyon Yol Haritası**
   - Hyperledger Fabric/Quorum PoC’leri için kimlik ve yetkilendirme akışları belgelendi mi? (`POST /blockchain/fabric/did/verify` planı tamamlandı mı?)
   - `tests/blockchain/config.example.toml` dosyasında yer alan ağ parametreleri gerçek ortamla uyumlu mu?

## İnceleme Döngüsü
- Kontrol listesi, sprint retrospektiflerinde Interop ve Security ekipleri tarafından gözden geçirilir.
- Tespit edilen açık maddeler için Jira/Linear üzerinde `ops/compliance` etiketiyle takip kartı açılır.
- Her revizyon bu dosyanın üst kısmındaki tarih ile işaretlenir ve CHANGELOG'da referans verilir.
