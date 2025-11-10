# Mimari Boşluk Analizi

Aşağıdaki başlıklar mevcut mimari belgelerinin hangi kritik alanları kapsamadığını
ve üretim planındaki teslimatlar tamamlanmadan önce hangi kararların
belgelenmesi gerektiğini özetler.

## 1. Veri Kalıcılığı ve Çok Bölgeli Dağıtım
- Mevcut genel bakış ve bileşen bölümleri kriptografik katmanları ayrıntılı
  biçimde anlatırken kalıcı veri katmanına hiç değinmiyor; bu durum SQLite'tan
  PostgreSQL'e geçiş, replikasyon, yedekleme ve şifreleme stratejilerinin nasıl
  uygulanacağını belirsiz bırakıyor.【F:docs/src/architecture/overview.md†L3-L37】【F:PROD_PLAN.md†L68-L75】
- PostgreSQL topolojisi (primary/replica düzeni, bağlantı havuzu, bakım penceresi)
  ile veri saklama politikalarının nasıl doğrulanacağı yazılmalıdır. Bu belge hem
  `Database & Persistence` hem de `Backup & Disaster Recovery` maddelerinin
  üretim planı ile bağını göstermelidir.【F:PROD_PLAN.md†L68-L75】【F:PROD_PLAN.md†L191-L195】

## 2. Kimlik ve Yetkilendirme Yüzeyi
- Mimari belgeler kimlik katmanını kriptografik anahtar üretimi ve strict kip
  fallback kurallarıyla sınırlıyor; MFA, RBAC ve oturum ömrü politikaları gibi
  erişim kontrol bileşenleri tanımlanmamış durumda.【F:docs/src/architecture/overview.md†L11-L20】【F:PROD_PLAN.md†L39-L45】
- Yetkilendirme modelinin servisler arası kimlik yayılımı, denetim kayıtları ve
  hata durumlarıyla nasıl çalıştığı dokümante edilmelidir. Özellikle admin
  operasyonları için MFA ve webhook tabanlı token iptal süreci netleştirilmelidir.【F:PROD_PLAN.md†L39-L45】

## 3. Blockchain ve DID Entegrasyonu
- Sunucu tarafında Hyperledger Fabric tabanlı DID kayıtlarını doğrulayan bir PoC
  modülü bulunmasına rağmen mimari katman belgelerinde bu akıştan hiç bahsedilmemektedir; bu da zincir üstü denetim izlerinin
  nasıl bağlanacağına dair boşluk yaratıyor.【F:crates/server/src/fabric.rs†L21-L198】【F:PROD_PLAN.md†L115-L120】
- Zincir seçimi, anahtar yönetimi, saat kayması toleransları ve yüksek erişilebilirlik
  gereksinimleri aynı belgede ele alınmalı; üretim planındaki `Blockchain
  Integration` teslimatlarıyla ilişkilendirilmiş karar kayıtlarına ihtiyaç vardır.【F:PROD_PLAN.md†L115-L120】

## 4. İstemci/Web Katmanı ile Mimari Uyumluluk
- `apps/web` yardımcıları OAuth tabanlı entegrasyonlarda URL çözümleme ve PKCE
  durum yönetimini üstleniyor ancak mimari belgelerde istemci katmanının
  sorumlulukları tanımlanmıyor. Sunucu ile paylaşılan sözleşmelerin nasıl
  doğrulandığı açıklanmadığı için entegrasyon riskleri görünmez kalıyor.【F:apps/web/README.md†L1-L55】
- Web ve mobil istemciler için oturum yenileme, hata senaryosu yönetimi ve
  ortam değişkeni kontrol listeleri belgelere eklenerek operasyon ekiplerinin
  `Authentication & Authorization` maddelerini tamamlamasına yardımcı olunmalıdır.【F:PROD_PLAN.md†L39-L45】

## 5. Gözlemlenebilirlik ve Operasyonel Ölçümler
- Kod tabanında OpenTelemetry başlangıç katmanı ve metrik kimlikleri hazır olsa
  da mimari belgelerde telemetri topolojisi, veri akışı ve alerting stratejisi
  yer almıyor. Bu eksiklik, gözlemlenebilirlik teslimatlarının nasıl doğrulanacağı
  konusunda belirsizlik yaratıyor.【F:crates/server/src/telemetry.rs†L11-L194】【F:PROD_PLAN.md†L76-L82】
- Ölçüm toplama, log korelasyonu ve dağıtık izleme bileşenlerinin hangi servisler
  tarafından tüketileceği ve `ENABLE_HTTP3_POC` gibi özellik bayraklarının
  gözlemlenebilirlik üzerinde etkileri ayrıntılandırılmalıdır.【F:PROD_PLAN.md†L76-L82】

## 6. Dağıtım ve Orkestrasyon Stratejisi
- Mimari genel bakışta platform katmanı sadece CLI, server ve wasm bileşenleri
  olarak listeleniyor; Kubernetes, servis mesh, mTLS veya dağıtım topolojileri
  açıklanmadığından üretim planındaki orkestrasyon maddeleriyle bağ kurulmamış
  oluyor.【F:docs/src/architecture/overview.md†L15-L20】【F:PROD_PLAN.md†L51-L67】
- Kubernetes'e geçiş, HPA, ingress katmanı ve rate limiting için hangi kontrol
  düzlemi bileşenlerinin kullanılacağı, ayrıca blue-green veya canary dağıtımların
  kim tarafından yönetileceği açıkça yazılmalıdır.【F:PROD_PLAN.md†L51-L67】

Her başlık için eksik kararlar tamamlandığında ilgili mdBook sayfası güncellenmeli
ve PROD_PLAN görevleriyle çapraz referans verilmelidir. Böylece mimari belgeler,
operasyon ve güvenlik ekiplerinin beklentileriyle aynı dili konuşur hale gelir.
