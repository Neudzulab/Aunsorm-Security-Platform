# aunsorm-mdm Ajanı Rehberi

- MDM altyapısı kayıt, politika yönetimi ve sertifika dağıtım planı için
  eşlenik (mirrored) API'ler sağlamalıdır.
- Tüm veri tipleri serde ile JSON uyumlu tutulmalı; tarih/zaman değerleri
  Unix saniyeleri olarak kodlanmalıdır.
- `thiserror` tabanlı hata türleri açık ve eylem odaklı mesajlar taşımalıdır.
- Testler kayıt/duplikasyon, politika güncelleme ve plan hesaplama
  senaryolarını kapsamalıdır.
