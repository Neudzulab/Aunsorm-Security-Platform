# Ağ ve Yük Dengeleme Konfigürasyon Rehberi

- Dosya adları uygulanacak bileşeni (`ingress`, `gateway`, `istio`) açıkça belirtmelidir.
- Her YAML dosyası başında ilgili bileşenin görevini ve bağımlı olduğu gizli anahtar / CRD'leri açıklayan yorum
  satırı bulundurmalıdır.
- Rate limiting ve güvenlik politikaları `metadata.annotations` içinde belgelendirilmeli; ilişkili dokümantasyona
  bağlantı veren yorum satırları eklenmelidir.
- EnvoyFilter gibi gelişmiş kaynaklar için referans alınan resmi dokümantasyon URL'si yorum olarak verilmelidir.
