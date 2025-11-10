# Kubernetes Konfigürasyon Standartları

- Bu dizindeki tüm manifestler üretim ortamını hedefler; `kind: Namespace` ve benzeri kaynak adları değiştirilmeden
  uygulanabilir durumda olmalıdır.
- YAML dosyaları `apiVersion`, `kind`, `metadata`, `spec` sırasını takip etmeli ve çoklu kaynaklar `---` ile ayrılmalıdır.
- Her manifestte TLS gizli anahtarları gibi hassas değerler placeholder olarak bırakılmalı ve metin içinde nasıl
  sağlanacağı açıklanmalıdır.
- Konfigürasyon dosyaları en üstte, uygulanacağı sırayı anlatan yorum bloğu içermelidir.
- Bu dizine yeni alt klasör açıldığında aynı kuralları özetleyen kendi `AGENTS.md` dosyası eklenmelidir.
