# KMS Fixture Rehberi

- JSON dosyaları `provider`, `key_material` ve `messages` alanlarını
  içermelidir.
- `key_material.private_key` değerleri yalnızca test amaçlıdır ve
  gizli tutulması gerekmez; yine de başka ortamlarda yeniden
  kullanılmamalıdır.
- Her fixture, beraberindeki rapor kaydında hangi sertifikasyon
  senaryosunu temsil ettiğini belirtmelidir.
