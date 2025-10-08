# aunsorm-pytests Ajanı Rehberi

- Bu crate Python referans uygulamasından yakalanan uyumluluk vektörlerini doğrulamak için kullanılır.
- Yeni vektörler eklerken çıktının kaynağını ve üretim adımlarını `vectors/` dizinindeki README'de belgeleyin.
- Testler deterministik olmalı; dış servis veya ağ çağrısı yapılmamalıdır.
- JSON vektörleri Base64 (padding'siz) değerler içerir; `STANDARD_NO_PAD` kullanın.
- `aunsorm-packet` ve `aunsorm-core` için API yüzeyinin değişmesi halinde bu crate güncellenmelidir.
