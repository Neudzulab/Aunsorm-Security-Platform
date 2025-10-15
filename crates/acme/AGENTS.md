# aunsorm-acme Ajanı Rehberi

- ACME protokolü RFC 8555'e uygun olarak uygulanmalı; gereksiz
yuvarlamalardan kaçınılmalı ve zorunlu uç noktalar doğrulanmalıdır.
- Directory ve nonce işlemleri deterministik ve tekrarlanabilir
şekilde test edilmelidir; testlerde gerçek ağ çağrıları yapılmaz.
- JSON ayrıştırma hataları ayrıntılı, kullanıcıya yardımcı olacak
hata mesajları ile dönmelidir.
- Gelecekteki domain doğrulama iş akışları için modüler yapı
korunmalı; `reqwest` gibi istemciler üst katmanda, bu crate içinde
temel veri modelleri ve doğrulamalar yer almalıdır.
- Tüm modüller `#![forbid(unsafe_code)]`, `#![deny(warnings)]` ve
Clippy lint setlerine uymalıdır.
