# aunsorm-pqc

`aunsorm-pqc`, Aunsorm platformu için post-kuantum kriptografi köprüsü sağlar. ML-KEM anahtar
kapsülleme şemaları ile ML-DSA, Falcon ve SPHINCS+ imza algoritmalarını tek noktadan sunar. Hem
"strict" bağlamında fail-fast politikaları destekler hem de klasik modlar için güvenli degradasyon
senaryosu sunar.

## Özellikler
- ML-KEM-768 ve ML-KEM-1024 için anahtar üretme, kapsülleme, kapsülü çözme
- ML-DSA 65, Falcon-512 ve SPHINCS+-SHAKE-128f imza algoritmaları
- Strict kipte kullanılabilir algoritma zorlaması
- `aunsorm-packet` entegrasyonu için hazır KEM paketleyicileri

## Kullanım
```rust
use aunsorm_pqc::{
    kem::{negotiate_kem, KemAlgorithm},
    strict::StrictMode,
};

let selection = negotiate_kem(&[KemAlgorithm::MlKem768], StrictMode::Strict)?;
println!("Seçilen algoritma: {}", selection.algorithm.name());
```
