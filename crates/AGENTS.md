# Crates Alanı Standartları

Bu dizindeki tüm crate'ler için aşağıdaki kurallar geçerlidir:

- `#![forbid(unsafe_code)]` ve `#![deny(warnings)]` üst seviye nitelikleri zorunludur.
- Clippy için en az `clippy::all`, `clippy::pedantic` ve `clippy::nursery` deny edilmelidir. Gerekirse tekil uyarılara `#[allow]`
  ile gerekçeli açıklama eklenebilir.
- Her crate kendi `README.md` dosyasına sahip olmalı ve dışa açıkladığı API'leri kısaca belgelemelidir.
- Güvenlik için hassas byte dizileri `zeroize` veya eşdeğer çözümlerle temizlenmelidir.
- Modül testleri `#[cfg(test)]` bloklarında yer almalı ve happy-path + hata senaryosu içermelidir.
