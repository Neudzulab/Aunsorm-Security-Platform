# Aunsorm Repository Coordination

Bu depo tek bir ajan tarafından değil, alan uzmanı takımlar tarafından yönetilecek şekilde tasarlanmalıdır. PLAN.md içerisindeki gereksinimler her sprintte küçük parçalara ayrılacak ve her iş öğesi için sorumlu ajan tanımlanacaktır.

## Genel İlkeler
- Tüm kod MSRV 1.76 üzerinde derlenebilir olmalıdır.
- Güvenlik odaklı gereksinimler (kalibrasyon bağlamı, strict kipleri, sıfırlama vb.) uygulanırken formal dokümantasyon tutulmalıdır.
- Her dizin altındaki ajanlar, bu dosyada belirtilen standartlara uymalıdır.
- Yeni bir alan açıldığında, o dizine özel ek `AGENTS.md` oluşturulmalıdır.

## İş Akışı
1. README üzerindeki durum kutucuklarını (checklist) güncel tutun.
2. Her ajan kendi bölümünde çalışır; çakışma durumunda koordinasyon bu dosyada güncellenir.
3. `cargo fmt --all`, `cargo clippy --all-targets --all-features`, `cargo test --all-features` komutları her değişiklikte çalıştırılmalıdır.
4. Güvenlik gerekçesiyle `unsafe` kod yasaktır.

## Planlama Ajanları
- **Crypto Agent**: `crates/core`, `crates/pqc`, `crates/packet`.
- **Platform Agent**: `crates/cli`, `crates/server`, `crates/wasm`.
- **Identity Agent**: `crates/jwt`, `crates/x509`, `crates/kms`.
- **Interop Agent**: `benches`, `fuzz`, `crates/pytests`, `examples`, `.github`.

Bu ilk commit planlama ve altyapı başlangıcı içindir. Sonraki işler ilgili ajan tarafından üstlenilecek.
