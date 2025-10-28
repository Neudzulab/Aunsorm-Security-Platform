# Aunsorm Repository Coordination

Bu depo tek bir ajan tarafından değil, alan uzmanı takımlar tarafından yönetilecek şekilde tasarlanmalıdır. PLAN.md içerisindeki gereksinimler her sprintte küçük parçalara ayrılacak ve her iş öğesi için sorumlu ajan tanımlanacaktır.

## Genel İlkeler
- Tüm kod MSRV 1.76 üzerinde derlenebilir olmalıdır.
- Güvenlik odaklı gereksinimler (kalibrasyon bağlamı, strict kipleri, sıfırlama vb.) uygulanırken formal dokümantasyon tutulmalıdır.
- Her dizin altındaki ajanlar, bu dosyada belirtilen standartlara uymalıdır.
- Yeni bir alan açıldığında, o dizine özel ek `AGENTS.md` oluşturulmalıdır.

## 🎲 AUNSORM NATIVE RNG ZORUNLU KULLANIMI (v0.4.5+)
**KRITIK:** Tüm kriptografik rastgele sayı üretimleri artık Aunsorm'un kendi native RNG algoritmasını kullanmak zorundadır!

### Yasak Kullanımlar:
- ❌ **OsRng direkt kullanımı** (sadece initial entropy seeding için izin verilir)
- ❌ **HTTP /random/number** endpoint çağrıları (6.4s overhead)  
- ❌ **rand::thread_rng()** veya benzeri stdlib RNG'leri
- ❌ **ChaCha8Rng** veya diğer harici RNG implementasyonları (test hariç)

### Zorunlu Kullanım:
- ✅ **AunsormNativeRng** - Tüm crate'lerde aynı implementation
- ✅ **HKDF + NEUDZ-PCS + AACM mixing** - Server ile aynı algoritma
- ✅ **4x Performance** - Native vs HTTP (1.5s vs 6.4s RSA-2048)
- ✅ **Cross-Crate Standardization** - Aynı entropi kalitesi her yerde

### Implementation Pattern:
```rust
// ✅ DOĞRU - Her crate'te aynı pattern
use crate::rng::AunsormNativeRng;

pub fn generate_key() -> Result<Key, Error> {
    let mut rng = AunsormNativeRng::new();
    Key::generate_with_rng(&mut rng)
}

// ❌ YANLIŞ - Artık yasak
use rand_core::OsRng;
pub fn generate_key() -> Result<Key, Error> {
    let mut rng = OsRng;  // YASAK!
    Key::generate_with_rng(&mut rng)
}
```

### Crate-Specific Requirements:
- **ACME**: Ed25519, P256, RSA account keys → `AunsormNativeRng`
- **JWT**: Ed25519 signing keys, JTI generation → `AunsormNativeRng`  
- **KMS**: AES-GCM nonce generation → `AunsormNativeRng`
- **X509**: RSA key generation for certificates → `AunsormNativeRng`
- **YENİ CRATE'LER**: Mutlaka kendi `src/rng.rs` modülü oluştur

### Implementation Checklist:
1. **src/rng.rs oluştur** (mevcut crate'lerden kopyala)
2. **Cargo.toml'a hkdf dependency ekle** 
3. **lib.rs'de mod rng; pub use rng::* ekle**
4. **Tüm OsRng kullanımlarını AunsormNativeRng ile değiştir**
5. **cargo test ile doğrula**

Bu kural ihlal edilirse PR reject edilecektir!

## İş Akışı
1. README üzerindeki durum kutucuklarını (checklist) güncel tutun.
2. Her ajan kendi bölümünde çalışır; çakışma durumunda koordinasyon bu dosyada güncellenir.
3. `cargo fmt --all`, `cargo clippy --all-targets --all-features`, `cargo test --all-features` komutları her değişiklikte çalıştırılmalıdır.
4. Güvenlik gerekçesiyle `unsafe` kod yasaktır.
5. README, PLAN.md, TODO.md veya diğer planlama dosyalarında **tamamlandı (`[x]` veya `done`)** olarak işaretlenmiş kalemler kilitlidir; ajanlar bu maddeleri tekrar açmak yerine yeni bir iş maddesi olarak revizyon talebi oluşturmalıdır.
   - Revizyon ihtiyacı varsa, ilgili bölümde `Revize:` önekiyle yeni bir madde ekleyin ve eski maddeye referans verin.
   - Kilitli maddelerdeki dosyalara dokunmanız gerekiyorsa, PLAN.md içerisinde yeni teslimat maddesi olarak belgeleyin ve yetkilendirme gelmeden değişiklik yapmayın.
6. Ajanlar yalnızca yapılacak işleri, `README.md` ana planını ve kapsamlarındaki `AGENTS.md` yönergelerini esas almalıdır; tamamlanan maddeleri değiştirmek iş akışını bozduğundan kaçınılmalıdır.

## 🚨 Servis Ağacı Güncelleme Direktifi
**YENİ ÖZELLİK/ENDPOINT EKLENDİĞİNDE MUTLAKA YAPILACAKLAR:**

1. **README.md Server Endpoint Ağacını Güncelle**
   - Yeni endpoint eklendiğinde `README.md` içindeki endpoint ağacına ekle
   - Yarım/tamamlanmamış özellik bile olsa `[Planlandı v0.X.0]` veya `[Devam Ediyor]` işaretiyle ekle
   - Kaybolmasın! Ajan değişse bile sonraki ajan eksik olanı görebilmeli

2. **Servis Durumu İşaretleri**
   - ✅ Aktif/Çalışıyor: Endpoint tamamen çalışıyor ve test edilmiş
   - 🚧 Geliştirme: Kod var ama endpoint route'u henüz eklenmedi
   - 📋 Planlandı: Crate var, servis entegrasyonu bekliyor
   - 🔮 Gelecek: Henüz tasarım aşamasında

3. **Örnek Formatlar**
   ```markdown
   - `POST /id/generate` 🚧 - Benzersiz kimlik oluştur (aunsorm-id crate hazır, endpoint bekliyor)
   - `GET /acme/directory` 📋 [Planlandı v0.5.0] - ACME servis keşfi (RFC 8555)
   - `POST /session/init` ✅ - Oturum başlatma (kalibrasyon gerektirir)
   ```

4. **Kontrol Noktaları**
   - Yeni crate eklendiğinde → README'de bahset, endpoint planı yaz
   - Yeni endpoint eklendiğinde → README ağacını güncelle, durum işareti koy
   - Git commit öncesi → README ile routes.rs dosyasını karşılaştır
   - Sprint sonunda → Tüm ağacı gözden geçir, eksik servisleri işaretle

5. **Sorumluluk**
   - **Platform Agent**: Server endpoint ağacının sahibidir
   - **Crypto Agent**: Core, PQC, Packet servislerini bildirmekle sorumludur
   - **Identity Agent**: JWT, X509, KMS, ID servislerini bildirmekle sorumludur
   - **Interop Agent**: Test/benchmark süreçlerinde eksik servisleri tespit etmekle sorumludur

## Planlama Ajanları
- **Crypto Agent**: `crates/core`, `crates/pqc`, `crates/packet`.
- **Platform Agent**: `crates/cli`, `crates/server`, `crates/wasm`.
- **Identity Agent**: `crates/jwt`, `crates/x509`, `crates/kms`.
- **Interop Agent**: `benches`, `fuzz`, `crates/pytests`, `examples`, `.github`.

Bu ilk commit planlama ve altyapı başlangıcı içindir. Sonraki işler ilgili ajan tarafından üstlenilecek.
