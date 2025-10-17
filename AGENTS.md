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
