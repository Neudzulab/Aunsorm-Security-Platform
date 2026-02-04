# Agent Charter ve Sprint Intake Kılavuzu

*Revizyon: 2025-10-24*

Bu belge, Aunsorm Crypt platformundaki uzman ajanların kapsamını ve
revizyon kilidi politikasına uyumlu sprint intake sürecini standartlaştırır.
Her ajan, kendi alanındaki teslimatları yönetirken burada listelenen
kontrol noktalarını takip etmekten sorumludur.

## Agent Charter Özeti

| Ajan | Birincil Kapsam | Ana Teslimatlar | Kritik Kontrol Noktaları |
| ---- | --------------- | ---------------- | ------------------------ |
| **Project Coordinator** | Planlama artefaktları (PROD_PLAN.md, ROADMAP.md, TODO.md) | Sprint hedeflerinin yayımı, revizyon kilidi politikasının uygulanması | Tüm maddelerde sorumlu ajan tayini, kilitli girdilerde değişiklik yapılmadığını doğrulama |
| **Crypto Agent** | `crates/core`, `crates/pqc`, `crates/packet` | Kalibrasyon bağlamı, ratchet yaşam döngüsü, PQC köprüleri | `#![forbid(unsafe_code)]` ve `#![deny(warnings)]` denetimleri; fuzz/bench artefaktlarının güncelliği |
| **Platform Agent** | `crates/cli`, `crates/server`, `crates/wasm` | Endpoint ağacı, CLI/WASM uyumu, dağıtım runbook'ları | README endpoint ağacı ↔ `crates/server` routes eşleşmesi, servis ağacı durum etiketleri |
| **Identity Agent** | `crates/jwt`, `crates/x509`, `crates/kms`, `certifications/` | JWT/X.509/KMS akışları, sertifikasyon raporları | Known Answer Test (KAT) fixture'ları ve CI gating'in güncel tutulması |
| **Interop Agent** | `benches/`, `fuzz/`, `crates/pytests/`, `examples/`, `.github/` | CI entegrasyonları, fuzz/bench raporları, dil köprüleri | 10k exec sanity sonuçları, workflow'larda başarısız koşular için uyarı mekanizmaları |

Her ajan, kapsamındaki `AGENTS.md` yönergelerini güncel tutmakla ve yeni
alt dizinler oluşturulduğunda ek talimatlar sağlamaktan sorumludur.

## Revizyon Kilidiyle Uyumlu Çalışma İlkeleri

1. `[x]` olarak işaretlenen tüm maddeler revizyon kilidi altındadır.
   - Değişiklik ihtiyacı olduğunda aynı satır düzenlenmez; `Revize:` öneki ile
     yeni madde açılır ve orijinal girdiye referans verilir.
   - Revizyon isteği PROD_PLAN.md'de yeni bir teslimat olarak listelenir ve sorumlu
     ajan atanır.
2. README, TODO ve PROD_PLAN artefaktları senkron tutulur.
   - Yeni endpoint veya özellik ekleyen her değişiklik README servis ağacında
     durum etiketi (✅/🚧/📋/🔮) ile belgelenir.
   - `crates/server/routes` güncellemeleri ile README ağacı karşılaştırılır.
3. Her commit öncesi zorunlu denetimler tamamlanır:
   - `cargo fmt --all`
   - `cargo clippy --all-targets --all-features`
   - `cargo test --all-features`
   - İlgiliyse `npm test` veya diğer dil köprüsü testleri
4. Güvenlik gerekçesiyle `unsafe` kod yasağı ihlal edilmez; yeni bağımlılıklar
   `deny.toml` ve `cargo audit` süreçleriyle doğrulanır.
5. Dokümantasyon güncellemeleri mdBook içinde doğru başlık altında
   listelenir ve `docs/src/SUMMARY.md` dosyasında gezinme bağları eklenir.

## Sprint Intake Checklist

Aşağıdaki adımlar, yeni bir sprint hedefi kabul edilmeden önce tamamlanmalıdır:

1. **Kapsam Doğrulaması**
   - PROD_PLAN.md üzerinde yeni teslimat maddesi açıldı mı?
   - Sorumlu ajan ve hedef tarih belirtildi mi?
2. **Revizyon Kilidi Tarama**
   - README/TODO/ROADMAP içindeki `[x]` maddeleri üzerinde değişiklik
     yapılmayacağını teyit et.
   - Gerekliyse `Revize:` maddeleri oluştur.
3. **Bağımlılık ve Çapraz Ekip Bağlantıları**
   - Endpoint değişiklikleri için Platform Agent, kimlik akışları için
     Identity Agent ile etkileşim planı belirlendi mi?
   - Interop Agent'a CI/benchmark etkisi bildirildi mi?
4. **Test ve Gating Planı**
   - Minimum test seti (`cargo test`, fuzz sanitesi, bençmark) listelendi mi?
   - Dış sistem erişimi gerekiyorsa (KMS, ACME) fixture veya mock planı var mı?
5. **Dokümantasyon ve İletişim**
   - İlgili dokümanlar (mdBook, README, AGENTS) için güncelleme sorumluları
     belirlendi mi?
   - Gerektiğinde AGENTS-REQUESTS.md üzerinden myeoffice ekibi ile paylaşılacak
     notlar hazırlandı mı?
6. **Onay ve Kilitleme**
   - Project Coordinator tarafından sprint intake formu gözden geçirildi mi?
   - Tüm ajanlar görev dağılımını `devam` komutuyla tetiklenecek sıraya göre
     onayladı mı?

## Seremoni ve İzleme

- **Günlük Durum:** Her ajan kendi kapsamındaki blokajları kısa not olarak
  paylaşır; değişiklik gerektiren kilitli maddeler için revizyon süreci başlatılır.
- **Sprint Review:** Teslimatlar README üzerindeki durum etiketleri ve
  test artefaktları ile birlikte sunulur.
- **Retrospektif:** Revizyon kilidi ihlalleri, geciken testler veya eksik
  dokümantasyon örnekleri kayda alınır ve bir sonraki sprint intake
  checklist'ine geri besleme yapılır.

Bu kılavuz, `PROD_PLAN.md` üzerinde listelenen STEP-AUN-001 hedefinin tamamlandığını
belgeler ve gelecekteki sprint'ler için standart referans olarak kullanılmalıdır.
