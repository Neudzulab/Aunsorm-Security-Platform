# Contributing to Aunsorm

Teşekkürler! Aunsorm; güçlü kalibrasyon bağlamı, oturum ratchet'i ve opsiyonel PQC desteğiyle kurumsal güvenlik hedefleyen bir araçtır. Bu rehber, değişiklik teklif etmeden önce izlemeniz gereken adımları açıklar.

## Temel İlkeler
- En düşük desteklenen Rust sürümü (MSRV) **1.76**'dır. Rustup ile bu sürümü aktif tutun.
- Tüm crate'ler `#![forbid(unsafe_code)]`, `#![deny(warnings)]` ve `clippy::all/pedantic/nursery` deny yönergelerini taşır. `#[allow]` kullanmanız gerekirse dosyada gerekçeli yorum bırakın.
- Kalibrasyon bağlamı **EXTERNAL** gereksinimine uymayan kod değişiklikleri kabul edilmez. API'lar kalibrasyon metni olmadan çalışmamalıdır.
- Strict kip (`AUNSORM_STRICT=1`) geri dönüşlere izin vermez. Yeni özellikler strict kipini açıkken kapsayacak şekilde test edilmelidir.
- `zeroize` ile gizli materyalleri temizlemeyi unutmayın; yeni buffer tipleri ekleniyorsa drop davranışlarını test edin.

## Geliştirme Akışı
1. Depoyu çatallayın ve anlamlı bir dal adı kullanın (ör. `feature/jti-cache`).
2. Değişiklik öncesi `cargo fetch` ile bağımlılıkları güncelleyin.
3. Kod yazarken `cargo fmt --all` ve `cargo clippy --all-targets --all-features` komutlarını düzenli olarak çalıştırın.
4. Yeni iş mantıkları için birim testleri, entegrasyon testleri ve mümkünse proptest senaryoları ekleyin.
5. Ratchet, paket ve KMS bileşenleri için geriye dönük uyumu belgelemek adına `CHANGELOG.md` dosyasını güncelleyin.

## Test ve Doğrulama
Aşağıdaki komutlar PR açmadan önce **zorunludur**:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features
cargo test --all-features
```

Ek olarak:
- Fuzz hedeflerine dokunuyorsanız `cargo fuzz run <target> -- -runs=10000` çalıştırın ve çıktıyı paylaşın.
- Benchmark senaryolarını değiştiriyorsanız `cargo bench` sonuçlarını dokümante edin.

## Belgelendirme
- Yeni özellikler için ilgili crate `README.md` dosyasını güncelleyin.
- Kullanıcı akışlarını etkileyen değişikliklerde `SECURITY.md` ve `README.md` üzerinde tehdit modeli/quickstart bölümlerini gözden geçirin.
- Diyagram gerekiyorsa [Mermaid](https://mermaid.js.org/) kullanın ve kaynak dosyayı repo içine ekleyin.

## Pull Request Etiketi
- PR açıklamasında ilgili ajanı ve tamamlanan gereksinimleri belirtin.
- Her PR için `make_pr` aracını kullanarak özet ve test çıktılarıyla birlikte teklif gönderin.
- İnceleme geri bildirimlerini adreslerken `fixup!` commit'leri yerine değişiklikleri düzenli commit geçmişiyle yeniden yazmayı tercih edin.

## Güvenlik Bildirimleri
Bir güvenlik açığı keşfettiyseniz kamuya açık bir PR açmak yerine `security@aunsorm.example` adresiyle iletişime geçin. Ayrıntılar için `SECURITY.md` dokümanına bakın.

Mutlu katkılar!
