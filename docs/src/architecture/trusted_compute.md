# Kilitli Bellek ve Güvenli Donanım Entegrasyon Planı

Aunsorm'un tehdit modeli, kalibrasyon bağlamı olmadan verinin açılmaması
ve oturum anahtarlarının kalıcı hâle gelmemesi üzerine kurulu. Bu hedefi
pekiştirmek için kritik sırların çalışma belleğinde kilitlenmesi ve
üretim dağıtımlarında Intel SGX ile AMD SEV gibi güvenli yürütme
ortamlarından yararlanılması planlanmaktadır.

## Tehdit Modeli ve Amaçlar

- **Saldırı yüzeyi:** Yetkisiz kök erişimi, swap dosyası sızıntıları ve
  hipervizör/konuk ayrımı ihlalleri.
- **Amaçlar:**
  1. Anahtar materyalinin RAM dışına taşmasını engellemek.
  2. Remote attestation ile `strict` kipindeki dağıtımları doğrulamak.
  3. Donanım destekli izolasyonlarda bile kalibrasyon akışının aynı
     deterministik sözleşmeleri sağlamasını garanti altına almak.

## Bellek Kilitleme Stratejisi

1. `aunsorm-core` içerisinde kullanılan `SensitiveVec` yapısı, `mlock`
   ve `mprotect` çağrılarını soyutlayan yeni bir `LockedMemory`
   yardımcı modülüyle genişletilecektir.
   - POSIX hedeflerinde [`memsec`](https://crates.io/crates/memsec) ve
     `libc::mlock` kombinasyonu;
   - Windows hedeflerinde `VirtualLock` çağrısı kullanılacaktır.
2. Kilitleme başarısız olduğunda `strict` kipte hata verilecek,
   gevşek kipte ise olay `tracing` aracılığıyla yüksek önemde loglanacak.
3. Zeroize mantığı kilit çözülmeden önce çağrılacak; bu adım CI'da
   `cargo miri test` ile doğrulanacak.
4. CLI ve server katmanları, parola/sessiz anahtar girdilerini bellek
   kilitleme API'sine teslim edecek. Böylece uygulama sınırlarında
   taşıma süreleri minimize edilecek.

## Intel SGX Entegrasyonu

1. `aunsorm-core` ve `aunsorm-kms` için ortak bir enclave kitaplığı
   hazırlanacak (`crates/enclave`). Bu kitaplık, HKDF ve PQC operasyonlarını
   enclave içinde koşacak şekilde `no_std` profiliyle derlenecek.
2. Enclave ile host arasındaki çağrılar için `ecall`/`ocall` yüzeyi,
   `packet` crate'inin DTO türleriyle birebir uyumlu olacak.
3. Remote attestation çıktıları, server tarafından `AUNSORM_STRICT`
   ortam değişkeni set edildiğinde zorunlu tutulacak ve JWT introspection
   endpoint'i attested durum bitini doğrulayacak.
4. CI pipeline'ına `sgx-lkl` tabanlı bir entegrasyon testi eklenerek
   temel encrypt/decrypt ve oturum ratchet senaryolarının enclave içinde
   koştuğu doğrulanacak.

## AMD SEV ve TDX Yol Haritası

1. Kapsayıcı görüntüler, `sevctl` ve `qemu` entegrasyonu ile SEV-ES/SEV-SNP
   doğrulama adımlarını içerecek şekilde güncellenecek.
2. Server dağıtımları için, başlatma sırasında misafir ölçümü (`launch
   digest`) alınarak kalibrasyon koordinatlarına bağlanacak ve koordinat
   hash'i JWT token payload'ına gömülecek.
3. Gelecekteki TDX desteği, SEV ile aynı API yüzeyini kullanacak; böylece
   CLI tarafındaki kullanıcı deneyimi değişmeden kalacak.

## Doğrulama ve Yol Haritası

- **Kısa vadeli teslimler:** `LockedMemory` modülü, CLI/server entegrasyonu
  ve negatif testler.
- **Orta vadeli teslimler:** SGX enclave prototipi, attestation doğrulama
  kancaları, CI kapsaması.
- **Uzun vadeli teslimler:** SEV/TDX entegrasyon testleri, üretim dökümantasyonu
  ve operasyonel playbook güncellemeleri.

Bu plan tamamlandığında, Aunsorm dağıtımları bellek taşmalarına ve
hipervizör saldırılarına karşı önemli ölçüde güçlendirilmiş olacaktır.
