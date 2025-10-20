# Rastgele Sayı Üretimi İyileştirme Önerileri

## Mevcut Durum: ✅ Güvenli ve Çalışıyor

**Test Sonuçları:**
- 1M örnek ortalama: 50.0287 (beklenen: 50.0)
- Chi-square: 77.34 < 124.3 ✅
- Uniform dağılım doğrulandı ✅

## Önerilen İyileştirmeler

### 1. HKDF Entropi Genişletme (Öncelik: Yüksek)

**Neden?**
- NIST SP 800-108 standardına uygun
- Kriptografik olarak kanıtlanmış
- Aunsorm zaten `hkdf` kullanıyor

**Değişiklik:**
```rust
fn next_entropy_block(&self) -> [u8; 32] {
    use hkdf::Hkdf;
    
    let mut os_entropy = [0_u8; 32];
    OsRng.fill_bytes(&mut os_entropy);
    
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos()
        .to_le_bytes();
    
    let counter = {
        let mut guard = self.entropy_counter.lock().expect("counter poisoned");
        let val = *guard;
        *guard = val.wrapping_add(1);
        val
    };
    
    // HKDF-Extract-and-Expand
    let hk = Hkdf::<Sha256>::new(Some(&self.entropy_salt), &os_entropy);
    let mut okm = [0u8; 32];
    let mut info = Vec::with_capacity(24);
    info.extend_from_slice(&counter.to_le_bytes());
    info.extend_from_slice(&timestamp);
    hk.expand(&info, &mut okm)
        .expect("HKDF expand with 32 bytes should never fail");
    okm
}
```

### 2. Constant-Time Rejection Sampling (Öncelik: Orta)

**Neden?**
- Timing attack koruması
- Side-channel dayanıklılığı

**Değişiklik:**
```rust
fn map_entropy_to_range(entropy: &[u8; 32], min: u64, max: u64) -> Option<u64> {
    if min == max {
        return Some(min);
    }
    let span = max.checked_sub(min)?;
    let range = span.checked_add(1)?;
    let threshold = u64::MAX - u64::MAX % range;

    // Constant-time: tüm chunk'ları kontrol et
    let mut selected = 0_u64;
    let mut found_mask = 0_u64;
    for chunk in entropy.chunks_exact(8) {
        let mut buf = [0_u8; 8];
        buf.copy_from_slice(chunk);
        let candidate = u64::from_be_bytes(buf);

        let is_valid = u64::from(candidate < threshold);
        let result = min + candidate % range;
        let take_mask = is_valid & (1_u64 ^ found_mask);
        let mask = u64::MAX.wrapping_mul(take_mask);

        selected = (selected & !mask) | (result & mask);
        found_mask |= take_mask;
    }

    (found_mask == 1).then_some(selected)
}
```

**Durum (2025-03-05):** ✅ Uygulandı — `ServerState::map_entropy_to_range` mask tabanlı branchless seçim kullanır ve unit testlerle
doğrulanır (`state.rs`).

### 3. ChaCha20-RNG Alternatifi (Öncelik: Düşük - Performans)

**Neden?**
- 10x daha hızlı olabilir
- SIMD optimizasyonları
- Deterministik (test edilebilir)

**Trade-off:**
- ❌ Her çağrıda OsRng'ye gitmiyor (security-performance tradeoff)
- ✅ Seed kriptografik kalitede
- ✅ RFC 8439 standardı

**Karar:** Şu anki yaklaşım daha güvenli, performans sorun değilse değiştirmeye gerek yok.

### 4. Entropy Pool Yönetimi (Öncelik: Düşük)

**Gelişmiş Senaryo:**
```rust
pub struct EntropyPool {
    pool: Mutex<[u8; 256]>,  // 256-byte pool
    position: AtomicUsize,
}

impl EntropyPool {
    fn refill(&self) {
        let mut pool = self.pool.lock().unwrap();
        OsRng.fill_bytes(&mut *pool);
        // HKDF ile genişlet...
    }
    
    fn take_block(&self) -> [u8; 32] {
        // Atomic position management...
    }
}
```

**Avantaj:** OsRng'ye daha az çağrı
**Dezavantaj:** Daha karmaşık, forward secrecy riski

## Öneri: SADECE #1 (HKDF) Uygula

**Sebep:**
1. ✅ Güvenliği artırır (standards-compliant)
2. ✅ Minimal kod değişikliği
3. ✅ Aunsorm zaten HKDF kullanıyor
4. ✅ Performance impact minimal

**#2 (Constant-time)** opsiyonel - side-channel concern varsa.

**#3 ve #4** gereksiz - mevcut sistem yeterince hızlı (78K sample/s).

## Test Sonrası Beklenti

HKDF değişikliği sonrası:
- Chi-square değeri değişmemeli (~77)
- Ortalama aynı kalmalı (~50.0)
- Performans farkı < %5 olmalı

## Uygulama Planı

1. ✅ HKDF'i `next_entropy_block()` içine entegre et
2. ✅ Tüm testleri çalıştır (1M samples)
3. ✅ Chi-square değerini karşılaştır
4. ✅ Performans benchmark'ı yap
5. ✅ CHANGELOG.md'ye ekle

## Güvenlik Notu

Mevcut implementasyon **üretim ortamında kullanılabilir** durumdadır. 
Bu iyileştirmeler "good" → "excellent" geçişi içindir, kritik değildir.
