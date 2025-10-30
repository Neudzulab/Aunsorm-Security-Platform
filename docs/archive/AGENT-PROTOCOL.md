# Aunsorm Media Agent Protocol

**Bu dosya Aunsorm agent'ları için özel talimatlar içerir.**

## 🎯 Görev: İstek Sistemi

Aunsorm agent'ları **myeoffice repo'sundan gelen isteklere** göre çalışır.

### 📋 İstek Kaynağı

**Dosya:** `AGENTS-REQUESTS.md` (repo root'da)

```bash
# Bu dosyayı kontrol et
cat AGENTS-REQUESTS.md | grep "aunsorm-crypt"
```

### ✅ İş Akışı

1. **İstekleri oku:**
   ```markdown
   ### [REQUEST-XXX] Başlık
   **Hedef Repo:** aunsorm-crypt
   **Status:** 📋 Pending
   ```

2. **Implementasyon yap:**
   - Kendi repo'nda (aunsorm-crypt-dev) kod yaz
   - Test et
   - Commit et

3. **Status güncelle:**
   ```markdown
   **Status:**
   - [x] 📋 Pending (2025-10-18)
   - [x] 🔄 In Progress (2025-10-18 22:00 - Agent started)
   - [ ] ✅ Done
   
   **Implementation Notes:**
   - Commit: abc123def
   - Files changed: crates/audio-codec/src/datachannel.rs
   - Breaking changes: None
   ```

4. **AGENTS-REQUESTS.md'yi güncelle:**
   - Status'u değiştir
   - Notes ekle
   - Commit et

5. **Sync bekle:**
   - Developer sync yapınca değişiklikler myeoffice'e gider
   - myeoffice agent'ları sonucu görür

### 🚫 Yasaklar

**❌ ASLA YAPMA:**
- myeoffice repo'suna direkt değişiklik
- AGENTS-REQUESTS.md'ye yeni istek ekleme (sadece status güncelle!)
- Kendi repo dışında değişiklik

**✅ SADECE YAP:**
- AGENTS-REQUESTS.md status güncellemesi
- Kendi repo'nda implementasyon
- Commit message'larda REQUEST-XXX referans ver

### 📝 Örnek Workflow

```bash
# 1. İsteği gör
cat AGENTS-REQUESTS.md | grep -A 20 "REQUEST-001"

# 2. Implementasyon yap
code crates/audio-codec/src/datachannel.rs
cargo test

# 3. Commit et
git add .
git commit -m "feat(REQUEST-001): DataChannel audio routing

Implements lossless audio over DataChannel.
- Added pcm_to_datachannel() function
- Codec B integration
- Tests passing

Closes REQUEST-001"

# 4. Status güncelle
code AGENTS-REQUESTS.md
# Status: In Progress → Done
git add AGENTS-REQUESTS.md
git commit -m "docs(REQUEST-001): Mark as completed"

# 5. Sync bekle (developer yapar)
```

### 🔄 Sync Kuralları

**myeoffice → Aunsorm-dev:**
- AGENTS-REQUESTS.md yeni isteklerle gelir
- Senin status güncellemen kaybolmaz (manuel merge)

**Aunsorm-dev → myeoffice:**
- Senin kod değişikliklerin gider
- AGENTS-REQUESTS.md status güncellemen gider

### 🎯 Öncelik Sistemi

- 🔴 **Urgent**: Hemen başla, aynı gün bitir
- 🟡 **Normal**: 1-2 gün içinde
- 🟢 **Low**: Backlog, zamanın olunca

### 📞 İletişim

**Soru/Problem varsa:**
- AGENTS-REQUESTS.md'ye not ekle:
  ```markdown
  **Agent Question:**
  > Bu özellik için X kütüphanesi gerekiyor, ekleyebilir miyim?
  
  **Developer Response:** (myeoffice agent cevaplayacak)
  ```

---

## 🚀 Hızlı Başlangıç

```bash
# İstek var mı kontrol et
grep -A 10 "Status.*Pending" AGENTS-REQUESTS.md | grep "aunsorm-crypt"

# Varsa implement et
# 1. Kod yaz
# 2. Test et
# 3. Commit et
# 4. AGENTS-REQUESTS.md güncelle
# 5. Commit et
# 6. Bekle (developer sync yapar)
```
