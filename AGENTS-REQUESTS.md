# Agent İstek Sistemi

**Bu dosya agent'lar arası iletişim için kullanılır.**

## 🔄 Nasıl Çalışır?

### myeoffice Agent'ları (Web App):
1. ✅ **Bu dosyaya yazabilir** - Zasian/Aunsorm'dan özellik isteyebilir
2. ❌ **Zasian/Aunsorm dosyalarına DOKUNMAZ**
3. ✅ Sync sonrası cevapları bu dosyada okur

### Zasian/Aunsorm Agent'ları:
1. ✅ **Bu dosyayı okur** - İstekleri görür
2. ✅ **Kendi repo'larında implementasyon yapar**
3. ✅ **Bu dosyayı günceller** - Status ve sonuçları yazar
4. ✅ Sync sonrası myeoffice repo'suna döner

## 📝 İstek Formatı

```markdown
### [REQUEST-XXX] Kısa Başlık (Tarih: YYYY-MM-DD)

**Talep Eden:** myeoffice-agent / developer
**Hedef Repo:** zasian-media / aunsorm-crypt
**Öncelik:** 🔴 Urgent / 🟡 Normal / 🟢 Low

**Açıklama:**
[Detaylı açıklama]

**Beklenen Davranış:**
[Ne istiyorsun?]

**Kullanım Örneği:**
```typescript
// Code example
```

**Status:** 
- [ ] 📋 Pending (Bekleniyor)
- [ ] 🔄 In Progress (Yapılıyor)
- [ ] ✅ Done (Tamamlandı - commit hash: abc123)
- [ ] ❌ Rejected (Reddedildi - sebep: ...)
```

---

## 🎯 Aktif İstekler

<!-- myeoffice agent'ları buraya istek ekleyin -->

---

## ✅ Tamamlanan İstekler

<!-- Tamamlanan istekler buraya taşınır -->

---

## 📚 Sync Kuralları

**⚠️ ÇOK ÖNEMLİ:**

1. **myeoffice tarafı GÜÇ sahibi:**
   - Sync conflict'te myeoffice versiyonu kazanır
   - Zasian/Aunsorm istekleri eklemez, sadece status günceller

2. **Sync workflow:**
   ```bash
   # myeoffice → dev (istek gidiyor)
   cp AGENTS-REQUESTS.md zasian-media-dev/
   cp AGENTS-REQUESTS.md aunsorm-crypt-dev/
   
   # dev → myeoffice (status dönüyor)
   # Manuel merge gerekirse myeoffice versiyonu tutar
   ```

3. **Conflict çözümü:**
   - myeoffice yeni istek ekledi → Koru
   - dev status güncelledi → Merge et
   - Her ikisi de aynı satırı değiştirdi → myeoffice kazanır

---

## 📖 Örnek İstek

### [REQUEST-001] DataChannel Audio Routing (2025-10-18)

**Talep Eden:** myeoffice-agent
**Hedef Repo:** zasian-media
**Öncelik:** 🔴 Urgent

**Açıklama:**
WebRTC DataChannel üzerinden lossless audio routing gerekiyor. Opus yerine direkt PCM + Codec B kullanılacak.

**Beklenen Davranış:**
```typescript
// apps/web/lib/zasian-datachannel-client.ts
async sendAudioFrame(pcmData: Float32Array) {
  const compressed = await codecB.encode(pcmData);
  this.dataChannel.send(compressed);
}
```

**Status:**
- [x] 📋 Pending (2025-10-18 21:00)
- [ ] 🔄 In Progress
- [ ] ✅ Done
- [ ] ❌ Rejected

**Zasian Agent Notes:**
<!-- Zasian agent buraya notlar ekleyecek -->
