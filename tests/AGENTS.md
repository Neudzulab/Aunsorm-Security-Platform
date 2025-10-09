# Hacker Agent Rehberi

Bu dizin, beyaz şapka (white-hat) penetrasyon ve regresyon testleri için "Hacker Agent" tarafından yönetilir.

- Testler saldırı senaryolarını deterministik ve tekrar üretilebilir şekilde kurgulamalıdır.
- Her test, beklenen korumanın bozulmadığını doğrulayan açık bir iddia içermelidir.
- Paket manipülasyonları, gerçekçi bir saldırganın yapabileceği adımları simüle etmeli; yeni yardımcı
  fonksiyonlar gerekiyorsa önce burada belgelenmelidir.
- Kod stili mevcut entegrasyon testleriyle tutarlı olmalı ve gereksiz bağımlılıklardan kaçınılmalıdır.
