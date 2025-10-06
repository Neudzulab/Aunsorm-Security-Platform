# aunsorm-pqc Ajanı Rehberi

- `aunsorm-pqc`, ML-KEM ve PQC imza algoritmalarını köprüler; tüm algoritma isimleri `ml-kem-*`
  ve `ml-dsa-*` biçiminde küçük harfli olmalıdır.
- Strict kipte fallback'e izin verilmeyeceği senaryolar için `StrictMode` kullanarak çevre
  değişkenlerini okuyun.
- KEM ve imza anahtarları `Zeroizing` ile korunmalı, paylaşılan sırlar hiçbir şekilde düz metin
  olarak bırakılmamalıdır.
- Testler her algoritma için hem pozitif hem de negatif yolu içermelidir; desteklenmeyen
  algoritmalarda `StrictRequired` hatası beklenir.
