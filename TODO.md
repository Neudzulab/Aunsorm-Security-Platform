# Aunsorm Crypt Görev Listesi

## Tamamlanan Ana İşler
- [x] Sprint 0 planlama ve altyapı teslimleri (çekirdek, paket, PQC, CLI/Server/WASM, test ve dokümantasyon). (Bkz. README.md, "Sprint 0" bölümü.)
- [x] Sprint 1 kripto ve paket temelleri (KDF otomasyonu, AEAD/strict kip, ratchet, replay koruması ve PQC köprüsü). (Bkz. README.md, "Sprint 1".)
- [x] Sprint 2 kimlik ve platform katmanları (KMS entegrasyonları, JWT/X.509 akışları, sunucu uçları). (Bkz. README.md, "Sprint 2".)
- [x] Sprint 3 interop ve dağıtım çalışmaları (WASM, Python testleri, CI fuzz/bench ve gözlemlenebilirlik). (Bkz. README.md, "Sprint 3".)
- [x] Bonus vizyon prototipleri (WebTransport adaptörü, kilitli bellek planı, key transparency). (Bkz. README.md, "Bonus (Vizyon)")
- [x] mdBook dokümantasyonunun CI pipeline'ında otomatik derlenmesi ve artefakt olarak yayımlanması. (Bkz. CHANGELOG.md "Added" ve README.md "Belgeler".)

## Öncelikli Geliştirme İşleri
- [x] Uzak KMS sağlayıcıları (GCP/Azure) için canlı soak test harness'ini tamamla. (Bkz. CHANGELOG.md "Added".)
- [x] ML-DSA için üretim düzeyi sertleştirme ve istemci tarafı denetim listelerini genişlet. (Bkz. docs/src/appendix/roadmap.md.)
- [x] `cargo fuzz cmin` tabanlı uzun süreli fuzz korpusu minimizasyonunu nightly pipeline'a entegre et. (Bkz. docs/src/appendix/roadmap.md.)
- [x] Harici KMS/HSM sağlayıcıları için ek conformance fixture'ları ve sertifikasyon raporlarını üret. (Bkz. docs/src/operations/kms_conformance.md ve crates/kms/tests/data/.)

## Dokümantasyon ve İzleme
- [x] Yol haritasındaki mdBook otomasyon maddesini (artık tamamlandı) güncel durumu yansıtacak şekilde revize et. (Bkz. docs/src/appendix/roadmap.md ile CHANGELOG.md.)
