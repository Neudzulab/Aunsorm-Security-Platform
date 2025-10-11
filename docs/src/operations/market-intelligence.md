# Pazar İstihbaratı ve Gelecek Vizyonu Çalıştayı

Bu belge, Aunsorm ekibinin uzman geri bildirimleri toplaması, rakip/piyasa analizlerini güncel tutması, yeni teknolojileri değerlendirmesi ve bu içgörülerle gelecek vizyon planını şekillendirmesi için izlenecek süreci tanımlar.

## 1. Hedef ve Kapsam
- **Amaç:** Ürünün stratejik yol haritasını güncellemek, müşteri ve piyasa beklentilerine uyumlu olacak şekilde öncelikleri netleştirmek.
- **Kapsam:** Kriptografi ve güvenlik modülleri, platform entegrasyonları, operasyonel süreçler ve müşteri deneyimi.
- **Zamanlama:** Her çeyrekte en az bir kez, büyük özellik sürümleri öncesinde ekstra tur.

## 2. Uzman Geri Bildirim Programı
1. **Uzman Havuzunun Güncellenmesi**
   - Akademi, endüstri ve topluluk içinden en az 12 aktif danışman listesi tut.
   - Her danışmanın uzmanlık alanı (PQC, KMS, uyumluluk vb.) ve iletişim tercihini kaydet.
2. **Odağımızdaki Sorular**
   - Kalibrasyon bağlama zorunluluğu ve pratik kullanım geri bildirimleri.
   - PQC geçiş senaryolarında performans/operasyonel riskler.
   - Regülasyon (eIDAS 2.0, NIS2, KVKK) ve denetim beklentileri.
3. **Toplama Yöntemi**
   - Ayda bir asenkron anket (Mattermost/Forms) + kritik konular için iki ayda bir 60 dakikalık çevrim içi oturum.
   - Yanıtların `%` skorlaması ile özetlenmesi ve açık uçlu yorumların tematik analizi.
4. **Belgeleme**
   - `docs/src/operations/feedback-log/` altında tarih bazlı notlar.
   - Ana risk/öneri maddelerini PLAN.md üzerinde ilgili sprint planlarına referansla ilişkilendir.

## 3. Rakip ve Piyasa Analizi
1. **Rakip Haritalaması**
   - Doğrudan rakipler (örn. PQC destekli E2EE platformları) ve dolaylı rakipler (MSSP, KMS sağlayıcıları) için veri tabanı oluştur.
   - Her rakip için ürün kapsamı, fiyatlandırma, öne çıkan özellikler, sertifikasyon durumu.
2. **Sinyal Toplama Kanalları**
   - RSS/Atom takipleri, sektör raporları, standart kuruluşları (IETF, ETSI), regülasyon duyuruları.
   - Sosyal medya ve geliştirici toplulukları için haftalık keyword taraması.
3. **Piyasa Beklentisi Ölçümü**
   - Üç aylık müşteri memnuniyet anketi (Net Satisfaction + Güven skoru).
   - Satış/bizdev ekibinden aylık fırsat geri bildirim raporu.
   - Toplanan metrikler: Özellik talep sıklığı, entegrasyon öncelikleri, uyumluluk ihtiyaçları.
4. **Analiz Çıktısı**
   - Her çeyrek "Pazar Nabzı" raporu: SWOT, trendler, fırsat/tehditler.
   - Kritik bulgular için ürün backlog'unda `market:` etiketi.

## 4. Yeni Teknolojiler ve Entegrasyon Fırsatları
- **Teknoloji Tarama Listesi:** PQC kütüphaneleri, donanım güvenlik modülleri, telemetri/observability araçları, gizlilik artırıcı teknikler (MPC, FHE).
- **Deneme Atölyeleri:** Her büyük sürüm öncesi iki haftalık PoC sprinti; başarı kriterleri: performans kazanımı, güvenlik etkisi, bakım maliyeti.
- **Uyumluluk Kontrolü:** Yeni entegrasyonlar için regülasyon ve iç güvenlik standartı kontrol listesi.
- **Geri Bildirim Döngüsü:** PoC sonuçları uzman danışmanlarla doğrulanır, karar şablonu (Devam/Revizyon/Rafa) oluşturulur.

## 5. Çapraz Fonksiyonel Toplantı Planı
1. **Hazırlık (T-14 gün)**
   - Toplanan uzman geri bildirimleri, rakip raporları ve teknoloji değerlendirmeleri özetlenir.
   - Oturum hedefleri, ön okuma dokümanları ve sorumlular paylaşılır.
2. **Çalıştay Gündemi**
   - Açılış: Son çeyreğin başarı/aksaklık özeti.
   - Bölüm 1: Uzman geri bildirimlerinden çıkan kritik aksiyonlar.
   - Bölüm 2: Piyasa ve rakip trendlerine göre öncelik matrisi.
   - Bölüm 3: Teknoloji entegrasyon PoC sonuçları.
   - Bölüm 4: Karar oturumu – kısa/orta/uzun vadeli yol haritası maddeleri.
3. **Sonrası (T+7 gün)**
   - Kararlar için sahip atanması ve Jira/Linear kartlarının açılması.
   - PLAN.md ve README hedef tablolarının güncellenmesi.
   - Bir sonraki tur için geri bildirim süreç iyileştirme maddeleri.

## 6. Başarı Metrikleri
- Uzman geri bildirimlerinin %80'inin iki sprint içinde aksiyon planına dönüştürülmesi.
- Pazar nabzı raporlarının zamanında yayınlanma oranı ≥ %90.
- Yeni teknoloji PoC'lerinde kabul edilen entegrasyonların sürüm takvimine etkisi ≤ +1 sprint.
- Toplantı sonrası alınan kararların %95'inin takip edildiğine dair kapanış raporu.

## 7. Ekip İletişimi ve Şeffaflık
- Tüm çıktı ve raporlar iç Confluence/MDBook üzerinde yayınlanır.
- Özeti herkesin erişebildiği aylık bülten şeklinde paylaş.
- Toplulukla paylaşılabilir bulgular için blog/konferans sunumları planla.

## 8. Sürekli İyileştirme
- Her çeyrek çalıştayından sonra süreç retrospektifi.
- Elde edilen metrikler ışığında anket soruları ve PoC kriterlerini güncelle.
- Geri bildirim verimliliği düşükse uzman havuzunu genişlet ve teşvik mekanizmasını gözden geçir.

Bu süreç izlendiğinde Aunsorm ekibi ürün vizyonunu canlı tutar, piyasadaki değişimlere hızlı uyum sağlar ve teknoloji liderliğini pekiştirir.
