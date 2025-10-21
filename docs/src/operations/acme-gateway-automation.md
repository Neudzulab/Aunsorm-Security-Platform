# ACME Gateway Otomasyonu

Bu runbook, Aunsorm ACME servisinin gateway uç noktaları için üretim
sertifikalarını otomatik olarak üretip dağıtmak amacıyla izlenecek adımları
belgeler. Amaç, self-signed sertifika betiklerinden çıkarak sürekli yenilenen
bir Let’s Encrypt benzeri süreçle operasyonel riski azaltmaktır.

## Önkoşullar

- `aunsorm-cli` binary'si PATH üzerinde veya komut satırında `--cli` parametresi
  ile erişilebilir olmalıdır.
- Gateway'in CSR üretim zinciri hazır olmalıdır (örnek: `openssl req` veya
  mevcut özel anahtı ile üretilmiş PEM/DER CSR dosyası).
- Aunsorm ACME servisinin `http(s)://HOST:PORT/acme/*` uçları erişilebilir
  durumda olmalı, firewall ve DNS yönlendirmeleri tamamlanmalıdır.
- Operasyon ekibi üretim domain'leri için ACME doğrulama yöntemine (HTTP-01,
  DNS-01, vb.) uygun otomasyonu hazırlamış olmalıdır. Bu runbook finalize
  adımına odaklanır; challenge doğrulamaları ayrı sprintte tamamlanacaktır.

## Manuel CLI Akışı

Aşağıdaki adımlar tek tek çalıştırıldığında hesap kaydı, order oluşturma,
finalize ve sertifika indirme işlemlerini gerçekleştirir:

```bash
# 1. Hesap kaydı (state dosyası güncellenir)
aunsorm-cli acme register \
  --server https://aunsorm.example.com \
  --account /etc/aunsorm/acme/account.json \
  --email infra@example.com \
  --accept-terms

# 2. Order oluşturma (yanıt artefaktı JSON olarak kaydedilir)
aunsorm-cli acme order \
  --server https://aunsorm.example.com \
  --account /etc/aunsorm/acme/account.json \
  --domain gateway.example.com \
  --output /var/lib/aunsorm/acme/order.json

# 3. CSR ile finalize etme
aunsorm-cli acme finalize \
  --server https://aunsorm.example.com \
  --account /etc/aunsorm/acme/account.json \
  --csr /etc/aunsorm/acme/gateway.csr \
  --output /var/lib/aunsorm/acme/finalize.json

# 4. Sertifika zincirini indirme
aunsorm-cli acme fetch-cert \
  --server https://aunsorm.example.com \
  --account /etc/aunsorm/acme/account.json \
  --output /etc/aunsorm/tls/gateway-fullchain.pem
```

- `account.json` dosyası ACME hesabına ait özel anahtar ve son order snapshot’ını
  içerir; gizli olarak saklanmalıdır.
- `gateway-fullchain.pem` dosyası leaf + issuing CA zincirini içerir. Gateway
  servisinin beklediği formata göre private key ile birlikte uygun dizine
  kopyalanmalıdır.

## Otomasyon Betiği

Manuel adımların tamamı `scripts/deploy_gateway_cert.sh` betiği ile
otomatikleştirilebilir. Betik, register → order → finalize → fetch sırasını tek
komutla çalıştırır ve çıktı artefaktlarını belirttiğiniz klasöre yazdırır.

```bash
scripts/deploy_gateway_cert.sh \
  --server https://aunsorm.example.com \
  --account /etc/aunsorm/acme/account.json \
  --email infra@example.com \
  --domain gateway.example.com \
  --csr /etc/aunsorm/acme/gateway.csr \
  --bundle /etc/aunsorm/tls/gateway-fullchain.pem \
  --output-dir /var/lib/aunsorm/acme \
  --reload-cmd 'systemctl reload gateway.service'
```

Komut başarıyla tamamlandığında standart çıktıda aşağıdaki özet paylaşılır:

```
ACME sertifika dağıtımı tamamlandı.
  Account state : /etc/aunsorm/acme/account.json
  Order yanıtı  : /var/lib/aunsorm/acme/order.json
  Finalize yanıt: /var/lib/aunsorm/acme/finalize.json
  Sertifika     : /etc/aunsorm/tls/gateway-fullchain.pem
```

Betik varsayılan olarak `aunsorm-cli` binary'sini PATH üzerinden çağırır;
isterseniz `--cli /opt/aunsorm/bin/aunsorm-cli` parametresiyle farklı bir yol
belirtebilirsiniz. `--reload-cmd` parametresi sertifika indirildikten sonra
ağ hizmetini yeniden yüklemek veya config dağıtımı yapmak için kullanılabilir.
Komut `bash -c` üzerinden çalıştırılır ve hata durumunda betik `set -e` nedeniyle
non-zero kodla sonlanır.

## Yenileme ve Cron Planı

Günlük yenileme denemesi için örnek cron girdisi:

```
15 02 * * * /usr/local/bin/deploy_gateway_cert.sh \
  --server https://aunsorm.example.com \
  --account /etc/aunsorm/acme/account.json \
  --email infra@example.com \
  --domain gateway.example.com \
  --csr /etc/aunsorm/acme/gateway.csr \
  --bundle /etc/aunsorm/tls/gateway-fullchain.pem \
  --output-dir /var/lib/aunsorm/acme \
  --reload-cmd 'systemctl reload gateway.service' \
  >> /var/log/aunsorm/acme-renew.log 2>&1
```

Cron betiği aşağıdaki kontrollerle izlenmelidir:

- `order.json` ve `finalize.json` dosyalarının zaman damgaları her yenilemede
  güncellenmeli; eski dosya tespit edilirse alarm üretin.
- Gateway servisi yeni sertifikayı başarıyla yükledi mi? `systemctl status`
  veya hedef log dosyası kontrol edilmelidir.
- Sertifika bitiş tarihi (örn. `openssl x509 -enddate -noout`) izlenmeli ve
  15 günden kısa süre kaldığında monitoring sistemine uyarı gönderilmelidir.

## Hata Yönetimi

- CLI komutları non-zero çıkış kodu döndürdüğünde `deploy_gateway_cert.sh`
  betiği hemen durur; cron logları veya CI pipeline’ı bu durumu tespit etmelidir.
- `ACME sunucusu problem döndürdü` şeklinde bir hata alınırsa `order.json`
  içindeki `authorizations` alanı incelenerek eksik doğrulama adımları takip
  edilmelidir.
- Sertifika indirme hatalarında (`acme fetch-cert`) genellikle order finalize
  edilmemiş demektir; finalize çıktısı gözden geçirilmelidir.

## İlgili Kaynaklar

- `README.md` → “ACME Onboarding” bölümü, CLI akışına dair hızlı başlangıç
  komutlarını içerir.
- `scripts/deploy_gateway_cert.sh` → Betik kaynağı ve CLI argümanlarının
  referans implementasyonu.
- `CHANGELOG.md` → ACME otomasyonu ile ilgili yayınlanan değişiklikler ve sürüm
  notları.
