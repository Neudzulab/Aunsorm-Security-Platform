# Ağ ve Yük Dengeleme Sertleştirmesi

Güncellenen üretim dağıtımı, dış trafik ile mikro servisler arasındaki tüm akışı TLS ile koruyacak, kapıdaki istekleri
oranlamaya tabi tutacak ve DDoS saldırılarına karşı kenar/bulut seviyesinde savunma sağlayacak şekilde düzenlendi. Bu
belge, yapılandırmanın tamamını ve doğrulama adımlarını özetler.

## 1. Ingress Controller + TLS Sonlandırma

- `config/kubernetes/networking/ingress-nginx-values.yaml` dosyası `ingress-nginx` Helm chart'ını üç replika ile kurar,
  AWS NLB üzerinde SSL sertifikasını (`aunsorm-edge-tls`) bağlar ve HSTS/SSL yönlendirmelerini zorunlu kılar.
- `config/kubernetes/networking/aunsorm-gateway-ingress.yaml` manifesti `aunsorm-platform` namespace'ini otomatik
  sidecar enjeksiyonu ile açar, `aunsorm-gateway` servisini tanımlar ve TLS sonlandırmasını sağlayan Ingress kaynağını
  uygular.
- Sertifikalar `kubectl create secret tls aunsorm-edge-tls --namespace ingress-nginx ...` komutu ile yüklenir.

**Doğrulama:**
```bash
helm upgrade --install aunsorm-ingress ingress-nginx/ingress-nginx -n ingress-nginx -f config/kubernetes/networking/ingress-nginx-values.yaml
kubectl apply -f config/kubernetes/networking/aunsorm-gateway-ingress.yaml
kubectl -n ingress-nginx get ingressclass aunsorm-nginx
kubectl -n aunsorm-platform get ingress aunsorm-gateway -o yaml | rg "tls:" -n
```

## 2. Ağ Geçidi Seviyesinde Rate Limiting

- Ingress üzerindeki `nginx.ingress.kubernetes.io/limit-*` anotasyonları istemci başına `120 rps`/`6000 rpm` sınırını uygular.
- `config/kubernetes/networking/istio-controlplane.yaml` içindeki `EnvoyFilter` bölümü, `istio-ingressgateway` için
  yerel Envoy rate-limit filtresini etkinleştirerek katman 7'de saniyede 200 isteği sınırlar ve 429 yanıtında
  `Retry-After` başlığı döner.

**Doğrulama:**
```bash
kubectl apply -f config/kubernetes/networking/istio-controlplane.yaml
kubectl -n istio-system get envoyfilter aunsorm-gateway-rate-limit -o yaml | rg "token_bucket"
```

## 3. DDoS Koruması (Cloudflare + AWS Shield)

- `config/cloudflare/ddos-ruleset.yaml` Cloudflare Ruleset API'sine uygun şekilde ülke bazlı managed challenge, tehdit
  puanı bazlı bloklama ve 3000 rpm üzerindeki patlamaları engelleyen kuralları içerir. Dağıtım için `wrangler ruleset
  deploy --config ddos-ruleset.yaml` komutu kullanılabilir.
- `config/aws/shield-advanced.tf` Terraform betiği, ingress NLB'sini Shield Advanced ile korur, ilgili korumayı bir
  Protection Group altında toplar ve varsa WAF WebACL ile otomatik yanıt kuralı etkinleştirir.

**Doğrulama:**
```bash
wrangler ruleset validate config/cloudflare/ddos-ruleset.yaml
terraform -chdir=config/aws init
terraform -chdir=config/aws apply -target=aws_shield_protection.aunsorm_ingress
```

## 4. İç Servis Mesh (Istio) ve Mutual TLS

- `IstioOperator` kaynağı (`config/kubernetes/networking/istio-controlplane.yaml`) minimal profile ile kontrol düzlemini
  kurar ve `istio-ingressgateway` için HPA ayarlarını içerir.
- `PeerAuthentication` objeleri hem küme genelinde hem de `aunsorm-platform` içerisinde mTLS `STRICT` modunu
  zorunlu kılar.
- `DestinationRule` TLS modunu `ISTIO_MUTUAL` olarak ayarlarken bağlantı havuzu parametrelerini de tanımlar.

**Doğrulama:**
```bash
istioctl install -f config/kubernetes/networking/istio-controlplane.yaml
kubectl -n istio-system get peerauthentication default -o yaml | rg "mode: STRICT"
kubectl -n aunsorm-platform get destinationrule aunsorm-gateway -o yaml | rg "ISTIO_MUTUAL"
```

## 5. Devre Kesiciler ve Geri Çekilme Politikaları

- Aynı `DestinationRule` konfigürasyonu `outlierDetection` ile ardışık 5xx hatalarında 30 saniyelik çıkarma uygulayarak
  devre kesici davranışı sağlar.
- `VirtualService` tanımı, 3 denemeye kadar yeniden deneme ve `perTryTimeout` değerleri ile istemciyi şeffaf şekilde
  korur.

**Doğrulama:**
```bash
kubectl -n aunsorm-platform get destinationrule aunsorm-gateway -o yaml | rg "outlierDetection" -n
kubectl -n aunsorm-platform get virtualservice aunsorm-gateway -o yaml | rg "retries" -n
```

## Operasyon Sonrası Adımlar

1. Cloudflare ve AWS Shield alarm metriklerini Prometheus/Grafana panellerine entegre edin.
2. `hey` veya `k6` ile yük testi yaparak rate limit ve devre kesici eşiklerinin beklenen şekilde tetiklendiğini doğrulayın.
3. `kubectl top pod -n istio-system` ile ingress gateway HPA davranışını gözlemleyin ve gerektiğinde eşikleri güncelleyin.
4. Üretim sertifikası yenilemelerini `cert-manager` ACME entegrasyonu üzerinden otomatikleştirin.
