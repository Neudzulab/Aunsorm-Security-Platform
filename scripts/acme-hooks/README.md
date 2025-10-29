# ACME Post-Renewal Hooks

Bu dizin, ACME sertifika yenileme işinin ardından tetiklenecek örnek komutları içerir.
Skriptler, yenileme job'u tarafından `scripts/acme-hooks/` altında aranır ve sırayla
çalıştırılır. Her komut aşağıdaki sözleşmeyi takip etmelidir:

- Çalıştırılabilir (`chmod +x`) olmalıdır.
- Sertifika kimliğini `AUNSORM_ACME_ORDER` ortam değişkeninden almalıdır.
- Yenilenen sertifika zincirinin yolu `AUNSORM_ACME_FULLCHAIN` değişkeninde,
  özel anahtar yolu ise `AUNSORM_ACME_PRIVATE_KEY` değişkeninde sağlanır.
- Başarısızlık durumunda sıfırdan farklı bir çıkış kodu döndürerek job'un loglara
  hata yazmasını sağlamalıdır.

## Örnek Kullanım

```
$ ./scripts/acme-hooks/reload-example.sh
```

Gerçek dağıtımlarda, bu dizine hizmetleri yeniden yükleyen veya konfigürasyon
kopyalayan ek komutlar ekleyebilirsiniz.
