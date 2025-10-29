# ACME Fixture Açıklamaları

- `http01_fixture.json`: RFC 8555 HTTP-01 akışı için sentetik bir key-authorization
  örneği içerir. Token ve hesap thumbprint değerleri testlerde deterministik
  olarak kullanılmak üzere rastgele seçilmiştir.
- `dns01_fixture.json`: Aynı token/thumbprint çifti için `_acme-challenge`
  TXT kaydı gereksinimini ve beklenen base64url karmasını içerir.
- `dns_mock_publish.json`: Mock DNS sağlayıcısı ile publish/verify/revoke
  akışını doğrulamak için beklenen TXT kayıt adını ve değerini içerir.
- `dns_mock_operations.json`: TXT kaydı yayınlanmadan yapılan doğrulama veya
  revoke girişimlerinin hata üretmesi gerektiğini açıklayan senaryoyu
  dokümante eder.
