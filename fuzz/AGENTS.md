# Aunsorm Fuzz Ajanı

- Fuzz hedefleri hızlı geri bildirim için minimal ancak anlamlı kontroller içermelidir.
- Panik yakalayan `catch_unwind` benzeri yapılar kullanmayın; hatalar doğrudan ortaya çıkmalıdır.
- Fuzzer girdilerini doğrularken sadece gerekli minimum koşulları uygulayın.
