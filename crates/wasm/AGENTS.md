# aunsorm-wasm Ajanı Rehberi

- Bu crate yalnızca WebAssembly hedefleri için dışa açılan binding'leri sağlar; iş mantığı `internal`
  modülünde test edilebilir şekilde tutulmalıdır.
- `wasm-bindgen` ile dışa açılan fonksiyonlar yalın `JsValue` parametreleri almalı ve hataları
  `js_sys::Error` aracılığıyla döndürmelidir.
- İstemci tarafı API'ler `serde_wasm_bindgen` ile (de)serileştirilmiş JSON benzeri nesneler kabul
  etmelidir.
- Varsayılan değerler (profil, AEAD, strict) README'de belgelenmeli ve kodda merkezi helper
  fonksiyonlar aracılığıyla uygulanmalıdır.
