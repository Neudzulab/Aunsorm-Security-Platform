use js_sys::Error as JsError;
use wasm_bindgen::prelude::*;

use crate::internal::{self, DecryptRequest, EncryptRequest, WasmError};

fn err_to_js(error: WasmError) -> JsValue {
    JsError::from(error).into()
}

#[wasm_bindgen]
pub fn encrypt_with_calib_text(request: JsValue) -> Result<String, JsValue> {
    let request: EncryptRequest =
        serde_wasm_bindgen::from_value(request).map_err(|err| err_to_js(WasmError::from(err)))?;
    internal::encrypt(request).map_err(err_to_js)
}

#[wasm_bindgen]
pub fn decrypt_with_calib_text(request: JsValue) -> Result<Vec<u8>, JsValue> {
    let request: DecryptRequest =
        serde_wasm_bindgen::from_value(request).map_err(|err| err_to_js(WasmError::from(err)))?;
    internal::decrypt(request).map_err(err_to_js)
}

#[wasm_bindgen]
pub fn peek_header(packet_b64: &str) -> Result<JsValue, JsValue> {
    let header = internal::peek_header(packet_b64).map_err(err_to_js)?;
    serde_wasm_bindgen::to_value(&header).map_err(|err| err_to_js(WasmError::from(err)))
}
