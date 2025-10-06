use std::env;

/// Strict kip politikasını temsil eder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictMode {
    /// Klasik/PQC karışık mod; fallback kabul edilir.
    Relaxed,
    /// Fail-fast mod; PQC bulunmazsa işlem reddedilir.
    Strict,
}

impl StrictMode {
    /// Ortam değişkeninden strict kipini okur.
    #[must_use]
    pub fn from_env() -> Self {
        match env::var("AUNSORM_STRICT") {
            Ok(value) if value == "1" || value.eq_ignore_ascii_case("true") => Self::Strict,
            _ => Self::Relaxed,
        }
    }

    /// Strict kipin etkin olup olmadığını döndürür.
    #[must_use]
    pub const fn is_strict(self) -> bool {
        matches!(self, Self::Strict)
    }
}
