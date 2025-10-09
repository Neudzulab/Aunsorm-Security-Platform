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
        env::var("AUNSORM_STRICT").map_or(Self::Relaxed, |value| {
            let trimmed = value.trim();
            if trimmed == "1"
                || trimmed.eq_ignore_ascii_case("true")
                || trimmed.eq_ignore_ascii_case("on")
            {
                Self::Strict
            } else {
                Self::Relaxed
            }
        })
    }

    /// Strict kipin etkin olup olmadığını döndürür.
    #[must_use]
    pub const fn is_strict(self) -> bool {
        matches!(self, Self::Strict)
    }
}

#[cfg(test)]
mod tests {
    use super::StrictMode;

    #[test]
    fn strict_mode_respects_missing_env() {
        std::env::remove_var("AUNSORM_STRICT");
        assert!(matches!(StrictMode::from_env(), StrictMode::Relaxed));
        std::env::remove_var("AUNSORM_STRICT");
    }

    #[test]
    fn strict_mode_accepts_boolean_variants() {
        std::env::set_var("AUNSORM_STRICT", "true");
        assert!(matches!(StrictMode::from_env(), StrictMode::Strict));
        std::env::set_var("AUNSORM_STRICT", "TRUE");
        assert!(matches!(StrictMode::from_env(), StrictMode::Strict));
        std::env::set_var("AUNSORM_STRICT", "on");
        assert!(matches!(StrictMode::from_env(), StrictMode::Strict));
        std::env::set_var("AUNSORM_STRICT", "ON");
        assert!(matches!(StrictMode::from_env(), StrictMode::Strict));
        std::env::remove_var("AUNSORM_STRICT");
    }

    #[test]
    fn strict_mode_rejects_other_values() {
        std::env::set_var("AUNSORM_STRICT", "0");
        assert!(matches!(StrictMode::from_env(), StrictMode::Relaxed));
        std::env::set_var("AUNSORM_STRICT", "false");
        assert!(matches!(StrictMode::from_env(), StrictMode::Relaxed));
        std::env::remove_var("AUNSORM_STRICT");
    }
}
