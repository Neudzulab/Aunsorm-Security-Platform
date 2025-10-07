use crate::config::{BackendKind, BackendLocator, KeyDescriptor, KmsConfig};
use crate::error::{KmsError, Result};
use crate::local::LocalBackend;

/// KMS backend'leri üzerinde ortak operasyonları gerçekleştiren istemci.
#[derive(Clone)]
pub struct KmsClient {
    strict: bool,
    allow_fallback: bool,
    local: Option<LocalBackend>,
}

impl KmsClient {
    /// Yapılandırmadan yeni istemci oluşturur.
    ///
    /// # Errors
    ///
    /// Yerel store okunamazsa veya yapılandırma geçersizse `KmsError` döner.
    pub fn from_config(config: KmsConfig) -> Result<Self> {
        let local = match config.local_store {
            Some(store) => Some(LocalBackend::from_file(store.path())?),
            None => None,
        };
        Ok(Self {
            strict: config.strict,
            allow_fallback: config.allow_fallback,
            local,
        })
    }

    /// Ed25519 imzası üretir.
    ///
    /// # Errors
    ///
    /// İstenen backend yapılandırılmamışsa veya imzalama işlemi başarısız olursa
    /// `KmsError` döner.
    pub fn sign_ed25519(&self, descriptor: &KeyDescriptor, message: &[u8]) -> Result<Vec<u8>> {
        self.execute_with_fallback(descriptor, |locator| match locator.kind() {
            BackendKind::Local => {
                let backend = self.require_local()?;
                backend.sign_ed25519(locator.key_id(), message)
            }
            BackendKind::Gcp | BackendKind::Azure | BackendKind::Pkcs11 => {
                Err(KmsError::Unsupported {
                    backend: locator.kind(),
                })
            }
        })
    }

    /// Ed25519 public anahtarını döndürür.
    ///
    /// # Errors
    ///
    /// Backend yapılandırılmamışsa veya anahtar bulunamazsa `KmsError`
    /// döner.
    pub fn public_ed25519(&self, descriptor: &KeyDescriptor) -> Result<Vec<u8>> {
        self.execute_with_fallback(descriptor, |locator| match locator.kind() {
            BackendKind::Local => {
                let backend = self.require_local()?;
                Ok(backend
                    .public_ed25519(locator.key_id())?
                    .to_bytes()
                    .to_vec())
            }
            BackendKind::Gcp | BackendKind::Azure | BackendKind::Pkcs11 => {
                Err(KmsError::Unsupported {
                    backend: locator.kind(),
                })
            }
        })
    }

    /// Anahtar kimliği için `kid` değerini döndürür.
    ///
    /// # Errors
    ///
    /// Backend yapılandırılmamışsa veya anahtar mevcut değilse `KmsError`
    /// döner.
    pub fn key_kid(&self, descriptor: &KeyDescriptor) -> Result<String> {
        self.execute_with_fallback(descriptor, |locator| match locator.kind() {
            BackendKind::Local => {
                let backend = self.require_local()?;
                backend.kid(locator.key_id())
            }
            BackendKind::Gcp | BackendKind::Azure | BackendKind::Pkcs11 => {
                Err(KmsError::Unsupported {
                    backend: locator.kind(),
                })
            }
        })
    }

    /// AES anahtar sarma işlemini gerçekleştirir.
    ///
    /// # Errors
    ///
    /// Backend desteklemiyorsa veya kriptografik hata oluşursa `KmsError`
    /// döner.
    pub fn wrap_key(
        &self,
        locator: &BackendLocator,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        match locator.kind() {
            BackendKind::Local => {
                let backend = self.require_local()?;
                backend.wrap_key(locator.key_id(), plaintext, aad)
            }
            BackendKind::Gcp | BackendKind::Azure | BackendKind::Pkcs11 => {
                Err(KmsError::Unsupported {
                    backend: locator.kind(),
                })
            }
        }
    }

    /// Sarılmış anahtarı çözer.
    ///
    /// # Errors
    ///
    /// Backend desteklemiyorsa veya doğrulama başarısız olursa `KmsError`
    /// döner.
    pub fn unwrap_key(
        &self,
        locator: &BackendLocator,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        match locator.kind() {
            BackendKind::Local => {
                let backend = self.require_local()?;
                backend.unwrap_key(locator.key_id(), ciphertext, aad)
            }
            BackendKind::Gcp | BackendKind::Azure | BackendKind::Pkcs11 => {
                Err(KmsError::Unsupported {
                    backend: locator.kind(),
                })
            }
        }
    }

    fn require_local(&self) -> Result<&LocalBackend> {
        self.local.as_ref().ok_or(KmsError::BackendNotConfigured {
            backend: BackendKind::Local,
        })
    }

    fn execute_with_fallback<T, F>(&self, descriptor: &KeyDescriptor, mut op: F) -> Result<T>
    where
        F: FnMut(&BackendLocator) -> Result<T>,
    {
        match op(descriptor.primary()) {
            Ok(result) => Ok(result),
            Err(first_err) => {
                if !Self::should_attempt_fallback(&first_err) {
                    return Err(first_err);
                }
                let Some(fallback) = descriptor.fallback() else {
                    return Err(first_err);
                };
                if !self.allow_fallback {
                    return Err(first_err);
                }
                if self.strict {
                    return Err(KmsError::StrictFallback {
                        from: descriptor.primary().kind(),
                        to: fallback.kind(),
                    });
                }
                op(fallback)
            }
        }
    }

    const fn should_attempt_fallback(err: &KmsError) -> bool {
        matches!(
            err,
            KmsError::BackendNotConfigured { .. }
                | KmsError::BackendUnavailable { .. }
                | KmsError::Unsupported { .. }
                | KmsError::KeyNotFound { .. }
        )
    }
}
