use crate::config::{BackendKind, BackendLocator, KeyDescriptor, KmsConfig};
use crate::error::{KmsError, Result};
use crate::local::LocalBackend;
#[cfg(any(feature = "kms-gcp", feature = "kms-azure", feature = "kms-pkcs11"))]
use crate::remote::RemoteBackend;
#[cfg(not(any(feature = "kms-gcp", feature = "kms-azure", feature = "kms-pkcs11")))]
type RemoteBackend = ();

/// KMS backend'leri üzerinde ortak operasyonları gerçekleştiren istemci.
#[derive(Clone)]
pub struct KmsClient {
    strict: bool,
    allow_fallback: bool,
    local: Option<LocalBackend>,
    #[cfg(feature = "kms-gcp")]
    gcp: Option<RemoteBackend>,
    #[cfg(feature = "kms-azure")]
    azure: Option<RemoteBackend>,
    #[cfg(feature = "kms-pkcs11")]
    pkcs11: Option<RemoteBackend>,
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
        #[cfg(feature = "kms-gcp")]
        let gcp = match config.gcp_store {
            Some(store) => Some(RemoteBackend::from_file(BackendKind::Gcp, store.path())?),
            None => None,
        };
        #[cfg(feature = "kms-azure")]
        let azure = match config.azure_store {
            Some(store) => Some(RemoteBackend::from_file(BackendKind::Azure, store.path())?),
            None => None,
        };
        #[cfg(feature = "kms-pkcs11")]
        let pkcs11 = match config.pkcs11_store {
            Some(store) => Some(RemoteBackend::from_file(BackendKind::Pkcs11, store.path())?),
            None => None,
        };
        Ok(Self {
            strict: config.strict,
            allow_fallback: config.allow_fallback,
            local,
            #[cfg(feature = "kms-gcp")]
            gcp,
            #[cfg(feature = "kms-azure")]
            azure,
            #[cfg(feature = "kms-pkcs11")]
            pkcs11,
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
                let backend = self.require_remote(locator.kind())?;
                backend.sign_ed25519(locator.key_id(), message)
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
                let backend = self.require_remote(locator.kind())?;
                Ok(backend
                    .public_ed25519(locator.key_id())?
                    .to_bytes()
                    .to_vec())
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
                let backend = self.require_remote(locator.kind())?;
                backend.kid(locator.key_id())
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
                let backend = self.require_remote(locator.kind())?;
                backend.wrap_key(locator.key_id(), plaintext, aad)
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
                let backend = self.require_remote(locator.kind())?;
                backend.unwrap_key(locator.key_id(), ciphertext, aad)
            }
        }
    }

    fn require_local(&self) -> Result<&LocalBackend> {
        self.local.as_ref().ok_or(KmsError::BackendNotConfigured {
            backend: BackendKind::Local,
        })
    }

    fn require_remote(&self, kind: BackendKind) -> Result<&RemoteBackend> {
        match kind {
            BackendKind::Local => unreachable!("local backend handled separately"),
            BackendKind::Gcp => {
                #[cfg(feature = "kms-gcp")]
                {
                    self.gcp.as_ref().ok_or(KmsError::BackendNotConfigured {
                        backend: BackendKind::Gcp,
                    })
                }
                #[cfg(not(feature = "kms-gcp"))]
                {
                    Err(KmsError::Unsupported {
                        backend: BackendKind::Gcp,
                    })
                }
            }
            BackendKind::Azure => {
                #[cfg(feature = "kms-azure")]
                {
                    self.azure.as_ref().ok_or(KmsError::BackendNotConfigured {
                        backend: BackendKind::Azure,
                    })
                }
                #[cfg(not(feature = "kms-azure"))]
                {
                    Err(KmsError::Unsupported {
                        backend: BackendKind::Azure,
                    })
                }
            }
            BackendKind::Pkcs11 => {
                #[cfg(feature = "kms-pkcs11")]
                {
                    self.pkcs11.as_ref().ok_or(KmsError::BackendNotConfigured {
                        backend: BackendKind::Pkcs11,
                    })
                }
                #[cfg(not(feature = "kms-pkcs11"))]
                {
                    Err(KmsError::Unsupported {
                        backend: BackendKind::Pkcs11,
                    })
                }
            }
        }
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
