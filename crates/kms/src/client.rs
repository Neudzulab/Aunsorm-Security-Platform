#[cfg(feature = "kms-azure")]
use crate::azure::AzureBackend;
use crate::config::{BackendKind, BackendLocator, KeyDescriptor, KmsConfig};
use crate::error::{KmsError, Result};
#[cfg(feature = "kms-gcp")]
use crate::gcp::GcpBackend;
use crate::local::LocalBackend;
#[cfg(feature = "kms-pkcs11")]
use crate::pkcs11::Pkcs11Backend;

/// KMS backend'leri üzerinde ortak operasyonları gerçekleştiren istemci.
pub struct KmsClient {
    strict: bool,
    allow_fallback: bool,
    local: Option<LocalBackend>,
    #[cfg(feature = "kms-gcp")]
    gcp: Option<GcpBackend>,
    #[cfg(feature = "kms-azure")]
    azure: Option<AzureBackend>,
    #[cfg(feature = "kms-pkcs11")]
    pkcs11: Option<Pkcs11Backend>,
}

impl KmsClient {
    /// Yapılandırmadan yeni istemci oluşturur.
    ///
    /// # Errors
    ///
    /// Yerel store okunamazsa veya yapılandırma geçersizse `KmsError` döner.
    pub fn from_config(mut config: KmsConfig) -> Result<Self> {
        let local = match config.local_store.take() {
            Some(store) => Some(LocalBackend::from_file(store.path())?),
            None => None,
        };
        #[cfg(feature = "kms-gcp")]
        let gcp = match config.gcp.take() {
            Some(cfg) => Some(GcpBackend::new(cfg)?),
            None => None,
        };
        #[cfg(feature = "kms-azure")]
        let azure = match config.azure.take() {
            Some(cfg) => Some(AzureBackend::new(cfg, config.strict)?),
            None => None,
        };
        #[cfg(feature = "kms-pkcs11")]
        let pkcs11 = match config.pkcs11.take() {
            Some(cfg) => Some(Pkcs11Backend::new(cfg, config.strict)?),
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
            #[cfg(feature = "kms-gcp")]
            BackendKind::Gcp => {
                let backend = self.require_gcp()?;
                backend.sign_ed25519(locator.key_id(), message)
            }
            #[cfg(not(feature = "kms-gcp"))]
            BackendKind::Gcp => Err(KmsError::BackendNotConfigured {
                backend: locator.kind(),
            }),
            #[cfg(feature = "kms-azure")]
            BackendKind::Azure => {
                let backend = self.require_azure()?;
                backend.sign_ed25519(locator.key_id(), message)
            }
            #[cfg(not(feature = "kms-azure"))]
            BackendKind::Azure => Err(KmsError::BackendNotConfigured {
                backend: locator.kind(),
            }),
            #[cfg(feature = "kms-pkcs11")]
            BackendKind::Pkcs11 => {
                let backend = self.require_pkcs11()?;
                backend.sign_ed25519(locator.key_id(), message)
            }
            #[cfg(not(feature = "kms-pkcs11"))]
            BackendKind::Pkcs11 => Err(KmsError::BackendNotConfigured {
                backend: locator.kind(),
            }),
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
            #[cfg(feature = "kms-gcp")]
            BackendKind::Gcp => {
                let backend = self.require_gcp()?;
                backend.public_ed25519(locator.key_id())
            }
            #[cfg(not(feature = "kms-gcp"))]
            BackendKind::Gcp => Err(KmsError::BackendNotConfigured {
                backend: locator.kind(),
            }),
            #[cfg(feature = "kms-azure")]
            BackendKind::Azure => {
                let backend = self.require_azure()?;
                backend.public_ed25519(locator.key_id())
            }
            #[cfg(not(feature = "kms-azure"))]
            BackendKind::Azure => Err(KmsError::BackendNotConfigured {
                backend: locator.kind(),
            }),
            #[cfg(feature = "kms-pkcs11")]
            BackendKind::Pkcs11 => {
                let backend = self.require_pkcs11()?;
                backend.public_ed25519(locator.key_id())
            }
            #[cfg(not(feature = "kms-pkcs11"))]
            BackendKind::Pkcs11 => Err(KmsError::BackendNotConfigured {
                backend: locator.kind(),
            }),
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
            #[cfg(feature = "kms-gcp")]
            BackendKind::Gcp => {
                let backend = self.require_gcp()?;
                backend.key_kid(locator.key_id())
            }
            #[cfg(not(feature = "kms-gcp"))]
            BackendKind::Gcp => Err(KmsError::BackendNotConfigured {
                backend: locator.kind(),
            }),
            #[cfg(feature = "kms-azure")]
            BackendKind::Azure => {
                let backend = self.require_azure()?;
                backend.key_kid(locator.key_id())
            }
            #[cfg(not(feature = "kms-azure"))]
            BackendKind::Azure => Err(KmsError::BackendNotConfigured {
                backend: locator.kind(),
            }),
            #[cfg(feature = "kms-pkcs11")]
            BackendKind::Pkcs11 => {
                let backend = self.require_pkcs11()?;
                backend.key_kid(locator.key_id())
            }
            #[cfg(not(feature = "kms-pkcs11"))]
            BackendKind::Pkcs11 => Err(KmsError::BackendNotConfigured {
                backend: locator.kind(),
            }),
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

    #[cfg(feature = "kms-gcp")]
    fn require_gcp(&self) -> Result<&GcpBackend> {
        self.gcp.as_ref().ok_or(KmsError::BackendNotConfigured {
            backend: BackendKind::Gcp,
        })
    }

    #[cfg(feature = "kms-azure")]
    fn require_azure(&self) -> Result<&AzureBackend> {
        self.azure.as_ref().ok_or(KmsError::BackendNotConfigured {
            backend: BackendKind::Azure,
        })
    }

    #[cfg(feature = "kms-pkcs11")]
    fn require_pkcs11(&self) -> Result<&Pkcs11Backend> {
        self.pkcs11.as_ref().ok_or(KmsError::BackendNotConfigured {
            backend: BackendKind::Pkcs11,
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
