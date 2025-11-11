use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::io;
use std::sync::{Mutex, MutexGuard};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::approval::{ApprovalBundle, ApprovalPolicy, ApprovalPolicyConfig, ApprovalSignerConfig};
#[cfg(feature = "kms-azure")]
use crate::azure::AzureBackend;
use crate::config::{BackendKind, BackendLocator, KeyDescriptor, KmsConfig};
use crate::error::{KmsError, Result};
#[cfg(feature = "kms-gcp")]
use crate::gcp::GcpBackend;
use crate::local::LocalBackend;
#[cfg(feature = "kms-pkcs11")]
use crate::pkcs11::Pkcs11Backend;
use crate::RotationEvent;

/// KMS backend'leri üzerinde ortak operasyonları gerçekleştiren istemci.
pub struct KmsClient {
    strict: bool,
    allow_fallback: bool,
    local: Option<Mutex<LocalBackend>>,
    #[cfg(feature = "kms-gcp")]
    gcp: Option<GcpBackend>,
    #[cfg(feature = "kms-azure")]
    azure: Option<AzureBackend>,
    #[cfg(feature = "kms-pkcs11")]
    pkcs11: Option<Pkcs11Backend>,
}

const ROTATE_OPERATION: &str = "kms.rotate-ed25519";
const BACKUP_OPERATION: &str = "kms.backup.local-store";
const RESTORE_OPERATION: &str = "kms.restore.local-store";

impl KmsClient {
    /// Yapılandırmadan yeni istemci oluşturur.
    ///
    /// # Errors
    ///
    /// Yerel store okunamazsa veya yapılandırma geçersizse `KmsError` döner.
    pub fn from_config(mut config: KmsConfig) -> Result<Self> {
        let local = match config.local_store.take() {
            Some(store) => Some(Mutex::new(LocalBackend::from_config(&store)?)),
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
                let mut backend = self.require_local()?;
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

    /// Mevcut ve grace dönemindeki tüm Ed25519 public anahtarlarını döndürür.
    pub fn public_ed25519_versions(
        &self,
        descriptor: &KeyDescriptor,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        self.execute_with_fallback(descriptor, |locator| match locator.kind() {
            BackendKind::Local => {
                let backend = self.require_local()?;
                backend.public_ed25519_versions(locator.key_id())
            }
            #[cfg(feature = "kms-gcp")]
            BackendKind::Gcp => Err(KmsError::Unsupported {
                backend: locator.kind(),
            }),
            #[cfg(not(feature = "kms-gcp"))]
            BackendKind::Gcp => Err(KmsError::BackendNotConfigured {
                backend: locator.kind(),
            }),
            #[cfg(feature = "kms-azure")]
            BackendKind::Azure => Err(KmsError::Unsupported {
                backend: locator.kind(),
            }),
            #[cfg(not(feature = "kms-azure"))]
            BackendKind::Azure => Err(KmsError::BackendNotConfigured {
                backend: locator.kind(),
            }),
            #[cfg(feature = "kms-pkcs11")]
            BackendKind::Pkcs11 => {
                let backend = self.require_pkcs11()?;
                backend.public_ed25519_versions(locator.key_id())
            }
            #[cfg(not(feature = "kms-pkcs11"))]
            BackendKind::Pkcs11 => Err(KmsError::BackendNotConfigured {
                backend: locator.kind(),
            }),
        })
    }

    /// Ed25519 anahtarını onay bundle'ı ile döndürür.
    pub fn rotate_ed25519_with_approvals(
        &self,
        locator: &BackendLocator,
        approvals: &ApprovalBundle,
    ) -> Result<RotationEvent> {
        match locator.kind() {
            BackendKind::Local => {
                let mut backend = self.require_local()?;
                let policy = backend.approvals(locator.key_id())?.cloned();
                self.ensure_approvals(approvals, ROTATE_OPERATION, locator.key_id(), policy)?;
                backend.rotate_ed25519(locator.key_id())
            }
            #[cfg(feature = "kms-pkcs11")]
            BackendKind::Pkcs11 => {
                let backend = self.require_pkcs11()?;
                backend.rotate_ed25519(locator.key_id(), approvals, self.strict)
            }
            #[cfg(not(feature = "kms-pkcs11"))]
            BackendKind::Pkcs11 => Err(KmsError::BackendNotConfigured {
                backend: locator.kind(),
            }),
            _ => Err(KmsError::Unsupported {
                backend: locator.kind(),
            }),
        }
    }

    /// Yerel store'u onay bundle'ı ile şifreli olarak dışa aktarır.
    pub fn export_local_backup_with_approvals(
        &self,
        encryption_key: &[u8; 32],
        approvals: &ApprovalBundle,
    ) -> Result<Vec<u8>> {
        let backend = self.require_local()?;
        let aggregated = self.aggregate_local_policy(&backend)?;
        self.ensure_approvals(approvals, BACKUP_OPERATION, "local-store", aggregated)?;
        backend.export_encrypted(encryption_key)
    }

    /// Şifreli yedekten yerel store'u geri yükler.
    pub fn restore_local_backup_with_approvals(
        &self,
        encrypted: &[u8],
        encryption_key: &[u8; 32],
        approvals: &ApprovalBundle,
    ) -> Result<()> {
        let mut backend = self.require_local()?;
        let aggregated = self.aggregate_local_policy(&backend)?;
        self.ensure_approvals(approvals, RESTORE_OPERATION, "local-store", aggregated)?;
        let restored = LocalBackend::from_encrypted_bytes(encrypted, encryption_key)?;
        *backend = restored;
        Ok(())
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

    fn require_local(&self) -> Result<MutexGuard<'_, LocalBackend>> {
        let Some(mutex) = self.local.as_ref() else {
            return Err(KmsError::BackendNotConfigured {
                backend: BackendKind::Local,
            });
        };
        mutex.lock().map_err(|err| {
            let io_err = io::Error::other(err.to_string());
            KmsError::unavailable(BackendKind::Local, io_err)
        })
    }

    fn aggregate_local_policy(&self, backend: &LocalBackend) -> Result<Option<ApprovalPolicy>> {
        let mut signer_map: BTreeMap<String, String> = BTreeMap::new();
        let mut required = 0usize;
        let mut has_policy = false;
        for key_id in backend.key_ids() {
            let Some(policy) = backend.approvals(&key_id)?.cloned() else {
                continue;
            };
            has_policy = true;
            required = required.max(policy.threshold());
            for signer_id in policy.signer_ids() {
                let verifying = policy.verifying_key(signer_id).ok_or_else(|| {
                    KmsError::Approval(format!("approval signer {signer_id} missing verifying key"))
                })?;
                let encoded = STANDARD.encode(verifying.as_bytes());
                match signer_map.entry(signer_id.clone()) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(encoded);
                    }
                    std::collections::btree_map::Entry::Occupied(entry) => {
                        if entry.get() != &encoded {
                            return Err(KmsError::Approval(format!(
                                "conflicting approval signer key for {signer_id}"
                            )));
                        }
                    }
                }
            }
        }
        if !has_policy {
            return Ok(None);
        }
        let required_u8 = u8::try_from(required)
            .map_err(|_| KmsError::Approval("aggregated approval threshold exceeds 255".into()))?;
        let signers = signer_map
            .into_iter()
            .map(|(id, public_key)| ApprovalSignerConfig { id, public_key })
            .collect();
        let config = ApprovalPolicyConfig {
            required: required_u8,
            signers,
        };
        ApprovalPolicy::from_config(&config).map(Some)
    }

    fn ensure_approvals(
        &self,
        bundle: &ApprovalBundle,
        expected_operation: &str,
        key_id: &str,
        policy: Option<ApprovalPolicy>,
    ) -> Result<()> {
        if bundle.operation() != expected_operation {
            return Err(KmsError::Approval(format!(
                "approval bundle operation mismatch: expected {expected_operation}, got {}",
                bundle.operation()
            )));
        }
        let Some(policy) = policy else {
            if self.strict {
                return Err(KmsError::Approval(format!(
                    "approval policy required for key {key_id}"
                )));
            }
            return Ok(());
        };
        let message = approval_message(expected_operation, key_id);
        bundle.verify(&message, &policy)
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

fn approval_message(operation: &str, key_id: &str) -> Vec<u8> {
    format!("{operation}:{key_id}").into_bytes()
}
