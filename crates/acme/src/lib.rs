#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

mod account;
mod authorization;
mod certificates;
mod directory;
mod jws;
mod nonce;
mod order;
mod providers;
mod renewal;
// mod rng; // DEPRECATED: Use aunsorm-core::AunsormNativeRng instead
mod storage;
mod validation;

// Re-export sealed RNG from aunsorm-core
pub use aunsorm_core::AunsormNativeRng;

/// Create a new Aunsorm native RNG instance
#[must_use]
pub fn create_aunsorm_rng() -> AunsormNativeRng {
    AunsormNativeRng::new()
}

pub use account::{
    AccountContact, AccountContactError, AccountContactKind, AccountService,
    ExternalAccountBinding, ExternalAccountBindingError, NewAccountRequest,
    NewAccountRequestBuilder,
};
pub use authorization::{
    Authorization, AuthorizationError, AuthorizationStatus, Challenge, ChallengeError,
    ChallengeKind, ChallengeStatus,
};
pub use certificates::{
    build_finalize_payload, download_certificate_chain, finalize_and_download_certificate,
    finalize_order_with_csr, CertificateDownload, CertificateError, FinalizeOptions,
    FinalizeWorkflow, OrderStatus, OrderStatusSnapshot,
};
pub use directory::{
    AcmeDirectory, AcmeDirectoryError, AcmeDirectoryMeta, DirectoryService, KnownEndpoint,
};
pub use jws::{
    AcmeJws, EcdsaP256AccountKey, EcdsaP256Jwk, Ed25519AccountKey, Ed25519Jwk, JwsError,
    KeyBinding, RsaAccountKey, RsaJwk,
};
pub use nonce::{
    NewNonceRequester, NonceError, NonceManager, NonceManagerError, NoncePool, NonceRequestError,
    NonceService, ReplayNonce, REPLAY_NONCE_HEADER,
};
pub use order::{
    IdentifierKind, NewOrderError, NewOrderRequest, NewOrderRequestBuilder, OrderIdentifier,
    OrderIdentifierError, OrderService,
};
pub use providers::dns::{
    CloudflareDnsProvider, DnsProvider, DnsProviderError, DnsRecordHandle, Route53DnsProvider,
};
pub use renewal::{
    async_trait, ManagedCertificate, RenewalCandidate, RenewalInventory, RenewalJob,
    RenewalJobError, DEFAULT_RENEWAL_THRESHOLD,
};
// pub use rng::{create_aunsorm_rng, AunsormNativeRng}; // Now re-exported from aunsorm-core above
pub use storage::{
    CertificateBundle, CertificateStorage, KmsStorage, LocalStorage, StorageError, StorageOutcome,
};
pub use validation::{
    dns01::Dns01Publication, dns01::Dns01StateMachine, http01::Http01Publication,
    http01::Http01StateMachine, ChallengeState, Dns01TxtRecord, Dns01ValidationError,
    Http01KeyAuthorization, Http01ValidationError, TlsAlpnCertificate, TlsAlpnCertificateError,
    TlsAlpnChallenge, TlsAlpnValidationError,
};
