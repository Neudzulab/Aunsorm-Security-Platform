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
mod rng;
mod storage;
mod validation;

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
    build_finalize_payload, download_certificate_chain, finalize_order_with_csr,
    CertificateDownload, CertificateError,
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
    RenewalJobError,
};
pub use rng::{create_aunsorm_rng, AunsormNativeRng};
pub use storage::{
    CertificateBundle, CertificateStorage, KmsStorage, LocalStorage, StorageError, StorageOutcome,
};
pub use validation::{
    dns01::Dns01Publication, dns01::Dns01StateMachine, http01::Http01Publication,
    http01::Http01StateMachine, ChallengeState, Dns01TxtRecord, Dns01ValidationError,
    Http01KeyAuthorization, Http01ValidationError, TlsAlpnCertificate, TlsAlpnCertificateError,
    TlsAlpnChallenge, TlsAlpnValidationError,
};
