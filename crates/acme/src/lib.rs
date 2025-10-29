#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

mod account;
mod authorization;
mod directory;
mod jws;
mod nonce;
mod order;
mod providers;
mod rng;
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
pub use rng::{create_aunsorm_rng, AunsormNativeRng};
pub use validation::{
    dns01::Dns01Publication, dns01::Dns01StateMachine, http01::Http01Publication,
    http01::Http01StateMachine, ChallengeState, Dns01TxtRecord, Dns01ValidationError,
    Http01KeyAuthorization, Http01ValidationError, TlsAlpnCertificate, TlsAlpnCertificateError,
    TlsAlpnChallenge, TlsAlpnValidationError,
};
