use async_trait::async_trait;

use super::{DnsProvider, DnsProviderError, DnsRecordHandle};
use crate::validation::{ChallengeState, Dns01TxtRecord};

/// AWS Route53 DNS API adaptörü iskeleti.
#[derive(Debug, Clone)]
pub struct Route53DnsProvider {
    /// Hosted zone kimliği.
    pub hosted_zone_id: String,
    /// AWS erişim anahtarı.
    pub access_key: String,
    /// AWS gizli anahtarı.
    pub secret_key: String,
}

#[async_trait]
impl DnsProvider for Route53DnsProvider {
    async fn publish_txt_record(
        &self,
        record: &Dns01TxtRecord,
    ) -> Result<DnsRecordHandle, DnsProviderError> {
        let _ = record;
        Err(DnsProviderError::NotImplemented {
            provider: "route53",
            operation: "publish_txt_record",
        })
    }

    async fn revoke_txt_record(
        &self,
        _handle: &DnsRecordHandle,
    ) -> Result<ChallengeState, DnsProviderError> {
        Err(DnsProviderError::NotImplemented {
            provider: "route53",
            operation: "revoke_txt_record",
        })
    }

    async fn verify_propagation(
        &self,
        _handle: &DnsRecordHandle,
    ) -> Result<ChallengeState, DnsProviderError> {
        Err(DnsProviderError::NotImplemented {
            provider: "route53",
            operation: "verify_propagation",
        })
    }
}
