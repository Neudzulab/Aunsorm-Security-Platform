use async_trait::async_trait;

use super::{DnsProvider, DnsProviderError, DnsRecordHandle};
use crate::validation::{ChallengeState, Dns01TxtRecord};

/// Cloudflare DNS API adaptörü iskeleti.
#[derive(Debug, Clone)]
pub struct CloudflareDnsProvider {
    /// Cloudflare bölge kimliği.
    pub zone_id: String,
    /// API erişim jetonu.
    pub api_token: String,
}

#[async_trait]
impl DnsProvider for CloudflareDnsProvider {
    async fn publish_txt_record(
        &self,
        record: &Dns01TxtRecord,
    ) -> Result<DnsRecordHandle, DnsProviderError> {
        let _ = record;
        Err(DnsProviderError::NotImplemented {
            provider: "cloudflare",
            operation: "publish_txt_record",
        })
    }

    async fn revoke_txt_record(
        &self,
        _handle: &DnsRecordHandle,
    ) -> Result<ChallengeState, DnsProviderError> {
        Err(DnsProviderError::NotImplemented {
            provider: "cloudflare",
            operation: "revoke_txt_record",
        })
    }

    async fn verify_propagation(
        &self,
        _handle: &DnsRecordHandle,
    ) -> Result<ChallengeState, DnsProviderError> {
        Err(DnsProviderError::NotImplemented {
            provider: "cloudflare",
            operation: "verify_propagation",
        })
    }
}
