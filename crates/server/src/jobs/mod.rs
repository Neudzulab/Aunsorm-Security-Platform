use std::sync::Arc;
use std::time::Duration as StdDuration;

use aunsorm_acme::{
    async_trait, ManagedCertificate, RenewalCandidate, RenewalInventory, RenewalJob,
    RenewalJobError,
};
use time::{Duration, OffsetDateTime};
use tokio::task::JoinHandle;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, error, info};

use crate::acme::RenewalInventoryError;
use crate::state::ServerState;

#[derive(Clone)]
struct ServerAcmeInventory {
    state: Arc<ServerState>,
}

#[async_trait]
impl RenewalInventory for ServerAcmeInventory {
    type Error = RenewalInventoryError;

    async fn load(&self) -> Result<Vec<ManagedCertificate>, Self::Error> {
        self.state.acme().renewal_inventory().await
    }
}

/// Spawns the background task responsible for scanning ACME certificates and
/// logging candidates that are approaching their expiry.
pub fn spawn_acme_renewal_job(
    state: Arc<ServerState>,
    period: StdDuration,
    renew_before: Duration,
) -> JoinHandle<()> {
    let inventory = ServerAcmeInventory { state };
    let job = RenewalJob::new(inventory, renew_before);
    tokio::spawn(async move {
        info!("ACME yenileme taraması başlatıldı");
        if !execute_scan(&job).await {
            return;
        }
        let mut ticker = interval(period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if !execute_scan(&job).await {
                break;
            }
        }
    })
}

async fn execute_scan(job: &RenewalJob<ServerAcmeInventory>) -> bool {
    match job.scan(OffsetDateTime::now_utc()).await {
        Ok(candidates) => handle_candidates(candidates),
        Err(err) => handle_scan_error(err),
    }
}

fn log_candidate(candidate: &RenewalCandidate) {
    let remaining = candidate.time_until_expiry();
    let identifiers = candidate.identifiers().join(", ");
    let account_id = candidate
        .metadata()
        .get("account_id")
        .map_or("unknown", String::as_str);
    info!(
        order_id = candidate.order_id(),
        account_id,
        expires_at = %candidate.expires_at(),
        remaining_days = remaining.whole_days(),
        remaining_hours = remaining.whole_hours(),
        identifiers = %identifiers,
        "ACME sertifikası yenileme eşiğinde"
    );
}

fn handle_candidates(candidates: Vec<RenewalCandidate>) -> bool {
    if candidates.is_empty() {
        debug!("ACME yenileme taramasında bekleyen sertifika yok");
        return true;
    }
    for candidate in candidates {
        log_candidate(&candidate);
    }
    true
}

fn handle_scan_error(err: RenewalJobError<RenewalInventoryError>) -> bool {
    match err {
        RenewalJobError::NegativeThreshold => {
            error!("ACME yenileme eşiği negatif yapılandırıldı; iş durduruluyor");
            false
        }
        RenewalJobError::Inventory(err) => {
            error!(error = %err, "ACME yenileme taraması sırasında envanter okunamadı");
            true
        }
    }
}
