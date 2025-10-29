use aunsorm_acme::{
    async_trait, ManagedCertificate, RenewalInventory, RenewalJob, RenewalJobError,
};
use time::macros::datetime;
use time::Duration;

#[derive(Clone)]
struct FixtureInventory {
    certificates: Vec<ManagedCertificate>,
}

#[async_trait]
impl RenewalInventory for FixtureInventory {
    type Error = std::convert::Infallible;

    async fn load(&self) -> Result<Vec<ManagedCertificate>, Self::Error> {
        Ok(self.certificates.clone())
    }
}

#[tokio::test]
async fn expiring_certificates_are_reported() {
    let now = datetime!(2024-04-10 09:00 UTC);
    let mut expired = ManagedCertificate::new(
        "order-expired",
        vec!["expired.example".to_string()],
        now - Duration::days(2),
    );
    expired
        .metadata_mut()
        .insert("account_id".to_string(), "acct-expired".to_string());
    let mut expiring = ManagedCertificate::new(
        "order-expiring",
        vec!["expiring.example".to_string()],
        now + Duration::days(7),
    );
    expiring
        .metadata_mut()
        .insert("account_id".to_string(), "acct-expiring".to_string());
    let stable = ManagedCertificate::new(
        "order-stable",
        vec!["stable.example".to_string()],
        now + Duration::days(90),
    );
    let inventory = FixtureInventory {
        certificates: vec![stable, expiring.clone(), expired.clone()],
    };
    let job = RenewalJob::new(inventory, Duration::days(30));

    let candidates = job.scan(now).await.expect("scan succeeds");
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].order_id(), expired.order_id());
    assert!(candidates[0].time_until_expiry().is_negative());
    assert_eq!(
        candidates[0]
            .metadata()
            .get("account_id")
            .expect("metadata preserved"),
        "acct-expired"
    );
    assert_eq!(candidates[1].order_id(), expiring.order_id());
    assert_eq!(candidates[1].identifiers(), expiring.identifiers());
    assert_eq!(candidates[1].time_until_expiry().whole_days(), 7);
}

#[tokio::test]
async fn negative_threshold_is_rejected() {
    let inventory = FixtureInventory {
        certificates: Vec::new(),
    };
    let job = RenewalJob::new(inventory, Duration::days(-5));
    let now = datetime!(2024-04-10 09:00 UTC);
    let err = job.scan(now).await.unwrap_err();
    match err {
        RenewalJobError::NegativeThreshold => {}
        RenewalJobError::Inventory(err) => panic!("unexpected inventory error: {err}"),
    }
}
