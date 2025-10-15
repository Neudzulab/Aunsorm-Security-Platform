#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

mod serde_utils;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DevicePlatform {
    Ios,
    Android,
    Macos,
    Windows,
    Linux,
    Custom(String),
}

impl DevicePlatform {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Ios => "ios",
            Self::Android => "android",
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::Custom(value) => value.as_str(),
        }
    }

    fn from_normalized(value: &str) -> Self {
        match value {
            "ios" => Self::Ios,
            "android" => Self::Android,
            "macos" => Self::Macos,
            "windows" => Self::Windows,
            "linux" => Self::Linux,
            other => Self::Custom(other.to_owned()),
        }
    }
}

impl fmt::Display for DevicePlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PlatformParseError {
    #[error("platform value cannot be empty")]
    Empty,
    #[error("platform contains control characters")]
    ControlCharacter,
}

impl FromStr for DevicePlatform {
    type Err = PlatformParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim();
        if normalized.is_empty() {
            return Err(PlatformParseError::Empty);
        }
        if normalized.chars().any(char::is_control) {
            return Err(PlatformParseError::ControlCharacter);
        }
        let lowered = normalized.to_ascii_lowercase();
        Ok(Self::from_normalized(&lowered))
    }
}

impl Serialize for DevicePlatform {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DevicePlatform {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRule {
    pub id: String,
    pub statement: String,
    pub mandatory: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDocument {
    pub version: String,
    pub description: String,
    #[serde(with = "serde_utils::time")]
    pub published_at: SystemTime,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollmentRequest {
    pub device_id: String,
    pub owner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub display_name: Option<String>,
    pub platform: DevicePlatform,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRecord {
    pub device_id: String,
    pub owner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub display_name: Option<String>,
    pub platform: DevicePlatform,
    #[serde(with = "serde_utils::time")]
    pub enrolled_at: SystemTime,
    #[serde(with = "serde_utils::time")]
    pub last_seen: SystemTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub certificate_serial: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EnrollmentMode {
    Automated,
    UserAssisted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateDistributionPlan {
    pub profile_name: String,
    pub certificate_authority: String,
    pub enrollment_mode: EnrollmentMode,
    pub distribution_endpoints: Vec<String>,
    pub renewal_window_days: u32,
    pub grace_period_hours: u32,
    pub bootstrap_package: String,
}

impl CertificateDistributionPlan {
    #[must_use]
    pub fn renewal_interval(&self) -> Duration {
        Duration::from_secs(u64::from(self.renewal_window_days) * 86_400)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceCertificatePlan {
    pub device_id: String,
    pub owner: String,
    pub platform: DevicePlatform,
    pub profile_name: String,
    pub certificate_authority: String,
    pub distribution_endpoints: Vec<String>,
    pub enrollment_mode: EnrollmentMode,
    pub bootstrap_package: String,
    pub grace_period_hours: u32,
    pub next_renewal: u64,
}

#[derive(Debug, Error)]
pub enum MdmError {
    #[error("device already registered: {0}")]
    AlreadyRegistered(String),
    #[error("identifier {0} cannot be empty")]
    InvalidIdentifier(&'static str),
    #[error("internal state lock poisoned")]
    StatePoisoned,
    #[error("policy for platform {0} not found")]
    PolicyMissing(String),
}

#[derive(Debug)]
pub struct MdmDirectory {
    devices: RwLock<HashMap<String, DeviceRecord>>,
    policies: RwLock<HashMap<DevicePlatform, PolicyDocument>>,
    plan: RwLock<CertificateDistributionPlan>,
}

impl MdmDirectory {
    #[must_use]
    pub fn new(plan: CertificateDistributionPlan) -> Self {
        Self {
            devices: RwLock::new(HashMap::new()),
            policies: RwLock::new(HashMap::new()),
            plan: RwLock::new(plan),
        }
    }

    /// Registers a device and stores its metadata.
    ///
    /// # Errors
    ///
    /// Returns [`MdmError::InvalidIdentifier`] when identifiers contain
    /// control characters or are empty, [`MdmError::AlreadyRegistered`] when
    /// the device is already known, and [`MdmError::StatePoisoned`] if the
    /// internal storage locks are poisoned.
    pub fn register_device(&self, request: EnrollmentRequest) -> Result<DeviceRecord, MdmError> {
        let device_id = request.device_id.trim().to_owned();
        if device_id.is_empty() {
            return Err(MdmError::InvalidIdentifier("device_id"));
        }
        if device_id.chars().any(char::is_control) {
            return Err(MdmError::InvalidIdentifier("device_id"));
        }
        let owner = request.owner.trim();
        if owner.is_empty() {
            return Err(MdmError::InvalidIdentifier("owner"));
        }
        if owner.chars().any(char::is_control) {
            return Err(MdmError::InvalidIdentifier("owner"));
        }
        let display_name = request
            .display_name
            .as_ref()
            .map(|name| name.trim())
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        let now = SystemTime::now();
        let record = DeviceRecord {
            device_id: device_id.clone(),
            owner: owner.to_owned(),
            display_name,
            platform: request.platform,
            enrolled_at: now,
            last_seen: now,
            certificate_serial: None,
        };
        {
            let mut guard = self.devices.write().map_err(|_| MdmError::StatePoisoned)?;
            if guard.contains_key(&device_id) {
                return Err(MdmError::AlreadyRegistered(device_id));
            }
            guard.insert(device_id, record.clone());
        }
        Ok(record)
    }

    /// Inserts or replaces the policy document for a platform.
    ///
    /// # Errors
    ///
    /// Returns [`MdmError::StatePoisoned`] if the policy store lock is poisoned.
    pub fn upsert_policy(
        &self,
        platform: DevicePlatform,
        policy: PolicyDocument,
    ) -> Result<(), MdmError> {
        self.policies
            .write()
            .map_err(|_| MdmError::StatePoisoned)?
            .insert(platform, policy);
        Ok(())
    }

    /// Returns the policy document for the requested platform, if available.
    ///
    /// # Errors
    ///
    /// Returns [`MdmError::StatePoisoned`] if the policy store cannot be read.
    pub fn policy(&self, platform: &DevicePlatform) -> Result<Option<PolicyDocument>, MdmError> {
        let guard = self.policies.read().map_err(|_| MdmError::StatePoisoned)?;
        Ok(guard.get(platform).cloned())
    }

    /// Returns the certificate distribution plan shared across devices.
    ///
    /// # Errors
    ///
    /// Returns [`MdmError::StatePoisoned`] if the plan lock is poisoned.
    pub fn distribution_plan(&self) -> Result<CertificateDistributionPlan, MdmError> {
        let guard = self.plan.read().map_err(|_| MdmError::StatePoisoned)?;
        Ok(guard.clone())
    }

    /// Replaces the shared certificate distribution plan.
    ///
    /// # Errors
    ///
    /// Returns [`MdmError::StatePoisoned`] if the plan lock is poisoned.
    pub fn set_distribution_plan(&self, plan: CertificateDistributionPlan) -> Result<(), MdmError> {
        *self.plan.write().map_err(|_| MdmError::StatePoisoned)? = plan;
        Ok(())
    }

    /// Looks up a previously registered device.
    ///
    /// # Errors
    ///
    /// Returns [`MdmError::StatePoisoned`] if the device store cannot be read.
    pub fn device(&self, id: &str) -> Result<Option<DeviceRecord>, MdmError> {
        let guard = self.devices.read().map_err(|_| MdmError::StatePoisoned)?;
        Ok(guard.get(id).cloned())
    }

    /// Produces a device-specific certificate distribution plan.
    ///
    /// # Errors
    ///
    /// Returns [`MdmError::StatePoisoned`] if the directory locks are poisoned.
    pub fn device_certificate_plan(
        &self,
        id: &str,
    ) -> Result<Option<DeviceCertificatePlan>, MdmError> {
        let Some(record) = self.device(id)? else {
            return Ok(None);
        };
        let plan = self.distribution_plan()?;
        let renewal_at = record
            .last_seen
            .checked_add(plan.renewal_interval())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let next_renewal = system_time_to_unix(&renewal_at);
        Ok(Some(DeviceCertificatePlan {
            device_id: record.device_id,
            owner: record.owner,
            platform: record.platform,
            profile_name: plan.profile_name,
            certificate_authority: plan.certificate_authority,
            distribution_endpoints: plan.distribution_endpoints,
            enrollment_mode: plan.enrollment_mode,
            bootstrap_package: plan.bootstrap_package,
            grace_period_hours: plan.grace_period_hours,
            next_renewal,
        }))
    }

    /// Returns the number of registered devices.
    ///
    /// # Errors
    ///
    /// Returns [`MdmError::StatePoisoned`] if the device store cannot be read.
    pub fn device_count(&self) -> Result<usize, MdmError> {
        let guard = self.devices.read().map_err(|_| MdmError::StatePoisoned)?;
        Ok(guard.len())
    }
}

fn system_time_to_unix(time: &SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_plan() -> CertificateDistributionPlan {
        CertificateDistributionPlan {
            profile_name: "aunsorm-mdm-bootstrap".to_owned(),
            certificate_authority: "CN=Aunsorm Device CA,O=Aunsorm".to_owned(),
            enrollment_mode: EnrollmentMode::Automated,
            distribution_endpoints: vec![
                "https://mdm.aunsorm.dev/scep".to_owned(),
                "acme://mdm.aunsorm.dev/device".to_owned(),
            ],
            renewal_window_days: 30,
            grace_period_hours: 72,
            bootstrap_package: "aunsorm-mdm.pkg".to_owned(),
        }
    }

    fn sample_policy(version: &str) -> PolicyDocument {
        PolicyDocument {
            version: version.to_owned(),
            description: "Baseline mobile hardening".to_owned(),
            published_at: SystemTime::now(),
            rules: vec![
                PolicyRule {
                    id: "screen-lock".to_owned(),
                    statement: "Devices must enforce auto-lock within 60 seconds".to_owned(),
                    mandatory: true,
                    remediation: Some("Push updated configuration profile".to_owned()),
                },
                PolicyRule {
                    id: "disk-encryption".to_owned(),
                    statement: "Full disk encryption must remain enabled".to_owned(),
                    mandatory: true,
                    remediation: None,
                },
            ],
        }
    }

    #[test]
    fn register_device_and_plan() {
        let directory = MdmDirectory::new(sample_plan());
        directory
            .upsert_policy(DevicePlatform::Ios, sample_policy("1.0"))
            .expect("policy");
        let request = EnrollmentRequest {
            device_id: " device-123 ".to_owned(),
            owner: "alice".to_owned(),
            display_name: Some(" Alice's iPhone 15 ".to_owned()),
            platform: DevicePlatform::Ios,
        };
        let record = directory.register_device(request).expect("register");
        assert_eq!(record.device_id, "device-123");
        assert_eq!(record.owner, "alice");
        assert_eq!(record.display_name.as_deref(), Some("Alice's iPhone 15"));
        assert_eq!(record.platform, DevicePlatform::Ios);
        let plan = directory
            .device_certificate_plan("device-123")
            .expect("plan")
            .expect("plan exists");
        assert_eq!(plan.device_id, "device-123");
        assert_eq!(plan.profile_name, "aunsorm-mdm-bootstrap");
        assert_eq!(plan.distribution_endpoints.len(), 2);
        assert!(plan.next_renewal > 0);
    }

    #[test]
    fn duplicate_registration_fails() {
        let directory = MdmDirectory::new(sample_plan());
        let request = EnrollmentRequest {
            device_id: "device-001".to_owned(),
            owner: "bob".to_owned(),
            display_name: None,
            platform: DevicePlatform::Windows,
        };
        directory.register_device(request.clone()).expect("first");
        let error = directory.register_device(request).expect_err("duplicate");
        match error {
            MdmError::AlreadyRegistered(id) => assert_eq!(id, "device-001"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn policy_serialization_roundtrip() {
        let policy = sample_policy("1.1");
        let json = serde_json::to_value(&policy).expect("serialize");
        assert_eq!(json["version"], json!("1.1"));
        assert!(json["rules"].as_array().is_some());
        let decoded: PolicyDocument = serde_json::from_value(json).expect("deserialize");
        assert_eq!(decoded.rules.len(), 2);
    }

    #[test]
    fn platform_parsing() {
        assert_eq!(
            DevicePlatform::from_str("ios").expect("ios"),
            DevicePlatform::Ios
        );
        assert_eq!(
            DevicePlatform::from_str("CustomOS").expect("custom"),
            DevicePlatform::Custom("customos".to_owned())
        );
        let err = DevicePlatform::from_str("\t\n").expect_err("empty");
        assert_eq!(err, PlatformParseError::Empty);
    }

    #[test]
    fn device_count_reports_entries() {
        let directory = MdmDirectory::new(sample_plan());
        assert_eq!(directory.device_count().expect("count"), 0);
        let request = EnrollmentRequest {
            device_id: "one".to_owned(),
            owner: "eve".to_owned(),
            display_name: None,
            platform: DevicePlatform::Linux,
        };
        directory.register_device(request).expect("register");
        assert_eq!(directory.device_count().expect("count"), 1);
    }
}
