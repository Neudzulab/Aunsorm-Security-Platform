//! CA otomasyon profilleri ve paketleme yardımcıları.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::{SubjectAltName, X509Error};

const MIN_ORG_SALT_LEN: usize = 8;

/// CA otomasyonu için kök ve ara profil tanımı.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaAutomationProfile {
    /// Profil kimliği.
    pub profile_id: String,
    /// Organizasyon tuzu (Base64).
    #[serde(rename = "org_salt")]
    pub org_salt_b64: String,
    /// Kök CA profili.
    pub root: CaProfileSection,
    /// Ara profiller (`ca issue --profile` ile seçilir).
    #[serde(default)]
    pub intermediates: BTreeMap<String, CaProfileSection>,
}

impl CaAutomationProfile {
    /// Diskten YAML/JSON profilini yükler.
    ///
    /// # Errors
    ///
    /// Dosya erişimi başarısız olursa veya içerik ayrıştırılamazsa `X509Error`
    /// döner. Profil doğrulaması başarısız olduğunda `ProfileValidation`
    /// hatası üretilir.
    pub fn from_path(path: &Path) -> Result<Self, X509Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let profile: Self = serde_yaml::from_reader(reader)?;
        profile.validate()?;
        Ok(profile)
    }

    /// Base64 `org_salt` değerini decode eder.
    ///
    /// # Errors
    ///
    /// Base64 decode işlemi başarısız olursa `InvalidOrgSalt` döner.
    pub fn decode_org_salt(&self) -> Result<Vec<u8>, X509Error> {
        let trimmed = self.org_salt_b64.trim();
        let decoded = STANDARD
            .decode(trimmed)
            .map_err(|err| X509Error::InvalidOrgSalt(err.to_string()))?;
        if decoded.len() < MIN_ORG_SALT_LEN {
            return Err(X509Error::InvalidOrgSalt(format!(
                "org_salt en az {MIN_ORG_SALT_LEN} bayt olmalıdır, bulundu {}",
                decoded.len()
            )));
        }
        Ok(decoded)
    }

    /// Ara profili getirir.
    ///
    /// # Errors
    ///
    /// Profil bulunamazsa `UnknownIntermediate` döner.
    pub fn intermediate(&self, name: &str) -> Result<&CaProfileSection, X509Error> {
        self.intermediates
            .get(name)
            .ok_or_else(|| X509Error::UnknownIntermediate(name.to_owned()))
    }

    fn validate(&self) -> Result<(), X509Error> {
        if self.profile_id.trim().is_empty() {
            return Err(X509Error::ProfileValidation(
                "profile_id boş olamaz".to_owned(),
            ));
        }
        if self.org_salt_b64.trim().is_empty() {
            return Err(X509Error::ProfileValidation(
                "org_salt boş olamaz".to_owned(),
            ));
        }
        self.decode_org_salt()?;
        self.root.validate("root")?;
        for (name, section) in &self.intermediates {
            section.validate(name)?;
        }
        Ok(())
    }
}

/// CA profil bölümü.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaProfileSection {
    /// Common Name değeri.
    pub common_name: String,
    /// Kalibrasyon metni.
    pub calibration_text: String,
    /// Geçerlilik süresi (gün).
    pub validity_days: u32,
    /// CPS URI listesi.
    #[serde(default)]
    pub cps_uris: Vec<String>,
    /// Politika OID listesi.
    #[serde(default)]
    pub policy_oids: Vec<String>,
    /// Subject Alternative Name girdileri.
    #[serde(default)]
    pub subject_alt_names: Vec<AutomationSan>,
}

impl CaProfileSection {
    fn validate(&self, scope: &str) -> Result<(), X509Error> {
        if self.common_name.trim().is_empty() {
            return Err(X509Error::ProfileValidation(format!(
                "{scope}: common_name boş olamaz"
            )));
        }
        if self.calibration_text.trim().is_empty() {
            return Err(X509Error::ProfileValidation(format!(
                "{scope}: calibration_text boş olamaz"
            )));
        }
        if self.validity_days == 0 {
            return Err(X509Error::ProfileValidation(format!(
                "{scope}: validity_days 0 olamaz"
            )));
        }
        for san in &self.subject_alt_names {
            san.validate(scope)?;
        }
        Ok(())
    }

    /// Profildeki SAN girdilerini `SubjectAltName` türüne dönüştürür.
    ///
    /// # Errors
    ///
    /// Geçersiz SAN girdileri varsa `X509Error::InvalidSan` döner.
    pub fn subject_alt_names(&self) -> Result<Vec<SubjectAltName>, X509Error> {
        self.subject_alt_names
            .iter()
            .map(AutomationSan::to_subject_alt_name)
            .collect()
    }
}

/// SAN girdileri için yardımcı tür.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AutomationSan {
    /// DNS tabanlı SAN girdisi.
    Dns { value: String },
    /// IP tabanlı SAN girdisi.
    Ip { value: String },
}

impl AutomationSan {
    fn validate(&self, scope: &str) -> Result<(), X509Error> {
        match self {
            Self::Dns { value } => {
                if value.trim().is_empty() {
                    return Err(X509Error::ProfileValidation(format!(
                        "{scope}: boş DNS SAN girdisi"
                    )));
                }
            }
            Self::Ip { value } => {
                if value.trim().is_empty() {
                    return Err(X509Error::ProfileValidation(format!(
                        "{scope}: boş IP SAN girdisi"
                    )));
                }
                value
                    .parse::<IpAddr>()
                    .map_err(|_| X509Error::InvalidSan(value.clone()))?;
            }
        }
        Ok(())
    }

    fn to_subject_alt_name(&self) -> Result<SubjectAltName, X509Error> {
        match self {
            Self::Dns { value } => Ok(SubjectAltName::Dns(value.trim().to_owned())),
            Self::Ip { value } => {
                let addr = value
                    .trim()
                    .parse::<IpAddr>()
                    .map_err(|_| X509Error::InvalidSan(value.clone()))?;
                Ok(SubjectAltName::Ip(addr))
            }
        }
    }
}

/// CA zinciri paket yapısı.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaBundle {
    /// Profil kimliği.
    pub profile_id: String,
    /// Kök sertifika girdisi.
    pub root: CaBundleEntry,
    /// Ara sertifika girdileri.
    #[serde(default)]
    pub intermediates: BTreeMap<String, CaBundleEntry>,
}

impl CaBundle {
    /// Yeni bir CA paketi oluşturur.
    #[must_use]
    pub fn new(profile_id: impl Into<String>, root: CaBundleEntry) -> Self {
        Self {
            profile_id: profile_id.into(),
            root,
            intermediates: BTreeMap::new(),
        }
    }

    /// Ara sertifika girdisi ekler veya günceller.
    pub fn upsert_intermediate(&mut self, name: impl Into<String>, entry: CaBundleEntry) {
        self.intermediates.insert(name.into(), entry);
    }
}

/// CA paketi girdisi.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaBundleEntry {
    /// Sertifika PEM çıktısı.
    pub certificate_pem: String,
    /// Kalibrasyon kimliği.
    pub calibration_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_validation_rejects_empty_values() {
        let yaml = r"
profile_id: ''
org_salt: ''
root:
  common_name: ''
  calibration_text: ''
  validity_days: 0
";
        let profile = serde_yaml::from_str::<CaAutomationProfile>(yaml).unwrap();
        let err = profile.validate().unwrap_err();
        assert!(matches!(err, X509Error::ProfileValidation(_)));
    }

    #[test]
    fn decode_org_salt_enforces_min_length() {
        let profile = CaAutomationProfile {
            profile_id: "demo".to_owned(),
            org_salt_b64: "YQ==".to_owned(),
            root: CaProfileSection {
                common_name: "Demo Root".to_owned(),
                calibration_text: "Calibration".to_owned(),
                validity_days: 365,
                cps_uris: Vec::new(),
                policy_oids: Vec::new(),
                subject_alt_names: Vec::new(),
            },
            intermediates: BTreeMap::new(),
        };
        let err = profile.decode_org_salt().unwrap_err();
        assert!(matches!(err, X509Error::InvalidOrgSalt(_)));
        let err = profile.validate().unwrap_err();
        assert!(matches!(err, X509Error::InvalidOrgSalt(_)));
    }

    #[test]
    fn profile_parses_subject_alt_names() {
        let yaml = r"
profile_id: demo
org_salt: ZGVtb3NhbHQ=
root:
  common_name: Demo Root
  calibration_text: Demo Root Calibration
  validity_days: 365
  subject_alt_names:
    - type: dns
      value: root.demo
intermediates:
  issuing:
    common_name: Demo Issuing
    calibration_text: Demo Issuing Calibration
    validity_days: 365
    subject_alt_names:
      - type: ip
        value: 127.0.0.1
";
        let profile = serde_yaml::from_str::<CaAutomationProfile>(yaml).unwrap();
        profile.validate().unwrap();

        let sans = profile.root.subject_alt_names().expect("sans");
        assert_eq!(sans.len(), 1);
        assert_eq!(sans[0], SubjectAltName::Dns("root.demo".to_owned()));

        let issuing = profile.intermediate("issuing").expect("issuing");
        let sans = issuing.subject_alt_names().expect("issuing sans");
        assert_eq!(sans.len(), 1);
        assert_eq!(
            sans[0],
            SubjectAltName::Ip("127.0.0.1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn bundle_upsert_updates_entries() {
        let mut bundle = CaBundle::new(
            "demo",
            CaBundleEntry {
                certificate_pem: "root".to_owned(),
                calibration_id: "root-calib".to_owned(),
            },
        );
        bundle.upsert_intermediate(
            "issuing",
            CaBundleEntry {
                certificate_pem: "issuing-cert".to_owned(),
                calibration_id: "issuing-calib".to_owned(),
            },
        );
        bundle.upsert_intermediate(
            "issuing",
            CaBundleEntry {
                certificate_pem: "updated".to_owned(),
                calibration_id: "updated-calib".to_owned(),
            },
        );
        assert_eq!(bundle.intermediates.len(), 1);
        let entry = bundle.intermediates.get("issuing").unwrap();
        assert_eq!(entry.certificate_pem, "updated");
        assert_eq!(entry.calibration_id, "updated-calib");
    }
}
