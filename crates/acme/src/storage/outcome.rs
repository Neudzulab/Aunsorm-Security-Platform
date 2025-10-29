use std::path::PathBuf;

/// Saklama işleminin ürettiği dosya yolları.
#[derive(Debug, Clone)]
pub struct StorageOutcome {
    pub certificate_path: PathBuf,
    pub chain_path: PathBuf,
    pub private_key_path: Option<PathBuf>,
    pub wrapped_key_path: Option<PathBuf>,
}
