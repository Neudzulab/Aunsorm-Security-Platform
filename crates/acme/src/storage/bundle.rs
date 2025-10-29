use super::StorageError;
use crate::certificates::CertificateDownload;

/// Özel anahtar ve sertifika zincirini birlikte tutan veri yapısı.
#[derive(Debug, Clone)]
pub struct CertificateBundle {
    certificates: Vec<String>,
    private_key_pem: String,
}

impl CertificateBundle {
    /// Ham PEM bileşenlerinden yeni bir demet oluşturur.
    ///
    /// # Errors
    ///
    /// Zincir boşsa [`StorageError::EmptyCertificates`] döner.
    pub fn new(private_key_pem: String, certificates: Vec<String>) -> Result<Self, StorageError> {
        if certificates.is_empty() {
            return Err(StorageError::EmptyCertificates);
        }
        Ok(Self {
            certificates,
            private_key_pem,
        })
    }

    /// [`CertificateDownload`] çıktısından demet oluşturur.
    ///
    /// # Errors
    ///
    /// Zincir boşsa [`StorageError::EmptyCertificates`] döner.
    pub fn from_download(
        download: &CertificateDownload,
        private_key_pem: String,
    ) -> Result<Self, StorageError> {
        Self::new(private_key_pem, download.certificates().to_vec())
    }

    #[must_use]
    pub fn certificates(&self) -> &[String] {
        &self.certificates
    }

    #[must_use]
    pub fn leaf_certificate(&self) -> &str {
        &self.certificates[0]
    }

    #[must_use]
    pub fn intermediates(&self) -> &[String] {
        match self.certificates.len() {
            0..=2 => &self.certificates[0..0],
            len => &self.certificates[1..len - 1],
        }
    }

    #[must_use]
    pub fn root_certificate(&self) -> Option<&str> {
        self.certificates.last().map(String::as_str)
    }

    #[must_use]
    pub fn private_key_pem(&self) -> &str {
        &self.private_key_pem
    }

    #[must_use]
    pub fn full_chain_pem(&self) -> String {
        let mut output = String::new();
        for cert in &self.certificates {
            let mut normalized = cert.trim().to_owned();
            normalized.push('\n');
            output.push_str(&normalized);
        }
        output
    }
}
