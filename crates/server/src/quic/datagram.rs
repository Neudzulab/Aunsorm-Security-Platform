use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// QUIC datagramlarında izin verilen en yüksek yük boyutu (bayt).
pub const MAX_PAYLOAD_BYTES: usize = 1150;
/// QUIC datagram paketinin (başlık + yük) izin verilen en yüksek toplam boyutu.
pub const MAX_WIRE_BYTES: usize = 1350;

/// HTTP/3 QUIC datagramları için hata türü.
#[derive(Debug, Error)]
pub enum DatagramError {
    /// Kodlama sırasında `postcard` hata verdi.
    #[error("serialization failure: {0}")]
    Serialization(String),
    /// Dekodlama sırasında `postcard` hata verdi.
    #[error("deserialization failure: {0}")]
    Deserialization(String),
    /// Yük boyutu sınırı aşıldı.
    #[error("payload too large: {actual} bytes (max {max})")]
    PayloadTooLarge { actual: usize, max: usize },
    /// Desteklenmeyen versiyon değeri.
    #[error("unsupported datagram version: {0}")]
    UnsupportedVersion(u8),
    /// Sistem zamanı UNIX epoch öncesine düştü.
    #[error("system time is before unix epoch")]
    TimeInversion,
    /// Zaman damgası `u64` sınırını aştı.
    #[error("timestamp overflow")]
    TimestampOverflow,
}

/// Datagram kanal türleri.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramChannel {
    /// OpenTelemetry uyumlu metrikler.
    Telemetry = 0,
    /// Denetim olay akışı.
    Audit = 1,
    /// Oturum ratchet gözlemleri.
    Ratchet = 2,
}

impl DatagramChannel {
    /// Kanal numarasını döndürür.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl Serialize for DatagramChannel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.as_u8())
    }
}

impl<'de> Deserialize<'de> for DatagramChannel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        match value {
            0 => Ok(Self::Telemetry),
            1 => Ok(Self::Audit),
            2 => Ok(Self::Ratchet),
            other => Err(D::Error::custom(format!(
                "unknown datagram channel: {other}"
            ))),
        }
    }
}

/// QUIC datagram yük türleri.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DatagramPayload {
    /// OpenTelemetry uyumlu metrik anlık görüntüsü.
    Otel(OtelPayload),
    /// Denetim olayı.
    Audit(AuditEvent),
    /// Oturum ratchet gözlemi.
    Ratchet(RatchetProbe),
}

impl DatagramPayload {
    /// İlgili kanal türünü döndürür.
    #[must_use]
    pub const fn channel(&self) -> DatagramChannel {
        match self {
            Self::Otel(_) => DatagramChannel::Telemetry,
            Self::Audit(_) => DatagramChannel::Audit,
            Self::Ratchet(_) => DatagramChannel::Ratchet,
        }
    }

    fn encoded_len(&self) -> Result<usize, DatagramError> {
        postcard::to_allocvec(self)
            .map(|bytes| bytes.len())
            .map_err(|err| DatagramError::Serialization(err.to_string()))
    }
}

/// OpenTelemetry metrik anlık görüntüsü.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct OtelPayload {
    #[serde(default)]
    pub counters: Vec<CounterSample>,
    #[serde(default)]
    pub gauges: Vec<GaugeSample>,
    #[serde(default)]
    pub histograms: Vec<HistogramSample>,
}

impl OtelPayload {
    /// Yeni boş bir metrik anlık görüntüsü.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sayaç örneği ekler.
    pub fn add_counter(&mut self, name: impl Into<String>, value: u64) {
        self.counters.push(CounterSample {
            name: name.into(),
            value,
        });
    }

    /// Gauge örneği ekler.
    pub fn add_gauge(&mut self, name: impl Into<String>, value: f64) {
        self.gauges.push(GaugeSample {
            name: name.into(),
            value,
        });
    }

    /// Histogram örneği ekler.
    pub fn add_histogram<I>(&mut self, name: impl Into<String>, buckets: I)
    where
        I: IntoIterator<Item = HistogramBucket>,
    {
        self.histograms.push(HistogramSample {
            name: name.into(),
            buckets: buckets.into_iter().collect(),
        });
    }
}

/// Sayaç metriği.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CounterSample {
    pub name: String,
    pub value: u64,
}

/// Gauge metriği.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GaugeSample {
    pub name: String,
    pub value: f64,
}

/// Histogram metriği.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistogramSample {
    pub name: String,
    pub buckets: Vec<HistogramBucket>,
}

/// Histogram kovası.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistogramBucket {
    pub upper_bound: f64,
    pub count: u64,
}

impl HistogramBucket {
    /// Yeni histogram kovası oluşturur.
    #[must_use]
    pub const fn new(upper_bound: f64, count: u64) -> Self {
        Self { upper_bound, count }
    }
}

/// Denetim olayı.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub event_id: String,
    pub principal_id: String,
    pub outcome: AuditOutcome,
    pub resource: String,
}

/// Denetim olay sonucu.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Failure,
}

/// Ratchet gözlemi.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RatchetProbe {
    pub session_id: [u8; 16],
    pub step: u64,
    pub drift: i64,
    pub status: RatchetStatus,
}

/// Ratchet gözlemi durumu.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RatchetStatus {
    Advancing,
    Stalled,
}

/// QUIC datagram v1 zarfı.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QuicDatagramV1 {
    /// Versiyon numarası (her zaman 1).
    pub version: u8,
    /// Kanal türü.
    pub channel: DatagramChannel,
    /// Sarma modunda ilerleyen sıra numarası.
    pub sequence: u32,
    /// UNIX epoch milisaniye cinsinden zaman damgası.
    pub timestamp_ms: u64,
    /// Yük verisi.
    pub payload: DatagramPayload,
}

impl QuicDatagramV1 {
    /// Geçerli versiyon numarası.
    pub const VERSION: u8 = 1;

    /// Yeni bir datagram üretir.
    ///
    /// # Errors
    ///
    /// Eğer yük serileştirilemezse veya izin verilen sınırları aşarsa
    /// [`DatagramError`] döner.
    pub fn new(
        sequence: u32,
        timestamp_ms: u64,
        payload: DatagramPayload,
    ) -> Result<Self, DatagramError> {
        let datagram = Self {
            version: Self::VERSION,
            channel: payload.channel(),
            sequence,
            timestamp_ms,
            payload,
        };
        datagram.ensure_payload_within_bounds()?;
        Ok(datagram)
    }

    /// Şu anki zamanı milisaniye cinsinden döndürür.
    ///
    /// # Errors
    ///
    /// Sistem saati UNIX epoch öncesine düşerse veya değer `u64`
    /// sınırını aşarsa [`DatagramError`] döner.
    pub fn now_timestamp_ms() -> Result<u64, DatagramError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DatagramError::TimeInversion)?;
        u64::try_from(duration.as_millis()).map_err(|_| DatagramError::TimestampOverflow)
    }

    /// Datagrımı `postcard` ile kodlar.
    ///
    /// # Errors
    ///
    /// Serileştirme başarısız olursa veya ortaya çıkan tel uzunluğu sınırları
    /// aşarsa [`DatagramError`] döner.
    pub fn encode(&self) -> Result<Vec<u8>, DatagramError> {
        self.ensure_payload_within_bounds()?;
        let bytes = postcard::to_allocvec(self)
            .map_err(|err| DatagramError::Serialization(err.to_string()))?;
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(DatagramError::PayloadTooLarge {
                actual: bytes.len(),
                max: MAX_WIRE_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Bayt dizisinden datagramı çözer.
    ///
    /// # Errors
    ///
    /// Serileştirilen veri geçersizse, sürüm desteklenmiyorsa veya yük sınırı
    /// aşılıyorsa [`DatagramError`] döner.
    pub fn decode(bytes: &[u8]) -> Result<Self, DatagramError> {
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(DatagramError::PayloadTooLarge {
                actual: bytes.len(),
                max: MAX_WIRE_BYTES,
            });
        }
        let datagram: Self = postcard::from_bytes(bytes)
            .map_err(|err| DatagramError::Deserialization(err.to_string()))?;
        if datagram.version != Self::VERSION {
            return Err(DatagramError::UnsupportedVersion(datagram.version));
        }
        datagram.ensure_payload_within_bounds()?;
        Ok(datagram)
    }

    /// Toplam tel uzunluğunu döndürür.
    ///
    /// # Errors
    ///
    /// Serileştirme sırasında hata oluşursa [`DatagramError`] döner.
    pub fn encoded_len(&self) -> Result<usize, DatagramError> {
        let bytes = self.encode()?;
        Ok(bytes.len())
    }

    fn ensure_payload_within_bounds(&self) -> Result<(), DatagramError> {
        let payload_len = self.payload.encoded_len()?;
        if payload_len > MAX_PAYLOAD_BYTES {
            return Err(DatagramError::PayloadTooLarge {
                actual: payload_len,
                max: MAX_PAYLOAD_BYTES,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_payload_size_is_within_limits() {
        let mut otel = OtelPayload::new();
        otel.add_counter("pending_auth_requests", 3);
        otel.add_counter("active_tokens", 2);
        otel.add_gauge("sfu_contexts", 1.0);
        let frame = QuicDatagramV1::new(1, 1_726_092_800_000, DatagramPayload::Otel(otel))
            .expect("datagram constructed");
        let encoded = frame.encode().expect("datagram encodes");
        assert!(encoded.len() <= MAX_WIRE_BYTES);
        // The reference length allows the PoC ölçüm tablosu için doğrulama sağlar.
        assert_eq!(encoded.len(), 72);
    }
}
