use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// QUIC datagramlarında izin verilen en yüksek yük boyutu (bayt).
pub const MAX_PAYLOAD_BYTES: usize = 1150;
/// QUIC datagram paketinin (başlık + yük) izin verilen en yüksek toplam boyutu.
pub const MAX_WIRE_BYTES: usize = 1350;
/// HD audio hattı için tek datagrama sığmasına izin verilen en yüksek PCM shard boyutu.
pub const MAX_AUDIO_FRAGMENT_BYTES: usize = 960;

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
    /// Gauge metric value is not finite.
    #[error("gauge '{name}' value must be finite (got {value})")]
    NonFiniteGauge { name: String, value: f64 },
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
    /// 96kHz PCM ses shard'ları.
    Audio = 3,
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
            3 => Ok(Self::Audio),
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
    /// 96kHz PCM ses shard'ı.
    Audio(AudioPcmDatagram),
}

impl DatagramPayload {
    /// İlgili kanal türünü döndürür.
    #[must_use]
    pub const fn channel(&self) -> DatagramChannel {
        match self {
            Self::Otel(_) => DatagramChannel::Telemetry,
            Self::Audit(_) => DatagramChannel::Audit,
            Self::Ratchet(_) => DatagramChannel::Ratchet,
            Self::Audio(_) => DatagramChannel::Audio,
        }
    }

    fn encoded_len(&self) -> Result<usize, DatagramError> {
        postcard::to_allocvec(self)
            .map(|bytes| bytes.len())
            .map_err(|err| DatagramError::Serialization(err.to_string()))
    }
}

/// HD audio datagramları için örnek formatı.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AudioSampleFormat {
    /// Signed 16-bit little-endian PCM.
    S16Le,
}

/// 96kHz PCM ses datagramı.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AudioPcmDatagram {
    pub stream_id: u32,
    pub sample_rate_hz: u32,
    pub channels: u8,
    pub sample_format: AudioSampleFormat,
    pub frame_samples: u16,
    pub frame_duration_ms: u16,
    pub fragment_index: u8,
    pub fragment_count: u8,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

impl AudioPcmDatagram {
    pub const SAMPLE_RATE_HZ: u32 = 96_000;
    pub const CHANNELS: u8 = 1;
    pub const FRAME_SAMPLES: u16 = 960;
    pub const FRAME_DURATION_MS: u16 = 10;
    /// Decrypted mono S16LE bytes in one complete 10 ms frame.
    pub const FRAME_BYTES: usize = Self::FRAME_SAMPLES as usize * 2;

    /// Tek bir PCM shard'ı oluşturur.
    ///
    /// # Errors
    ///
    /// Fragment bilgisi geçersizse veya payload shard sınırını aşarsa
    /// [`DatagramError`] döner.
    pub fn new(
        stream_id: u32,
        fragment_index: u8,
        fragment_count: u8,
        payload: Vec<u8>,
    ) -> Result<Self, DatagramError> {
        let fragment = Self {
            stream_id,
            sample_rate_hz: Self::SAMPLE_RATE_HZ,
            channels: Self::CHANNELS,
            sample_format: AudioSampleFormat::S16Le,
            frame_samples: Self::FRAME_SAMPLES,
            frame_duration_ms: Self::FRAME_DURATION_MS,
            fragment_index,
            fragment_count,
            payload,
        };
        fragment.validate()?;
        Ok(fragment)
    }

    /// Validate the fixed sample lattice and fragment metadata.
    ///
    /// The shard bytes are opaque: encrypted envelopes may have a different
    /// length and alignment from their decrypted S16LE samples.
    ///
    /// # Errors
    ///
    /// Returns [`DatagramError`] for unsupported sampling/profile fields,
    /// invalid fragment indices or a shard exceeding its byte budget.
    ///
    /// # Examples
    ///
    /// ```
    /// use aunsorm_server::AudioPcmDatagram;
    /// let shard = AudioPcmDatagram::new(7, 0, 2, vec![0; 960])?;
    /// shard.validate()?;
    /// # Ok::<(), aunsorm_server::DatagramError>(())
    /// ```
    pub fn validate(&self) -> Result<(), DatagramError> {
        if self.sample_rate_hz != Self::SAMPLE_RATE_HZ
            || self.channels != Self::CHANNELS
            || self.frame_samples != Self::FRAME_SAMPLES
            || self.frame_duration_ms != Self::FRAME_DURATION_MS
        {
            return Err(DatagramError::Deserialization(
                "unsupported audio sampling profile: expected 96000 Hz mono, 960 samples / 10 ms"
                    .to_owned(),
            ));
        }
        if self.fragment_count == 0 || self.fragment_index >= self.fragment_count {
            return Err(DatagramError::Deserialization(
                "audio fragment metadata is invalid".to_owned(),
            ));
        }
        if self.payload.len() > MAX_AUDIO_FRAGMENT_BYTES {
            return Err(DatagramError::PayloadTooLarge {
                actual: self.payload.len(),
                max: MAX_AUDIO_FRAGMENT_BYTES,
            });
        }

        Ok(())
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
    ///
    /// # Errors
    ///
    /// Eğer değer sonlu değilse [`DatagramError::NonFiniteGauge`] döner.
    pub fn add_gauge(&mut self, name: impl Into<String>, value: f64) -> Result<(), DatagramError> {
        let name = name.into();
        if !value.is_finite() {
            return Err(DatagramError::NonFiniteGauge { name, value });
        }
        self.gauges.push(GaugeSample { name, value });
        Ok(())
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
        let (datagram, remainder): (Self, &[u8]) = postcard::take_from_bytes(bytes)
            .map_err(|err| DatagramError::Deserialization(err.to_string()))?;
        if !remainder.is_empty() {
            return Err(DatagramError::Deserialization(
                "trailing bytes after datagram".to_owned(),
            ));
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

    /// Split one complete decrypted PCM frame into bounded datagrams.
    ///
    /// Fragment sequences advance from `sequence` with wrapping arithmetic;
    /// all fragments retain the same timestamp and stream ID. This helper does
    /// not encrypt or authenticate samples; apply the established transport /
    /// E2EE protection before transmitting them.
    ///
    /// # Errors
    ///
    /// Returns [`DatagramError`] when PCM has a different length from the
    /// advertised fixed profile or datagram serialization exceeds its budget.
    ///
    /// # Examples
    ///
    /// ```
    /// use aunsorm_server::{AudioPcmDatagram, QuicDatagramV1};
    /// let pcm = vec![0; AudioPcmDatagram::FRAME_BYTES];
    /// let shards = QuicDatagramV1::from_pcm_frame(42, 1000, 7, &pcm)?;
    /// assert_eq!(QuicDatagramV1::reassemble_pcm_frame(&shards)?, pcm);
    /// # Ok::<(), aunsorm_server::DatagramError>(())
    /// ```
    pub fn from_pcm_frame(
        sequence: u32,
        timestamp_ms: u64,
        stream_id: u32,
        pcm: &[u8],
    ) -> Result<Vec<Self>, DatagramError> {
        Self::from_pcm_frame_with_fragment_bytes(
            sequence,
            timestamp_ms,
            stream_id,
            pcm,
            MAX_AUDIO_FRAGMENT_BYTES,
        )
    }

    /// Split PCM while reserving space for caller-owned encrypted envelopes.
    ///
    /// `plaintext_fragment_bytes` must be even and in `8..=960`. Subtract all
    /// nonce/tag/envelope bytes from the wire shard budget before calling this
    /// helper. For example, a 12-byte nonce and 16-byte tag leave 932 plaintext
    /// bytes and require three fragments. Authenticate metadata and connection
    /// context, then decrypt each fragment before `reassemble_pcm_frame`.
    /// This helper neither encrypts data nor adopts an envelope/AAD protocol.
    ///
    /// # Errors
    ///
    /// Returns [`DatagramError`] for invalid fragment budgets or frame lengths.
    pub fn from_pcm_frame_with_fragment_bytes(
        sequence: u32,
        timestamp_ms: u64,
        stream_id: u32,
        pcm: &[u8],
        plaintext_fragment_bytes: usize,
    ) -> Result<Vec<Self>, DatagramError> {
        if !(8..=MAX_AUDIO_FRAGMENT_BYTES).contains(&plaintext_fragment_bytes)
            || plaintext_fragment_bytes % 2 != 0
        {
            return Err(DatagramError::Deserialization(
                "plaintext fragment budget must be even and in 8..=960 bytes".to_owned(),
            ));
        }
        if pcm.len() != AudioPcmDatagram::FRAME_BYTES {
            return Err(DatagramError::Deserialization(
                "complete PCM frame must contain exactly 1920 decrypted bytes".to_owned(),
            ));
        }
        let count = u8::try_from(pcm.chunks(plaintext_fragment_bytes).len())
            .map_err(|_| DatagramError::Deserialization("too many audio fragments".to_owned()))?;
        pcm.chunks(plaintext_fragment_bytes)
            .enumerate()
            .map(|(index, payload)| {
                let index = u8::try_from(index).map_err(|_| {
                    DatagramError::Deserialization("audio fragment index overflow".to_owned())
                })?;
                let audio = AudioPcmDatagram::new(stream_id, index, count, payload.to_vec())?;
                Self::new(
                    sequence.wrapping_add(u32::from(index)),
                    timestamp_ms,
                    DatagramPayload::Audio(audio),
                )
            })
            .collect()
    }

    /// Reassemble exactly one complete, already authenticated/decrypted frame.
    ///
    /// Accepts reordered fragments but rejects duplicates, loss and mixed
    /// streams/timestamps/sequence bases. Call only after authenticating the
    /// envelope and decrypting the payload: this structural check does not
    /// authenticate data and never estimates missing samples. Isolate inputs by
    /// authenticated connection/session and bind fragment metadata to the
    /// envelope authentication (e.g. AEAD associated data).
    ///
    /// # Errors
    ///
    /// Returns [`DatagramError`] on invalid metadata, incomplete/duplicate sets,
    /// mixed frame identity or a total different from 1920 PCM bytes.
    pub fn reassemble_pcm_frame(fragments: &[Self]) -> Result<Vec<u8>, DatagramError> {
        let first = fragments.first().ok_or_else(|| {
            DatagramError::Deserialization("audio frame has no fragments".to_owned())
        })?;
        first.ensure_payload_within_bounds()?;
        let DatagramPayload::Audio(first_audio) = &first.payload else {
            return Err(DatagramError::Deserialization(
                "expected audio fragments".to_owned(),
            ));
        };
        if fragments.len() != usize::from(first_audio.fragment_count) {
            return Err(DatagramError::Deserialization(
                "audio frame is incomplete".to_owned(),
            ));
        }
        let base_sequence = first
            .sequence
            .wrapping_sub(u32::from(first_audio.fragment_index));
        let mut ordered = vec![None; fragments.len()];
        let mut length = 0;
        for fragment in fragments {
            fragment.ensure_payload_within_bounds()?;
            let DatagramPayload::Audio(audio) = &fragment.payload else {
                return Err(DatagramError::Deserialization(
                    "expected audio fragments".to_owned(),
                ));
            };
            if audio.stream_id != first_audio.stream_id
                || audio.fragment_count != first_audio.fragment_count
                || fragment.timestamp_ms != first.timestamp_ms
                || fragment
                    .sequence
                    .wrapping_sub(u32::from(audio.fragment_index))
                    != base_sequence
            {
                return Err(DatagramError::Deserialization(
                    "mixed audio frame identity".to_owned(),
                ));
            }
            let entry = &mut ordered[usize::from(audio.fragment_index)];
            if entry.is_some() {
                return Err(DatagramError::Deserialization(
                    "duplicate audio fragment".to_owned(),
                ));
            }
            *entry = Some(audio);
            length += audio.payload.len();
            if length > AudioPcmDatagram::FRAME_BYTES {
                return Err(DatagramError::Deserialization(
                    "PCM frame exceeds 1920 bytes".to_owned(),
                ));
            }
        }
        if length != AudioPcmDatagram::FRAME_BYTES {
            return Err(DatagramError::Deserialization(
                "PCM frame has an invalid sample count".to_owned(),
            ));
        }
        let mut pcm = Vec::with_capacity(length);
        for audio in ordered {
            let audio = audio.ok_or_else(|| {
                DatagramError::Deserialization("missing audio fragment".to_owned())
            })?;
            pcm.extend_from_slice(&audio.payload);
        }
        Ok(pcm)
    }

    fn ensure_payload_within_bounds(&self) -> Result<(), DatagramError> {
        if self.version != Self::VERSION {
            return Err(DatagramError::UnsupportedVersion(self.version));
        }
        if self.channel != self.payload.channel() {
            return Err(DatagramError::Deserialization(
                "datagram channel does not match payload".to_owned(),
            ));
        }
        match &self.payload {
            DatagramPayload::Audio(audio) => audio.validate()?,
            DatagramPayload::Otel(otel) => {
                for gauge in &otel.gauges {
                    if !gauge.value.is_finite() {
                        return Err(DatagramError::NonFiniteGauge {
                            name: gauge.name.clone(),
                            value: gauge.value,
                        });
                    }
                }
                for histogram in &otel.histograms {
                    if histogram.buckets.iter().any(|bucket| {
                        bucket.upper_bound.is_nan() || bucket.upper_bound == f64::NEG_INFINITY
                    }) {
                        return Err(DatagramError::Deserialization(
                            "histogram upper bounds must be finite or positive infinity".to_owned(),
                        ));
                    }
                }
            }
            DatagramPayload::Audit(_) | DatagramPayload::Ratchet(_) => {}
        }
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
        otel.add_gauge("sfu_contexts", 1.0)
            .expect("gauge value is finite");
        let frame = QuicDatagramV1::new(1, 1_726_092_800_000, DatagramPayload::Otel(otel))
            .expect("datagram constructed");
        let encoded = frame.encode().expect("datagram encodes");
        assert!(encoded.len() <= MAX_WIRE_BYTES);
        // The reference length allows the PoC ölçüm tablosu için doğrulama sağlar.
        assert_eq!(encoded.len(), 72);
    }

    #[test]
    fn gauge_values_must_be_finite() {
        let mut otel = OtelPayload::new();
        let err = otel
            .add_gauge("sfu_contexts", f64::NAN)
            .expect_err("non-finite values are rejected");
        assert!(matches!(
            err,
            DatagramError::NonFiniteGauge {
                name,
                value
            } if name == "sfu_contexts" && value.is_nan()
        ));
    }

    #[test]
    fn audio_channel_datagram_round_trips() {
        let payload = AudioPcmDatagram::new(7, 0, 2, vec![0x55; 480]).expect("audio payload");
        let frame = QuicDatagramV1::new(9, 1_726_092_800_123, DatagramPayload::Audio(payload))
            .expect("datagram constructed");
        let encoded = frame.encode().expect("datagram encodes");
        let decoded = QuicDatagramV1::decode(&encoded).expect("datagram decodes");

        assert_eq!(decoded.channel, DatagramChannel::Audio);
        assert!(encoded.len() <= MAX_WIRE_BYTES);
    }

    #[test]
    fn audio_channel_rejects_oversized_fragments() {
        let err = AudioPcmDatagram::new(7, 0, 1, vec![0x11; MAX_AUDIO_FRAGMENT_BYTES + 1])
            .expect_err("oversized fragments must fail");

        assert!(matches!(
            err,
            DatagramError::PayloadTooLarge {
                actual,
                max: MAX_AUDIO_FRAGMENT_BYTES
            } if actual == MAX_AUDIO_FRAGMENT_BYTES + 1
        ));
    }

    fn raw_datagram(payload: DatagramPayload) -> QuicDatagramV1 {
        QuicDatagramV1 {
            version: QuicDatagramV1::VERSION,
            channel: payload.channel(),
            sequence: 10,
            timestamp_ms: 1000,
            payload,
        }
    }

    fn assert_rejected_at_both_boundaries(frame: &QuicDatagramV1) {
        assert!(frame.encode().is_err());
        // An attacker can bypass constructors and send postcard bytes directly.
        let wire = postcard::to_allocvec(frame).expect("serialize malformed fixture");
        assert!(QuicDatagramV1::decode(&wire).is_err());
    }

    #[test]
    fn audio_sampling_metadata_cannot_bypass_the_constructor() {
        let valid = AudioPcmDatagram::new(7, 0, 2, vec![0; 960]).unwrap();
        let mut invalid = vec![valid.clone(); 7];
        invalid[0].sample_rate_hz = 48_000;
        invalid[1].channels = 2;
        invalid[2].frame_samples = 480;
        invalid[3].frame_duration_ms = 20;
        invalid[4].fragment_count = 0;
        invalid[5].fragment_index = 2;
        invalid[6].payload.push(0);
        for audio in invalid {
            assert!(audio.validate().is_err());
            assert_rejected_at_both_boundaries(&raw_datagram(DatagramPayload::Audio(audio)));
        }
        assert_eq!(
            u64::from(valid.sample_rate_hz) * u64::from(valid.frame_duration_ms),
            u64::from(valid.frame_samples) * 1000
        );
    }

    #[test]
    fn channel_and_version_mutations_are_rejected_before_encoding() {
        let mut frame = raw_datagram(DatagramPayload::Otel(OtelPayload::new()));
        frame.channel = DatagramChannel::Audio;
        assert_rejected_at_both_boundaries(&frame);
        frame.channel = DatagramChannel::Telemetry;
        frame.version = 2;
        assert_rejected_at_both_boundaries(&frame);
    }

    #[test]
    fn trailing_bytes_do_not_form_a_valid_datagram() {
        let frame = raw_datagram(DatagramPayload::Otel(OtelPayload::new()));
        let mut wire = frame.encode().unwrap();
        wire.extend_from_slice(&[0, 1, 2]);
        assert!(QuicDatagramV1::decode(&wire).is_err());
    }

    #[test]
    fn nonfinite_gauges_cannot_bypass_the_builder() {
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let otel = OtelPayload {
                gauges: vec![GaugeSample {
                    name: "untrusted".to_owned(),
                    value,
                }],
                ..OtelPayload::default()
            };
            assert_rejected_at_both_boundaries(&raw_datagram(DatagramPayload::Otel(otel)));
        }
    }

    #[test]
    fn histogram_nan_is_rejected_and_positive_infinity_is_preserved() {
        for upper_bound in [f64::NAN, f64::NEG_INFINITY] {
            let mut otel = OtelPayload::new();
            otel.add_histogram("untrusted", [HistogramBucket::new(upper_bound, 1)]);
            assert_rejected_at_both_boundaries(&raw_datagram(DatagramPayload::Otel(otel)));
        }
        let mut otel = OtelPayload::new();
        otel.add_histogram(
            "latency",
            [
                HistogramBucket::new(1.0, 1),
                HistogramBucket::new(f64::INFINITY, 2),
            ],
        );
        let frame = raw_datagram(DatagramPayload::Otel(otel));
        assert_eq!(
            QuicDatagramV1::decode(&frame.encode().unwrap()).unwrap(),
            frame
        );
    }

    #[test]
    fn opaque_encrypted_shards_do_not_require_pcm_alignment() {
        let audio = AudioPcmDatagram::new(7, 0, 3, vec![0xaa; 17]).unwrap();
        let frame = raw_datagram(DatagramPayload::Audio(audio));
        assert_eq!(
            QuicDatagramV1::decode(&frame.encode().unwrap()).unwrap(),
            frame
        );
    }

    #[test]
    fn pcm_split_roundtrip_preserves_signed_samples_reordering_and_sequence_wrap() {
        let sample_values = [i16::MIN, -1, 0, i16::MAX];
        let pcm: Vec<_> = (0..usize::from(AudioPcmDatagram::FRAME_SAMPLES))
            .flat_map(|index| sample_values[index % sample_values.len()].to_le_bytes())
            .collect();
        let mut shards = QuicDatagramV1::from_pcm_frame(u32::MAX, 1000, 7, &pcm).unwrap();
        assert_eq!(shards.len(), 2);
        assert_eq!(shards[0].sequence, u32::MAX);
        assert_eq!(shards[1].sequence, 0);
        for shard in &mut shards {
            *shard = QuicDatagramV1::decode(&shard.encode().unwrap()).unwrap();
        }
        shards.reverse();
        assert_eq!(QuicDatagramV1::reassemble_pcm_frame(&shards).unwrap(), pcm);
    }

    #[test]
    fn pcm_split_requires_exact_sample_count() {
        for length in [0, 1919, 1921] {
            assert!(QuicDatagramV1::from_pcm_frame(0, 1000, 7, &vec![0; length]).is_err());
        }
    }

    #[test]
    fn pcm_reassembly_rejects_loss_duplicates_and_mixed_identity() {
        let valid =
            QuicDatagramV1::from_pcm_frame(10, 1000, 7, &vec![0; AudioPcmDatagram::FRAME_BYTES])
                .unwrap();
        assert!(QuicDatagramV1::reassemble_pcm_frame(&[]).is_err());
        assert!(QuicDatagramV1::reassemble_pcm_frame(&valid[..1]).is_err());
        assert!(
            QuicDatagramV1::reassemble_pcm_frame(&[valid[0].clone(), valid[0].clone()]).is_err()
        );
        let mut variants = vec![valid; 5];
        variants[0][1].timestamp_ms += 1;
        variants[1][1].sequence += 1;
        if let DatagramPayload::Audio(audio) = &mut variants[2][1].payload {
            audio.stream_id += 1;
        }
        if let DatagramPayload::Audio(audio) = &mut variants[3][1].payload {
            audio.fragment_count += 1;
        }
        variants[4][1].payload = DatagramPayload::Otel(OtelPayload::new());
        variants[4][1].channel = DatagramChannel::Telemetry;
        for shards in variants {
            assert!(QuicDatagramV1::reassemble_pcm_frame(&shards).is_err());
        }
    }

    #[test]
    fn pcm_reassembly_rejects_wrong_length_and_accepts_sample_bytes_split_across_shards() {
        let pcm = vec![0x7f; AudioPcmDatagram::FRAME_BYTES];
        let lengths = [1, 959, 960];
        let mut offset = 0;
        let mut shards = Vec::new();
        for (index, length) in lengths.into_iter().enumerate() {
            let audio = AudioPcmDatagram::new(
                7,
                u8::try_from(index).unwrap(),
                3,
                pcm[offset..offset + length].to_vec(),
            )
            .unwrap();
            shards.push(
                QuicDatagramV1::new(
                    u32::try_from(index).unwrap(),
                    1000,
                    DatagramPayload::Audio(audio),
                )
                .unwrap(),
            );
            offset += length;
        }
        assert_eq!(QuicDatagramV1::reassemble_pcm_frame(&shards).unwrap(), pcm);
        if let DatagramPayload::Audio(audio) = &mut shards[1].payload {
            audio.payload.pop();
        }
        assert!(QuicDatagramV1::reassemble_pcm_frame(&shards).is_err());
    }
}
