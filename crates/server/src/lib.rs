#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
#![cfg_attr(
    test,
    allow(
        clippy::cast_lossless,
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cloned_instead_of_copied,
        clippy::suboptimal_flops,
        clippy::too_many_lines,
        clippy::uninlined_format_args
    )
)]

//! Aunsorm OAuth benzeri sunucu bileşeni.

mod config;
mod error;
mod quic;
mod routes;
mod state;
mod telemetry;
mod transparency;

pub use config::{LedgerBackend, ServerConfig};
pub use error::{ApiError, ServerError};
pub use quic::datagram::{
    AuditEvent, AuditOutcome, CounterSample, DatagramChannel, DatagramError, DatagramPayload,
    GaugeSample, HistogramBucket, HistogramSample, OtelPayload, QuicDatagramV1, RatchetProbe,
    RatchetStatus, MAX_PAYLOAD_BYTES, MAX_WIRE_BYTES,
};
pub use routes::{build_router, serve};
pub use state::ServerState;
pub use telemetry::{init_tracing, TelemetryError, TelemetryGuard};
pub use transparency::{TransparencyEvent, TransparencyLogEntry, TransparencySnapshot};

#[cfg(test)]
mod tests;
