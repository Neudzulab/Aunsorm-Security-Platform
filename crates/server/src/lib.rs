#![forbid(unsafe_code)]
#![warn(warnings)]
#![deny(clippy::all)]
#![warn(clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::option_map_or_none)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::single_char_pattern)]
#![allow(clippy::manual_pattern_char_comparison)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::redundant_pub_crate)]
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

mod acme;
mod clock_refresh;
mod config;
mod error;
pub(crate) mod fabric;
mod jobs;
mod quic;
mod rng;
mod routes;
mod state;
mod telemetry;
mod transparency;

pub use clock_refresh::{ClockRefreshError, ClockRefreshService};
pub use config::{FabricChaincodeConfig, LedgerBackend, ServerConfig};
pub use error::{ApiError, ServerError};
pub use quic::datagram::{
    AuditEvent, AuditOutcome, CounterSample, DatagramChannel, DatagramError, DatagramPayload,
    GaugeSample, HistogramBucket, HistogramSample, OtelPayload, QuicDatagramV1, RatchetProbe,
    RatchetStatus, MAX_PAYLOAD_BYTES, MAX_WIRE_BYTES,
};
#[cfg(feature = "http3-experimental")]
pub use quic::{build_alt_svc_header_value, spawn_http3_poc, Http3PocGuard, ALT_SVC_MAX_AGE};
pub use rng::{create_aunsorm_rng, AunsormNativeRng};
pub use routes::{build_router, serve};
pub use state::ServerState;
pub use telemetry::{init_tracing, TelemetryError, TelemetryGuard};
pub use transparency::{TransparencyEvent, TransparencyLogEntry, TransparencySnapshot};

#[cfg(test)]
mod tests;
