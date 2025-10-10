#![allow(clippy::module_name_repetitions)]

use std::env;

use thiserror::Error;
use tracing::subscriber::{set_global_default, SetGlobalDefaultError};
use tracing_subscriber::filter::{EnvFilter, ParseError};
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::layer::SubscriberExt;

#[cfg(feature = "otel")]
use opentelemetry::{
    global,
    trace::{TraceError, TracerProvider},
};
#[cfg(feature = "otel")]
use opentelemetry_otlp::WithExportConfig;

/// Telemetri kurulumu sırasında oluşabilecek hatalar.
#[derive(Debug, Error)]
pub enum TelemetryError {
    /// Log filtresi geçersizdir.
    #[error("log filtresi geçersiz: {0}")]
    InvalidFilter(#[from] ParseError),
    /// Global abonelik kurulamadı.
    #[error("tracing aboneliği kurulamadı: {0}")]
    Subscriber(#[from] SetGlobalDefaultError),
    /// OpenTelemetry başlatılamadı.
    #[cfg(feature = "otel")]
    #[error("OpenTelemetry başlatılamadı: {0}")]
    OpenTelemetry(#[from] TraceError),
}

/// Telemetri yaşam döngüsünü yönetir.
#[must_use]
#[derive(Debug)]
pub struct TelemetryGuard {
    otel_enabled: bool,
}

impl TelemetryGuard {
    /// OpenTelemetry katmanı etkin mi?
    #[must_use]
    pub const fn otel_enabled(&self) -> bool {
        self.otel_enabled
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        #[cfg(feature = "otel")]
        if self.otel_enabled {
            opentelemetry::global::shutdown_tracer_provider();
        }
    }
}

/// Ortam değişkenlerinden tracing/telemetri aboneliğini başlatır.
///
/// * `AUNSORM_LOG` veya `RUST_LOG` log filtresini belirler.
/// * `AUNSORM_OTEL_ENDPOINT` veya `OTEL_EXPORTER_OTLP_ENDPOINT` ayarlanırsa
///   OTLP/HTTP üzerinden OpenTelemetry ihracatı açılır.
///
/// # Errors
///
/// Geçersiz log filtresi ya da abonelik kurulumu başarısız olursa hata döner.
pub fn init_tracing(service_name: &str) -> Result<TelemetryGuard, TelemetryError> {
    let filter = env::var("AUNSORM_LOG")
        .or_else(|_| env::var("RUST_LOG"))
        .unwrap_or_else(|_| "info".to_string());
    #[cfg(not(feature = "otel"))]
    let _ = service_name;
    #[cfg(feature = "otel")]
    let otel_enabled = {
        if let Some((layer, provider)) = otel_layer(service_name)? {
            global::set_tracer_provider(provider);
            let subscriber = tracing_subscriber::registry()
                .with(layer)
                .with(EnvFilter::try_new(filter.as_str())?)
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_timer(SystemTime)
                        .with_target(true),
                );
            set_global_default(subscriber).map_err(TelemetryError::Subscriber)?;
            true
        } else {
            let subscriber = tracing_subscriber::registry()
                .with(EnvFilter::try_new(filter.as_str())?)
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_timer(SystemTime)
                        .with_target(true),
                );
            set_global_default(subscriber).map_err(TelemetryError::Subscriber)?;
            false
        }
    };

    #[cfg(not(feature = "otel"))]
    let otel_enabled = {
        let subscriber = tracing_subscriber::registry()
            .with(EnvFilter::try_new(filter)?)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_timer(SystemTime)
                    .with_target(true),
            );
        set_global_default(subscriber).map_err(TelemetryError::Subscriber)?;
        false
    };

    Ok(TelemetryGuard { otel_enabled })
}

#[cfg(feature = "otel")]
type OtlpLayer = tracing_opentelemetry::OpenTelemetryLayer<
    tracing_subscriber::Registry,
    opentelemetry_sdk::trace::Tracer,
>;

#[cfg(feature = "otel")]
fn otel_layer(
    service_name: &str,
) -> Result<Option<(OtlpLayer, opentelemetry_sdk::trace::TracerProvider)>, TelemetryError> {
    let Some(endpoint) = otel_endpoint_from_env() else {
        return Ok(None);
    };
    let (provider, tracer) = build_tracer(service_name, &endpoint)?;
    let layer = tracing_opentelemetry::layer().with_tracer(tracer);
    Ok(Some((layer, provider)))
}

#[cfg(feature = "otel")]
fn otel_endpoint_from_env() -> Option<String> {
    env::var("AUNSORM_OTEL_ENDPOINT")
        .ok()
        .or_else(|| env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok())
}

#[cfg(feature = "otel")]
fn build_tracer(
    service_name: &str,
    endpoint: &str,
) -> Result<
    (
        opentelemetry_sdk::trace::TracerProvider,
        opentelemetry_sdk::trace::Tracer,
    ),
    TelemetryError,
> {
    use opentelemetry::KeyValue;
    use opentelemetry_sdk::trace;
    use opentelemetry_sdk::Resource;

    let exporter = opentelemetry_otlp::new_exporter()
        .http()
        .with_endpoint(endpoint.to_string());

    let config = trace::Config::default().with_resource(Resource::new(vec![
        KeyValue::new("service.name", service_name.to_string()),
        KeyValue::new("service.namespace", "aunsorm"),
    ]));

    let provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(config)
        .install_batch(opentelemetry_sdk::runtime::Tokio)?;
    let tracer = provider.tracer(service_name.to_string());
    Ok((provider, tracer))
}
