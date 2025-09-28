use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::LogExporter;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::logs::{LogError, SdkLogger};
use opentelemetry_sdk::Resource;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Init tracing logic.
pub fn init_logging(otel: &str) -> Result<(), LogError> {
    let logging_layer = setup_logging(otel)?;

    let fmt_layer = fmt::layer()
        .with_file(true)
        .with_line_number(true);

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(logging_layer)
        .init();

    Ok(())
}

fn ressources() -> Resource {
    Resource::builder().with_service_name("turms_turn").build()
}

/// Create OLTP exporter for logs.
pub fn setup_logging(
    endpoint: &str,
) -> Result<OpenTelemetryTracingBridge<SdkLoggerProvider, SdkLogger>, LogError>
{
    let exporter = LogExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;
    let provider: SdkLoggerProvider = SdkLoggerProvider::builder()
        .with_resource(ressources())
        .with_batch_exporter(exporter)
        .build();
    Ok(
        opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(
            &provider,
        ),
    )
}
