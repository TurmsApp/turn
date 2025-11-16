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
pub fn init_logging(otel: Option<String>) -> Result<(), LogError> {
    let fmt_layer = fmt::layer().with_file(true).with_line_number(true);

    let level = if cfg!(debug_assertions) {
        "debug"
    } else {
        "info"
    };
    let sub = tracing_subscriber::registry().with(
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            format!(
                "{}={level}",
                env!("CARGO_CRATE_NAME")
            )
            .into()
        }),
    ).with(fmt_layer);

    if let Some(addr) = otel {
        let logging_layer = setup_logging(&addr)?;
        sub.with(logging_layer).init();
    } else {
        sub.init();
    }

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
    println!("{endpoint:?}");
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
