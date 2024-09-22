use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Init tracing logic.
pub fn init_tracing() {
    let fmt_layer = fmt::layer()
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true);

    tracing_subscriber::registry().with(fmt_layer).init();
}
