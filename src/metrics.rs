use prometheus::{Gauge, HistogramOpts, HistogramVec, Registry};

lazy_static::lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    pub static ref CONNECTIONS: Gauge =
        Gauge::new("turn_connections", "Number of connections established through the TURN server")
        .expect("turn_connections metric could not be created");

    pub static ref IN_BYTES: Gauge =
        Gauge::new("turn_traffic_in_bytes", "Amount of data (in bytes) received through the TURN server each second")
        .expect("turn_traffic_in_bytes metric could not be created");

    pub static ref OUT_BYTES: Gauge =
        Gauge::new("turn_traffic_out_bytes_total", "Amount of data (in bytes) transmitted through the TURN server each second")
        .expect("turn_traffic_out_bytes_total metric could not be created");

    pub static ref RESPONSE_TIME_COLLECTOR: HistogramVec = HistogramVec::new(
        HistogramOpts::new("response_time", "Response Times"),
        &[]
    )
    .expect("response_time metric could not be created");
}

/// Register Prometheus custom metrics on the registery.
#[inline]
pub fn register_custom_metrics() {
    REGISTRY
        .register(Box::new(CONNECTIONS.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(IN_BYTES.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(OUT_BYTES.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(RESPONSE_TIME_COLLECTOR.clone()))
        .expect("collector can be registered");
}
