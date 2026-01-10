#[cfg(feature = "telemetry")]
use std::env;
#[cfg(feature = "telemetry")]
use std::time::Duration;

#[cfg(feature = "telemetry")]
use opentelemetry::metrics::{Counter, Histogram, Meter, MeterProvider};
#[cfg(feature = "telemetry")]
use opentelemetry::KeyValue;
#[cfg(feature = "telemetry")]
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
#[cfg(feature = "telemetry")]
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
#[cfg(feature = "telemetry")]
use opentelemetry_sdk::Resource;

/// Telemetry configuration and metrics
#[derive(Clone)]
pub struct Telemetry {
    #[cfg(feature = "telemetry")]
    meter: Meter,
    #[cfg(feature = "telemetry")]
    request_counter: Counter<u64>,
    #[cfg(feature = "telemetry")]
    request_duration: Histogram<f64>,
    #[cfg(feature = "telemetry")]
    error_counter: Counter<u64>,
    #[cfg(feature = "telemetry")]
    dns_query_counter: Counter<u64>,
}

impl Telemetry {
    /// Initialize telemetry with New Relic configuration
    pub fn init() -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(feature = "telemetry")]
        {
            // Check if New Relic is configured via environment variables
            let api_key = env::var("NEW_RELIC_LICENSE_KEY").ok();
            let endpoint = env::var("NEW_RELIC_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "https://otlp.nr-data.net:4318".to_string());

            let meter_provider = if api_key.is_some() {
                // Configure OTLP exporter for New Relic
                let mut exporter_builder = opentelemetry_otlp::MetricExporter::builder()
                    .with_http()
                    .with_endpoint(&endpoint)
                    .with_timeout(Duration::from_secs(10));

                // Add API key header if available
                if let Some(key) = api_key {
                    let mut headers = std::collections::HashMap::new();
                    headers.insert("api-key".to_string(), key);
                    exporter_builder = exporter_builder.with_headers(headers);
                }

                let exporter = exporter_builder.build()?;

                // Export interval is configurable via TELEMETRY_EXPORT_INTERVAL_SECS (default: 60 seconds).
                let export_interval_secs = match env::var("TELEMETRY_EXPORT_INTERVAL_SECS") {
                    Ok(val) => val.parse::<u64>().unwrap_or(60),
                    Err(_) => 60,
                };
                let reader =
                    PeriodicReader::builder(exporter)
                        .with_interval(Duration::from_secs(export_interval_secs))
                        .build();

                let resource = Resource::builder_empty()
                    .with_service_name("doh-proxy")
                    .with_attribute(KeyValue::new(
                        "service.version",
                        env!("CARGO_PKG_VERSION"),
                    ))
                    .build();

                SdkMeterProvider::builder()
                    .with_reader(reader)
                    .with_resource(resource)
                    .build()
            } else {
                // No New Relic configured, use noop provider
                eprintln!("Warning: NEW_RELIC_LICENSE_KEY not set, telemetry disabled");
                SdkMeterProvider::builder().build()
            };

            let meter = meter_provider.meter("doh-proxy");

            // Create metrics
            let request_counter = meter
                .u64_counter("doh.requests.total")
                .with_description("Total number of DoH requests")
                .with_unit("1")
                .build();

            let request_duration = meter
                .f64_histogram("doh.request.duration")
                .with_description("Duration of DoH requests in seconds")
                .with_unit("s")
                .build();

            let error_counter = meter
                .u64_counter("doh.errors.total")
                .with_description("Total number of errors")
                .with_unit("1")
                .build();

            let dns_query_counter = meter
                .u64_counter("doh.dns_queries.total")
                .with_description("Total number of DNS queries by type")
                .with_unit("1")
                .build();

            Ok(Telemetry {
                meter,
                request_counter,
                request_duration,
                error_counter,
                dns_query_counter,
            })
        }
        #[cfg(not(feature = "telemetry"))]
        {
            Ok(Telemetry {})
        }
    }

    /// Record a request
    pub fn record_request(&self, method: &str, path: &str, status: u16) {
        #[cfg(feature = "telemetry")]
        {
            self.request_counter.add(
                1,
                &[
                    KeyValue::new("method", method.to_string()),
                    KeyValue::new("path", path.to_string()),
                    KeyValue::new("status", status.to_string()),
                ],
            );
        }
        #[cfg(not(feature = "telemetry"))]
        {
            let _ = (method, path, status);
        }
    }

    /// Record request duration
    pub fn record_duration(&self, method: &str, path: &str, duration_secs: f64) {
        #[cfg(feature = "telemetry")]
        {
            self.request_duration.record(
                duration_secs,
                &[
                    KeyValue::new("method", method.to_string()),
                    KeyValue::new("path", path.to_string()),
                ],
            );
        }
        #[cfg(not(feature = "telemetry"))]
        {
            let _ = (method, path, duration_secs);
        }
    }

    /// Record an error
    pub fn record_error(&self, error_type: &str, endpoint: &str) {
        #[cfg(feature = "telemetry")]
        {
            self.error_counter.add(
                1,
                &[
                    KeyValue::new("error_type", error_type.to_string()),
                    KeyValue::new("endpoint", endpoint.to_string()),
                ],
            );
        }
        #[cfg(not(feature = "telemetry"))]
        {
            let _ = (error_type, endpoint);
        }
    }

    /// Record a DNS query by type
    pub fn record_dns_query(&self, query_type: &str, is_json: bool) {
        #[cfg(feature = "telemetry")]
        {
            self.dns_query_counter.add(
                1,
                &[
                    KeyValue::new("query_type", query_type.to_string()),
                    KeyValue::new("is_json", is_json.to_string()),
                ],
            );
        }
        #[cfg(not(feature = "telemetry"))]
        {
            let _ = (query_type, is_json);
        }
    }

    /// Get the meter for custom metrics
    #[cfg(feature = "telemetry")]
    pub fn meter(&self) -> &Meter {
        &self.meter
    }
}

impl std::fmt::Debug for Telemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Telemetry").finish()
    }
}
