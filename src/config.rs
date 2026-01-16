use anyhow::Context;
use rust_decimal::Decimal;
use serde::Deserialize;
use serde_with::serde_as;
use std::{collections::HashMap, fs, net::SocketAddr, path::PathBuf, time::Duration};

/// The configuration for the authority service.
#[derive(Clone, Deserialize)]
pub struct Config {
    /// The server configuration.
    pub server: ServerConfig,

    /// The private key
    pub private_key: PrivateKeyConfig,

    /// Configuration for Prometheus metrics endpoint.
    pub metrics: MetricsConfig,

    /// OpenTelemetry configuration.
    #[serde(default)]
    pub otel: OtelConfig,

    /// The payments configuration.
    pub payments: PaymentsConfig,

    /// The postgres configuration.
    pub postgres: PostgresConfig,
}

impl Config {
    /// Loads configuration from a YAML file and/or environment variables.
    ///
    /// Environment variables are prefixed with `NILAUTH_` and use `__` as a separator,
    /// for example, `NILAUTH_SERVER__BIND_ENDPOINT=0.0.0.0:8080`.
    pub fn load(path: Option<&str>) -> anyhow::Result<Self> {
        let mut builder =
            config::Config::builder().add_source(config::Environment::with_prefix("NILAUTH").separator("__"));
        if let Some(path) = path {
            builder = builder.add_source(config::File::new(path, config::FileFormat::Yaml));
        }
        let config = builder.build()?;
        let config = config.try_deserialize()?;
        Ok(config)
    }
}

/// The server configuration.
#[derive(Clone, Deserialize)]
pub struct ServerConfig {
    /// The endpoint to bind to.
    pub bind_endpoint: SocketAddr,
}

/// The secp256k1 private key to use.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateKeyConfig {
    /// The raw private key in hex.
    Hex(#[serde(with = "hex::serde")] [u8; 32]),

    /// The path to the private key.
    Path(PathBuf),
}

impl PrivateKeyConfig {
    /// Load a signer using this configuration.
    pub fn load_private_key(&self) -> anyhow::Result<[u8; 32]> {
        let bytes: [u8; 32] = match self {
            PrivateKeyConfig::Hex(hex_bytes) => hex_bytes
                .to_vec()
                .try_into()
                .map_err(|v: Vec<u8>| anyhow::anyhow!("Expected 32 bytes, got {}", v.len()))?,
            PrivateKeyConfig::Path(path_buf) => {
                let vec = fs::read(path_buf).context("failed to read private key from file")?;
                vec.try_into().map_err(|v: Vec<u8>| {
                    anyhow::anyhow!("Private key file must be exactly 32 bytes, got {}", v.len())
                })?
            }
        };
        Ok(bytes)
    }
}

/// The configuration for Prometheus metrics endpoint.
#[derive(Clone, Deserialize)]
pub struct MetricsConfig {
    /// The address to bind the Prometheus metrics endpoint to.
    pub bind_endpoint: SocketAddr,

    /// Whether the Prometheus metrics endpoint is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// OpenTelemetry configuration.
#[serde_as]
#[derive(Clone, Default, Deserialize)]
pub struct OtelConfig {
    /// Whether OpenTelemetry is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// The global OTLP gRPC endpoint URL (e.g., "http://localhost:4317").
    /// Can be overridden per-signal (e.g., `logs.endpoint`).
    #[serde(default = "default_otlp_endpoint")]
    pub endpoint: String,

    /// The service name for OTEL resource attributes.
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// The team responsible for the service.
    #[serde(default = "default_team_name")]
    pub team_name: String,

    /// The deployment environment (e.g., "local", "staging", "production").
    #[serde(default = "default_deployment_env")]
    pub deployment_env: String,

    /// Additional resource attributes as key-value pairs.
    #[serde(default)]
    pub resource_attributes: HashMap<String, String>,

    /// The batch export timeout.
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    #[serde(default = "default_export_timeout")]
    pub export_timeout: Duration,

    /// Log export configuration.
    #[serde(default)]
    pub logs: OtelLogsConfig,

    /// Trace export configuration.
    #[serde(default)]
    pub traces: OtelTracesConfig,
}

/// OpenTelemetry logs export configuration.
#[derive(Clone, Deserialize)]
pub struct OtelLogsConfig {
    /// Whether log export is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Optional endpoint override for log export.
    /// If not set, uses the global `otel.endpoint`.
    #[serde(default)]
    pub endpoint: Option<String>,
}

impl Default for OtelLogsConfig {
    fn default() -> Self {
        Self { enabled: true, endpoint: None }
    }
}

/// OpenTelemetry traces export configuration.
#[derive(Clone, Deserialize)]
pub struct OtelTracesConfig {
    /// Whether trace export is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Optional endpoint override for trace export.
    /// If not set, uses the global `otel.endpoint`.
    #[serde(default)]
    pub endpoint: Option<String>,
}

impl Default for OtelTracesConfig {
    fn default() -> Self {
        Self { enabled: true, endpoint: None }
    }
}

/// The payments configuration.
#[derive(Clone, Deserialize)]
pub struct PaymentsConfig {
    /// The Ethereum RPC URL to use.
    pub ethereum_rpc_url: String,

    /// The NIL ERC-20 token address.
    pub nil_token_address: String,

    /// The BurnWithDigest contract address.
    pub burn_contract_address: String,

    /// The Ethereum chain ID.
    pub chain_id: u64,

    /// The subscription configuration.
    pub subscriptions: SubscriptionConfig,

    /// The token price configuration.
    pub token_price: TokenPriceConfig,
}

/// The subscription configuration.
#[serde_as]
#[derive(Clone, Deserialize)]
pub struct SubscriptionConfig {
    /// The minimum time before expiration that a subscription can be renewed.
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    #[serde(rename = "renewal_threshold_seconds")]
    pub renewal_threshold: Duration,

    /// The length of a subscription.
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    #[serde(rename = "length_seconds")]
    pub length: Duration,

    /// The cost of each blind module, in dollars.
    pub dollar_cost: BlindModuleCosts,

    /// The allowed slippage in the payment, in the range 0-1.
    #[serde(default = "default_slippage")]
    pub payment_slippage: Decimal,
}

/// The costs of blind module subscriptions.
#[derive(Clone, Deserialize)]
pub struct BlindModuleCosts {
    /// The cost for a nildb subscription, in dollars.
    pub nildb: Decimal,

    /// The cost for a nilai subscription, in dollars.
    pub nilai: Decimal,
}

/// The token price configuration.
#[serde_as]
#[derive(Clone, Deserialize)]
pub struct TokenPriceConfig {
    /// The base url to use.
    #[serde(default = "default_token_price_base_url")]
    pub base_url: String,

    /// The API key for CoinGecko.
    pub api_key: String,

    /// The coin id to use when hitting the API.
    #[serde(default = "default_coin_id")]
    pub coin_id: String,

    /// The timeout for all token price requests made.
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    #[serde(default = "default_token_price_timeout")]
    pub request_timeout: Duration,
}

/// The postgres configuration.
#[derive(Clone, Deserialize)]
pub struct PostgresConfig {
    /// The connection string to use.
    pub url: String,
}

fn default_token_price_base_url() -> String {
    "https://pro-api.coingecko.com".into()
}

fn default_coin_id() -> String {
    "nillion".into()
}

fn default_token_price_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_slippage() -> Decimal {
    // 3%
    Decimal::new(3, 2)
}

fn default_otlp_endpoint() -> String {
    "http://localhost:4317".into()
}

fn default_service_name() -> String {
    "nilauth".into()
}

fn default_team_name() -> String {
    "nilauth".into()
}

fn default_deployment_env() -> String {
    "local".into()
}

fn default_true() -> bool {
    true
}

fn default_export_timeout() -> Duration {
    Duration::from_secs(30)
}
