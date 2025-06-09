use anyhow::Context;
use nillion_nucs::k256::SecretKey;
use rust_decimal::Decimal;
use serde::Deserialize;
use serde_with::serde_as;
use std::{fs, net::SocketAddr, path::PathBuf, time::Duration};

/// The configuration for the authority service.
#[derive(Clone, Deserialize)]
pub struct Config {
    /// The server configuration.
    pub server: ServerConfig,

    /// The private key
    pub private_key: PrivateKeyConfig,

    /// Configuration for metrics.
    pub metrics: MetricsConfig,

    /// The payments configuration.
    pub payments: PaymentsConfig,

    /// The postgres configuration.
    pub postgres: PostgresConfig,
}

impl Config {
    pub fn load(path: Option<&str>) -> anyhow::Result<Self> {
        let mut builder = config::Config::builder()
            .add_source(config::Environment::with_prefix("NILAUTH").separator("__"));
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
    /// Load a key using this configuration.
    pub fn load_key(&self) -> anyhow::Result<SecretKey> {
        let bytes = match self {
            PrivateKeyConfig::Hex(bytes) => bytes.to_vec(),
            PrivateKeyConfig::Path(path_buf) => {
                fs::read(path_buf).context("failed to read private key from file")?
            }
        };
        let private_key = SecretKey::from_slice(&bytes).context("invalid private key")?;
        Ok(private_key)
    }
}

/// The configuration for metrics.
#[derive(Clone, Deserialize)]
pub struct MetricsConfig {
    /// The address to bind to.
    pub bind_endpoint: SocketAddr,
}

/// The payments configuration.
#[derive(Clone, Deserialize)]
pub struct PaymentsConfig {
    /// The nilchain RPC URL to use.
    pub nilchain_url: String,

    /// The subscription configuration.
    pub subscriptions: SubscriptionConfig,

    /// The token price configuration.
    pub token_price: TokenPriceConfig,
}

/// The subscription configuration.
#[serde_as]
#[derive(Clone, Deserialize)]
pub struct SubscriptionConfig {
    /// The minimum time needed for a subscription to be renewed.
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
    "https://pro-api.coingecko.com/".into()
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
