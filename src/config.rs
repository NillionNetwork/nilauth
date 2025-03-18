use anyhow::Context;
use nillion_nucs::k256::SecretKey;
use serde::Deserialize;
use serde_with::serde_as;
use std::{fs, net::SocketAddr, path::PathBuf, time::Duration};

/// The configuration for the authority service.
#[derive(Deserialize)]
pub struct Config {
    /// The server configuration.
    pub server: ServerConfig,

    /// The private key
    pub private_key: PrivateKeyConfig,

    /// Configuration for tokens.
    pub tokens: TokensConfig,

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
            .add_source(config::Environment::with_prefix("AUTHORITY").separator("__"));
        if let Some(path) = path {
            builder = builder.add_source(config::File::new(path, config::FileFormat::Yaml));
        }
        let config = builder.build()?;
        let config = config.try_deserialize()?;
        Ok(config)
    }
}

/// The server configuration.
#[derive(Deserialize)]
pub struct ServerConfig {
    /// The endpoint to bind to.
    pub bind_endpoint: SocketAddr,
}

/// The secp256k1 private key to use.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateKeyConfig {
    /// The raw private key in hex.
    Hex(#[serde(deserialize_with = "hex::serde::deserialize")] [u8; 32]),

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

/// The configuration for minted tokens.
#[derive(Deserialize)]
pub struct TokensConfig {
    /// The token expiration in seconds.
    #[serde(rename = "expiration_seconds")]
    pub expiration: u64,
}

/// The configuration for metrics.
#[derive(Deserialize)]
pub struct MetricsConfig {
    /// The address to bind to.
    pub bind_endpoint: SocketAddr,
}

/// The payments configuration.
#[derive(Deserialize)]
pub struct PaymentsConfig {
    /// The nilchain RPC URL to use.
    pub nilchain_url: String,

    /// The subscription configuration.
    pub subscriptions: SubscriptionConfig,
}

/// The subscription configuration.
#[serde_as]
#[derive(Deserialize)]
pub struct SubscriptionConfig {
    /// The minimum time needed for a subscription to be renewed.
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    #[serde(rename = "renewal_threshold_seconds")]
    pub renewal_threshold: Duration,

    /// The length of a subscription.
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    #[serde(rename = "length_seconds")]
    pub length: Duration,
}

/// The postgres configuration.
#[derive(Deserialize)]
pub struct PostgresConfig {
    /// The connection string to use.
    pub url: String,
}
