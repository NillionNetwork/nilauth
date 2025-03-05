use anyhow::Context;
use nillion_nucs::k256::SecretKey;
use serde::Deserialize;
use std::{fs, net::SocketAddr, path::PathBuf};

/// The configuration for the authority service.
#[derive(Deserialize)]
pub struct Config {
    /// The server configuration.
    pub server: ServerConfig,

    /// The private key
    pub private_key: PrivateKeyConfig,

    /// Configuration for tokens.
    pub tokens: TokensConfig,
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

/// The configuration for minted tokens.
#[derive(Deserialize)]
pub struct TokensConfig {
    /// The token expiration in days.
    pub expiration_days: u64,
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
