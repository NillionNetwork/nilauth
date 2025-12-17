//! Ethereum RPC client for querying BurnWithDigest contract events.

use alloy::{
    network::Ethereum,
    primitives::{Address, B256, U256, keccak256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{Filter, Log},
    sol,
};
use async_trait::async_trait;
use std::str::FromStr;
use thiserror::Error;
use tracing::debug;

// Define the contract ABI using Alloy's sol! macro
sol! {
    #[sol(rpc)]
    contract BurnWithDigest {
        event LogBurnWithDigest(
            address indexed payer,
            uint256 amount,
            bytes32 indexed digest,
            uint256 timestamp
        );
    }
}

/// A log event from the BurnWithDigest contract.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BurnWithDigestEvent {
    /// The address that paid (payer).
    pub payer: Address,
    /// The amount burned in wei.
    pub amount: U256,
    /// The payment digest (keccak256 hash of canonical JSON).
    pub digest: B256,
    /// The block timestamp.
    pub timestamp: U256,
    /// The transaction hash.
    pub tx_hash: B256,
    /// The block number.
    pub block_number: u64,
    /// The log index within the block.
    pub log_index: u64,
    /// The chain ID.
    pub chain_id: u64,
}

/// Errors that can occur when interacting with the Ethereum RPC.
#[derive(Debug, Error)]
pub enum EthereumRpcError {
    #[error("RPC request failed: {0}")]
    RpcError(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Event not found for transaction hash: {0}")]
    EventNotFound(String),

    #[error("Invalid log data: {0}")]
    InvalidLogData(String),

    #[error("Chain ID mismatch: RPC node returned {node}, but config specifies {config}")]
    ChainIdMismatch { node: u64, config: u64 },
}

/// Trait for retrieving BurnWithDigest events from Ethereum.
#[async_trait]
pub trait BurnWithDigestEventRetriever: Send + Sync {
    /// Get a BurnWithDigest event by transaction hash.
    async fn get_event_by_tx_hash(&self, tx_hash: &str) -> Result<BurnWithDigestEvent, EthereumRpcError>;
}

/// Production implementation of BurnWithDigestEventRetriever using Alloy.
pub struct AlloyBurnWithDigestEventRetriever {
    provider: Box<dyn Provider<Ethereum>>,
    contract_address: Address,
    chain_id: u64,
}

impl AlloyBurnWithDigestEventRetriever {
    /// Create a new Alloy-based event retriever.
    ///
    /// This constructor verifies that the RPC node's chain ID matches the configured
    /// chain ID to prevent configuration errors (e.g., connecting to testnet while
    /// configured for mainnet).
    pub async fn new(rpc_url: &str, contract_address: &str, chain_id: u64) -> Result<Self, EthereumRpcError> {
        let url = rpc_url.parse().map_err(|e| EthereumRpcError::RpcError(format!("Invalid RPC URL: {}", e)))?;

        let provider = ProviderBuilder::new().network::<Ethereum>().connect_http(url);

        let node_chain_id = provider
            .get_chain_id()
            .await
            .map_err(|e| EthereumRpcError::RpcError(format!("Failed to get chain ID from RPC node: {}", e)))?;

        if node_chain_id != chain_id {
            return Err(EthereumRpcError::ChainIdMismatch { node: node_chain_id, config: chain_id });
        }

        let contract_address =
            Address::from_str(contract_address).map_err(|e| EthereumRpcError::InvalidAddress(e.to_string()))?;

        Ok(Self { provider: Box::new(provider), contract_address, chain_id })
    }

    /// Parse a LogBurnWithDigest event from a raw log.
    fn parse_log(&self, log: Log) -> Result<BurnWithDigestEvent, EthereumRpcError> {
        // Event signature: LogBurnWithDigest(address indexed payer, uint256 amount, bytes32 indexed digest, uint256 timestamp)
        // topics[0] = event signature hash
        // topics[1] = payer (indexed)
        // topics[2] = digest (indexed)
        // data = abi.encode(amount, timestamp)

        if log.topics().len() != 3 {
            return Err(EthereumRpcError::InvalidLogData(format!("Expected 3 topics, got {}", log.topics().len())));
        }

        let payer_bytes = log.topics()[1].as_slice();
        let payer = Address::from_slice(&payer_bytes[12..]); // Last 20 bytes

        let digest = log.topics()[2];

        // Decode data: (uint256 amount, uint256 timestamp)
        let data = log.data().data.as_ref();
        if data.len() != 64 {
            return Err(EthereumRpcError::InvalidLogData(format!("Expected 64 bytes of data, got {}", data.len())));
        }

        let amount = U256::from_be_slice(&data[0..32]);
        let timestamp = U256::from_be_slice(&data[32..64]);

        let tx_hash = log
            .transaction_hash
            .ok_or_else(|| EthereumRpcError::InvalidLogData("Log missing transaction hash".to_string()))?;

        let block_number =
            log.block_number.ok_or_else(|| EthereumRpcError::InvalidLogData("Log missing block number".to_string()))?;

        let log_index =
            log.log_index.ok_or_else(|| EthereumRpcError::InvalidLogData("Log missing log index".to_string()))?;

        Ok(BurnWithDigestEvent {
            payer,
            amount,
            digest,
            timestamp,
            tx_hash,
            block_number,
            log_index,
            chain_id: self.chain_id,
        })
    }
}

#[async_trait]
impl BurnWithDigestEventRetriever for AlloyBurnWithDigestEventRetriever {
    async fn get_event_by_tx_hash(&self, tx_hash: &str) -> Result<BurnWithDigestEvent, EthereumRpcError> {
        debug!("Querying Ethereum for transaction: {}", tx_hash);

        // Parse transaction hash
        let tx_hash_b256 =
            B256::from_str(tx_hash).map_err(|e| EthereumRpcError::InvalidAddress(format!("Invalid tx hash: {}", e)))?;

        // Get transaction receipt to find the block number
        let receipt = self
            .provider
            .get_transaction_receipt(tx_hash_b256)
            .await
            .map_err(|e| EthereumRpcError::RpcError(format!("Failed to fetch transaction receipt: {}", e)))?
            .ok_or_else(|| EthereumRpcError::EventNotFound(tx_hash.to_string()))?;

        let block_number = receipt
            .block_number
            .ok_or_else(|| EthereumRpcError::InvalidLogData("Receipt missing block number".to_string()))?;

        // Compute event signature: keccak256("LogBurnWithDigest(address,uint256,bytes32,uint256)")
        let event_signature = keccak256("LogBurnWithDigest(address,uint256,bytes32,uint256)");

        // Query logs for this specific transaction
        let filter = Filter::new()
            .address(self.contract_address)
            .event_signature(event_signature)
            .from_block(block_number)
            .to_block(block_number);

        let logs = self
            .provider
            .get_logs(&filter)
            .await
            .map_err(|e| EthereumRpcError::RpcError(format!("Failed to fetch logs: {}", e)))?;

        // Find the log matching our transaction hash
        let matching_log = logs
            .into_iter()
            .find(|log| log.transaction_hash == Some(tx_hash_b256))
            .ok_or_else(|| EthereumRpcError::EventNotFound(tx_hash.to_string()))?;

        self.parse_log(matching_log)
    }
}
