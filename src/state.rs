use axum::extract::State;
use nillion_chain_client::tx::PaymentTransactionRetriever;
use nillion_nucs::k256::SecretKey;
use std::{sync::Arc, time::Duration};

pub(crate) type SharedState = State<Arc<AppState>>;

/// Services used by the application.
pub struct Services {
    /// A service to retrieve transactions.
    pub tx: Box<dyn PaymentTransactionRetriever>,
}

/// The state to be shared across all routes.
pub struct AppState {
    /// The server's secret key.
    pub secret_key: SecretKey,

    /// The expiration time for tokens.
    pub token_expiration: Duration,

    pub services: Services,
}
