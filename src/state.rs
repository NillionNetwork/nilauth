use crate::{db::account::AccountDb, time::TimeService};
use axum::extract::State;
use chrono::{DateTime, Utc};
use nillion_chain_client::tx::PaymentTransactionRetriever;
use nillion_nucs::k256::SecretKey;
use std::sync::Arc;

pub(crate) type SharedState = State<Arc<AppState>>;

/// Services used by the application.
pub struct Services {
    /// A service to retrieve transactions.
    pub tx: Box<dyn PaymentTransactionRetriever>,

    /// A service that provides the current time.
    pub time: Box<dyn TimeService>,
}

/// Database interfaces used by the application.
pub struct Databases {
    /// The account database.
    pub accounts: Box<dyn AccountDb>,
}

/// The state to be shared across all routes.
pub struct AppState {
    /// The server's secret key.
    pub secret_key: SecretKey,

    /// The services the application uses.
    pub services: Services,

    /// The database interfaces the application uses.
    pub databases: Databases,

    /// The timestamp at which nilauth was started.
    pub started_at: DateTime<Utc>,
}
