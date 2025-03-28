use crate::{
    db::{account::AccountDb, revocations::RevocationDb},
    services::prices::TokenPriceService,
    time::TimeService,
};
use axum::extract::State;
use chrono::{DateTime, Utc};
use nillion_chain_client::tx::PaymentTransactionRetriever;
use nillion_nucs::k256::SecretKey;
use rust_decimal::Decimal;
use std::sync::Arc;

pub(crate) type SharedState = State<Arc<AppState>>;

/// Services used by the application.
pub struct Services {
    /// A service to retrieve transactions.
    pub tx: Box<dyn PaymentTransactionRetriever>,

    /// A service that provides the current time.
    pub time: Box<dyn TimeService>,

    /// A service that gets the current token price.
    pub prices: Box<dyn TokenPriceService>,
}

/// Database interfaces used by the application.
pub struct Databases {
    /// The account database.
    pub accounts: Box<dyn AccountDb>,

    /// The revocations database.
    pub revocations: Arc<dyn RevocationDb>,
}

/// The state to be shared across all routes.
pub struct AppState {
    /// The services the application uses.
    pub services: Services,

    /// The database interfaces the application uses.
    pub databases: Databases,

    /// The parameters for this service.
    pub parameters: Parameters,
}

pub struct Parameters {
    /// The server's secret key.
    pub secret_key: SecretKey,

    /// The timestamp at which nilauth was started.
    pub started_at: DateTime<Utc>,

    /// Subscription cost, in dollars.
    pub subscription_cost: Decimal,

    /// The allowed slippage in the range 0-1.
    pub subscription_cost_slippage: Decimal,
}
