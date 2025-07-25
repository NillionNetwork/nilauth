use crate::{
    db::{revocations::RevocationDb, subscriptions::SubscriptionDb},
    services::subscription_cost::SubscriptionCostService,
    time::TimeService,
};
use axum::extract::State;
use chrono::{DateTime, Utc};
use nilauth_client::nilchain_client::tx::PaymentTransactionRetriever;
use nillion_nucs::k256::SecretKey;
use rust_decimal::Decimal;
use std::{sync::Arc, time::Duration};

pub(crate) type SharedState = State<Arc<AppState>>;

/// Services used by the application.
pub struct Services {
    /// A service to retrieve transactions.
    pub tx: Box<dyn PaymentTransactionRetriever>,

    /// A service that provides the current time.
    pub time: Box<dyn TimeService>,

    /// A service to compute a subscription's cost.
    pub subscription_cost: Box<dyn SubscriptionCostService>,
}

/// Database interfaces used by the application.
pub struct Databases {
    /// The subscriptions database.
    pub subscriptions: Box<dyn SubscriptionDb>,

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

    /// The allowed slippage in the range 0-1.
    pub subscription_cost_slippage: Decimal,

    /// The threshold at which a subscription can be renewd.
    pub subscription_renewal_threshold: Duration,
}
