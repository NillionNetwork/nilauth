use axum::extract::State;
use nillion_nucs::k256::SecretKey;
use std::sync::Arc;

pub(crate) type SharedState = State<Arc<AppState>>;

/// The state to be shared across all routes.
pub struct AppState {
    /// The server's secret key.
    pub secret_key: SecretKey,
}
