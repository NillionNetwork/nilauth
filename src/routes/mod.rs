use crate::state::AppState;
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;

pub(crate) mod about;
pub(crate) mod nucs;
pub(crate) mod payments;

pub fn build_router(state: AppState) -> Router {
    let state = Arc::new(state);
    Router::new()
        .route("/about", get(about::handler))
        .nest(
            "/api/v1/",
            Router::new()
                .route("/nucs/create", post(nucs::create::handler))
                .route("/payments/validate", post(payments::validate::handler)),
        )
        .with_state(state)
}
