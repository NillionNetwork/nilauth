use crate::state::AppState;
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;

pub(crate) mod about;
pub(crate) mod nucs;

pub fn build_router(state: AppState) -> Router {
    let state = Arc::new(state);
    Router::new()
        .route("/about", get(about::handler))
        .route("/api/v1/nucs/create", post(nucs::create::handler))
        .with_state(state)
}
