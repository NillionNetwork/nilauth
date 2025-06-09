use crate::{auth::TokenValidatorState, state::AppState};
use axum::{
    extract::{rejection::JsonRejection, FromRequest, Request},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Extension, Router,
};
use convert_case::{Case, Casing};
use nillion_nucs::{token::Did, validator::NucValidator};
use serde::Serialize;
use std::{ops::Deref, sync::Arc};

pub(crate) mod about;
pub(crate) mod health;
pub(crate) mod nucs;
pub(crate) mod payments;
pub(crate) mod revocations;
pub(crate) mod subscriptions;

pub fn build_router(state: AppState) -> Router {
    let state = Arc::new(state);
    let public_key = state.parameters.secret_key.public_key();
    let validator = NucValidator::new(&[public_key]);
    // SAFETY: the key size is guaranteed to be correct.
    let nilauth_did = Did::new(
        public_key
            .to_sec1_bytes()
            .as_ref()
            .try_into()
            .expect("invalid public key size"),
    );
    let validator_state = TokenValidatorState::new(validator, nilauth_did);
    Router::new()
        .route("/about", get(about::handler))
        .route("/health", get(health::handler))
        .nest(
            "/api/v1/",
            Router::new()
                .route("/nucs/create", post(nucs::create::handler))
                .route("/payments/validate", post(payments::validate::handler))
                .route("/payments/cost", get(payments::cost::handler))
                .route("/revocations/revoke", post(revocations::revoke::handler))
                .route("/revocations/lookup", post(revocations::lookup::handler))
                .route("/subscriptions/status", get(subscriptions::status::handler)),
        )
        .with_state(state)
        .layer(Extension(validator_state))
}

/// An error when handling a request.
#[derive(Debug, Serialize)]
pub struct RequestHandlerError {
    pub(crate) message: String,
    pub(crate) error_code: String,
}

impl RequestHandlerError {
    pub(crate) fn new(message: impl Into<String>, error_code: impl AsRef<str>) -> Self {
        let error_code = error_code.as_ref().to_case(Case::UpperSnake);
        Self {
            message: message.into(),
            error_code,
        }
    }
}

/// A type that behaves like `axum::Json` but provides JSON structured errors when parsing fails.
#[derive(Debug)]
pub struct Json<T>(pub T);

impl<S, T> FromRequest<S> for Json<T>
where
    axum::Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, axum::Json<RequestHandlerError>);

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let req = Request::from_parts(parts, body);

        match axum::Json::<T>::from_request(req, state).await {
            Ok(value) => Ok(Self(value.0)),
            Err(rejection) => {
                let payload = RequestHandlerError::new(rejection.body_text(), "MALFORMED_REQUEST");

                Err((rejection.status(), axum::Json(payload)))
            }
        }
    }
}

impl<T> Deref for Json<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> IntoResponse for Json<T>
where
    T: Serialize,
{
    fn into_response(self) -> axum::response::Response {
        axum::Json(self.0).into_response()
    }
}
