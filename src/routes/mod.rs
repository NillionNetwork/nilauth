use crate::state::AppState;
use axum::{
    extract::{rejection::JsonRejection, FromRequest, Request},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde::Serialize;
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
                .route("/payments/validate", post(payments::validate::handler))
                .route("/payments/cost", get(payments::cost::handler)),
        )
        .with_state(state)
}

/// An error when handling a request.
#[derive(Debug, Serialize)]
pub struct RequestHandlerError {
    pub(crate) message: String,
}

/// A type that behaves like `axum::Json` but provides JSON structured errors when parsing fails.
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
                // Construct a JSON error.
                let payload = RequestHandlerError {
                    message: rejection.body_text(),
                };

                Err((rejection.status(), axum::Json(payload)))
            }
        }
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
