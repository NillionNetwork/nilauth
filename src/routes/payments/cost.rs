use crate::db::subscriptions::BlindModule;
use crate::routes::RequestHandlerError;
use crate::{routes::Json, state::SharedState};
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use strum::EnumDiscriminants;

#[derive(Serialize)]
pub(crate) struct GetCostResponse {
    /// The cost in unils.
    pub(crate) cost_unils: u64,
}

#[derive(Deserialize)]
pub(crate) struct RequestQuery {
    blind_module: BlindModule,
}

pub(crate) async fn handler(
    path: Query<RequestQuery>,
    state: SharedState,
) -> Result<Json<GetCostResponse>, HandlerError> {
    let result = state
        .services
        .subscription_cost
        .blind_module_cost(path.blind_module)
        .await;
    match result {
        Ok(cost) => Ok(Json(GetCostResponse { cost_unils: cost })),
        Err(_) => Err(HandlerError::Internal),
    }
}

#[derive(Debug, EnumDiscriminants)]
pub(crate) enum HandlerError {
    Internal,
}

impl IntoResponse for HandlerError {
    fn into_response(self) -> Response {
        let discriminant = HandlerErrorDiscriminants::from(&self);
        let (code, message) = match self {
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        };
        let response = RequestHandlerError::new(message, format!("{discriminant:?}"));
        (code, Json(response)).into_response()
    }
}
