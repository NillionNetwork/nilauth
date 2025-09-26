use crate::db::subscriptions::BlindModule;
use crate::routes::RequestHandlerError;
use crate::{routes::Json, state::SharedState};
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use strum::EnumDiscriminants;
use utoipa::{IntoParams, ToSchema};

/// A request to get the cost for a subscription.
#[derive(Deserialize, IntoParams)]
pub(crate) struct GetCostArgs {
    /// The blind module to get the cost for.
    #[param(value_type = String, example = crate::docs::blind_module)]
    blind_module: BlindModule,
}

/// The response to a request to get a subscription cost.
#[derive(Serialize, ToSchema)]
pub(crate) struct GetCostResponse {
    /// The cost in unils.
    #[schema(examples(1_000))]
    cost_unils: u64,
}

/// Get the cost of a nilauth subscription.
#[utoipa::path(
    get,
    path = "/payments/cost",
    params(GetCostArgs),
    responses((status = OK, body = GetCostResponse))
)]
pub(crate) async fn handler(
    path: Query<GetCostArgs>,
    state: SharedState,
) -> Result<Json<GetCostResponse>, HandlerError> {
    let result = state.services.subscription_cost.blind_module_cost(path.blind_module).await;
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
