use crate::routes::RequestHandlerError;
use crate::{routes::Json, state::SharedState};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use rust_decimal::Decimal;
use serde::Serialize;
use tracing::error;

pub(crate) static UNIL_IN_NIL: u64 = 1_000_000;

#[derive(Serialize)]
pub(crate) struct GetCostResponse {
    // The cost in unils.
    pub(crate) cost_unils: u64,
}

pub(crate) async fn handler(state: SharedState) -> Result<Json<GetCostResponse>, HandlerError> {
    match state.services.prices.nil_token_price().await {
        Ok(token_price) => {
            let cost = state.parameters.subscription_cost / token_price;
            let cost = cost * Decimal::from(UNIL_IN_NIL);
            let cost = cost.try_into().map_err(|_| {
                error!("Overflow when converting subscription price");
                HandlerError::Internal
            })?;
            Ok(Json(GetCostResponse { cost_unils: cost }))
        }

        Err(e) => {
            error!("Failed to get token price: {e}");
            Err(HandlerError::Internal)
        }
    }
}

#[derive(Debug)]
pub(crate) enum HandlerError {
    Internal,
}

impl IntoResponse for HandlerError {
    fn into_response(self) -> Response {
        let (code, message) = match self {
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into()),
        };
        let response = RequestHandlerError { message };
        (code, Json(response)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::extract::State;

    use super::*;
    use crate::tests::AppStateBuilder;

    #[tokio::test]
    async fn cost() {
        let state = AppStateBuilder::default()
            .with_expectations(|builder| {
                builder.subscription_cost = 100.into();
                builder
                    .token_price_service
                    .expect_nil_token_price()
                    .return_once(move || Ok(50.into()));
            })
            .build();
        let response = handler(State(state)).await.expect("request failed").0;
        // Subscription is $100, token is $50 => we need 2_000_000 unils to cover it.
        assert_eq!(response.cost_unils, 2_000_000);
    }
}
