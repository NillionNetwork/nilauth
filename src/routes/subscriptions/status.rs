use crate::db::subscriptions::BlindModule;
use crate::routes::Json;
use crate::{routes::RequestHandlerError, state::SharedState};
use axum::extract::Query;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use nillion_nucs::did::Did;
use serde::{Deserialize, Serialize};
use strum::EnumDiscriminants;
use tracing::error;
use utoipa::{IntoParams, ToSchema};

/// A request to get a subscription's status.
#[derive(Deserialize, IntoParams)]
pub(crate) struct SubscriptionStatusArgs {
    /// The Did to check the subscription for.
    #[param(value_type = String, example = "did:key:zQ3sh...")]
    did: Did,

    /// The blind module to check the subscription for.
    #[param(value_type = String, example = crate::docs::blind_module)]
    blind_module: BlindModule,
}

/// The response to a request to get a subscription's status.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SubscriptionStatusResponse {
    /// Whether the user is actively subscribed.
    subscribed: bool,

    /// The subscription details.
    details: Option<Subscription>,
}

/// A blind module subscription.
#[derive(Debug, Serialize, PartialEq, ToSchema)]
pub(crate) struct Subscription {
    /// The timestamp at which this subscription expires.
    #[serde(with = "chrono::serde::ts_seconds")]
    #[schema(value_type = u64, examples(crate::docs::epoch_timestamp))]
    expires_at: DateTime<Utc>,

    /// The timestamp at which this subscription can be renewed.
    ///
    /// Attempting to renew a subscription before this timestamp will fail.
    #[serde(with = "chrono::serde::ts_seconds")]
    #[schema(value_type = u64, examples(crate::docs::epoch_timestamp))]
    renewable_at: DateTime<Utc>,
}

//// Get a subscription's status.
#[utoipa::path(
    get,
    path = "/subscriptions/status",
    params(SubscriptionStatusArgs),
    responses(
        (status = OK, body = Subscription, description = "The details about the subscription associated with the input public key"),
        (status = 400, body = RequestHandlerError),
    )
)]
pub(crate) async fn handler(
    state: SharedState,
    request: Query<SubscriptionStatusArgs>,
) -> Result<Json<SubscriptionStatusResponse>, HandlerError> {
    let expires_at =
        state.databases.subscriptions.find_subscription_end(&request.did, &request.blind_module).await.map_err(
            |e| {
                error!("Subscription lookup failed: {e}");
                HandlerError::Internal
            },
        )?;
    let details = expires_at.map(|expires_at| Subscription {
        expires_at,
        renewable_at: expires_at - state.parameters.subscription_renewal_threshold,
    });
    let subscribed = expires_at.map(|e| e > state.services.time.current_time()).unwrap_or_default();
    Ok(Json(SubscriptionStatusResponse { subscribed, details }))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::AppStateBuilder;
    use axum::extract::State;
    use mockall::predicate::eq;
    use nillion_nucs::k256::SecretKey;
    use std::time::Duration;

    struct Handler {
        builder: AppStateBuilder,
    }

    impl Default for Handler {
        fn default() -> Self {
            let builder = AppStateBuilder::default();
            Self { builder }
        }
    }

    impl Handler {
        async fn invoke(self, request: SubscriptionStatusArgs) -> Result<SubscriptionStatusResponse, HandlerError> {
            let state = self.builder.build();
            let request = Query(request);
            handler(State(state), request).await.map(|r| r.0)
        }
    }

    #[tokio::test]
    async fn valid_request() {
        let mut handler = Handler::default();
        let key = SecretKey::random(&mut rand::thread_rng());
        let public_key_bytes: [u8; 33] = key.public_key().to_sec1_bytes().as_ref().try_into().unwrap();
        let subscriber_did = Did::key(public_key_bytes);
        let now = Utc::now();
        let timestamp = now + Duration::from_secs(120);
        let blind_module = BlindModule::NilDb;
        handler.builder.time_service.expect_current_time().returning(move || now);

        handler
            .builder
            .subscriptions_db
            .expect_find_subscription_end()
            .with(eq(subscriber_did), eq(blind_module))
            .return_once(move |_, _| Ok(Some(timestamp)));

        let renewal_threshold = Duration::from_secs(30);
        handler.builder.subscription_renewal_threshold = renewal_threshold;

        let request = SubscriptionStatusArgs { did: subscriber_did, blind_module };
        let response = handler.invoke(request).await.expect("handler failed");
        assert!(response.subscribed);
        assert_eq!(
            response.details,
            Some(Subscription { expires_at: timestamp, renewable_at: timestamp - renewal_threshold })
        );
    }

    #[tokio::test]
    async fn expired_subscription() {
        let mut handler = Handler::default();
        let key = SecretKey::random(&mut rand::thread_rng());
        let public_key_bytes: [u8; 33] = key.public_key().to_sec1_bytes().as_ref().try_into().unwrap();
        let subscriber_did = Did::key(public_key_bytes);
        let now = Utc::now();
        let timestamp = now - Duration::from_secs(60);
        let blind_module = BlindModule::NilDb;
        handler.builder.time_service.expect_current_time().returning(move || now);

        handler
            .builder
            .subscriptions_db
            .expect_find_subscription_end()
            .with(eq(subscriber_did), eq(blind_module))
            .return_once(move |_, _| Ok(Some(timestamp)));

        let request = SubscriptionStatusArgs { did: subscriber_did, blind_module };
        let response = handler.invoke(request).await.expect("handler failed");
        assert!(!response.subscribed);
        response.details.expect("subscription should still be returned");
    }
}
