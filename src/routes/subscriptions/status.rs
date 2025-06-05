use crate::db::subscriptions::BlindModule;
use crate::routes::Json;
use crate::{routes::RequestHandlerError, state::SharedState};
use axum::extract::Query;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use nillion_nucs::k256::PublicKey;
use serde::{Deserialize, Serialize};
use strum::EnumDiscriminants;
use tracing::error;

#[derive(Deserialize)]
pub(crate) struct Request {
    #[serde(with = "hex::serde")]
    pub(crate) public_key: [u8; 33],

    pub(crate) blind_module: BlindModule,
}

#[derive(Debug, Serialize)]
pub(crate) struct SubscriptionStatusResponse {
    subscribed: bool,
    details: Option<Subscription>,
}

#[derive(Debug, Serialize, PartialEq)]
pub(crate) struct Subscription {
    #[serde(with = "chrono::serde::ts_seconds")]
    expires_at: DateTime<Utc>,

    #[serde(with = "chrono::serde::ts_seconds")]
    renewable_at: DateTime<Utc>,
}

pub(crate) async fn handler(
    state: SharedState,
    request: Query<Request>,
) -> Result<Json<SubscriptionStatusResponse>, HandlerError> {
    let public_key = PublicKey::from_sec1_bytes(&request.public_key)
        .map_err(|_| HandlerError::InvalidPublicKey)?;
    let expires_at = state
        .databases
        .subscriptions
        .find_subscription_end(&public_key, &request.blind_module)
        .await
        .map_err(|e| {
            error!("Subscription lookup failed: {e}");
            HandlerError::Internal
        })?;
    let details = expires_at.map(|expires_at| Subscription {
        expires_at,
        renewable_at: expires_at - state.parameters.subscription_renewal_threshold,
    });
    let subscribed = expires_at
        .map(|e| e > state.services.time.current_time())
        .unwrap_or_default();
    Ok(Json(SubscriptionStatusResponse {
        subscribed,
        details,
    }))
}

#[derive(Debug, EnumDiscriminants)]
pub(crate) enum HandlerError {
    Internal,
    InvalidPublicKey,
}

impl IntoResponse for HandlerError {
    fn into_response(self) -> Response {
        let discriminant = HandlerErrorDiscriminants::from(&self);
        let (code, message) = match self {
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
            Self::InvalidPublicKey => (StatusCode::BAD_REQUEST, "invalid public key"),
        };
        let response = RequestHandlerError::new(message, format!("{discriminant:?}"));
        (code, Json(response)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{AppStateBuilder, PublicKeyExt};
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
        async fn invoke(
            self,
            request: Request,
        ) -> Result<SubscriptionStatusResponse, HandlerError> {
            let state = self.builder.build();
            let request = Query(request);
            handler(State(state), request).await.map(|r| r.0)
        }
    }

    #[tokio::test]
    async fn valid_request() {
        let mut handler = Handler::default();
        let key = SecretKey::random(&mut rand::thread_rng());
        let now = Utc::now();
        let timestamp = Utc::now();
        let blind_module = BlindModule::NilDb;
        handler
            .builder
            .time_service
            .expect_current_time()
            .returning(move || now);

        handler
            .builder
            .subscriptions_db
            .expect_find_subscription_end()
            .with(eq(key.public_key()), eq(blind_module))
            .return_once(move |_, _| Ok(Some(timestamp)));

        let renewal_threshold = Duration::from_secs(30);
        handler.builder.subscription_renewal_threshold = renewal_threshold;

        let request = Request {
            public_key: key.public_key().to_bytes(),
            blind_module,
        };
        let response = handler.invoke(request).await.expect("handler failed");
        assert!(response.subscribed);
        assert_eq!(
            response.details,
            Some(Subscription {
                expires_at: timestamp,
                renewable_at: timestamp - renewal_threshold
            })
        );
    }

    #[tokio::test]
    async fn expired_subscription() {
        let mut handler = Handler::default();
        let key = SecretKey::random(&mut rand::thread_rng());
        let now = Utc::now();
        let timestamp = now - Duration::from_secs(60);
        let blind_module = BlindModule::NilDb;
        handler
            .builder
            .time_service
            .expect_current_time()
            .returning(move || now);

        handler
            .builder
            .subscriptions_db
            .expect_find_subscription_end()
            .with(eq(key.public_key()), eq(blind_module))
            .return_once(move |_, _| Ok(Some(timestamp)));

        let request = Request {
            public_key: key.public_key().to_bytes(),
            blind_module,
        };
        let response = handler.invoke(request).await.expect("handler failed");
        assert!(!response.subscribed);
        response
            .details
            .expect("subscription should still be returned");
    }
}
