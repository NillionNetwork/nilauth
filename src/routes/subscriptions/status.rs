use crate::routes::Json;
use crate::signed::{SignedRequest, VerificationError};
use crate::{routes::RequestHandlerError, state::SharedState};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum::EnumDiscriminants;
use tracing::error;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    #[allow(dead_code)]
    #[serde(with = "hex::serde")]
    nonce: [u8; 16],

    #[serde(with = "chrono::serde::ts_seconds")]
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SubscriptionStatusResponse {
    subscribed: bool,
    subscription: Option<Subscription>,
}

#[derive(Debug, Serialize, PartialEq)]
pub(crate) struct Subscription {
    #[serde(with = "chrono::serde::ts_seconds")]
    expires_at: DateTime<Utc>,
}

pub(crate) async fn handler(
    state: SharedState,
    Json(request): Json<SignedRequest>,
) -> Result<Json<SubscriptionStatusResponse>, HandlerError> {
    let decoded_payload: Payload = serde_json::from_slice(&request.payload)
        .map_err(|e| HandlerError::MalformedPayload(e.to_string()))?;
    if decoded_payload.expires_at <= state.services.time.current_time() {
        return Err(HandlerError::PayloadExpired);
    }
    let public_key = request.verify()?;
    let expires_at = state
        .databases
        .accounts
        .find_subscription_end(&public_key)
        .await
        .map_err(|e| {
            error!("Subscription lookup failed: {e}");
            HandlerError::Internal
        })?;
    let subscription = expires_at.map(|expires_at| Subscription { expires_at });
    let subscribed = subscription.is_some();
    Ok(Json(SubscriptionStatusResponse {
        subscribed,
        subscription,
    }))
}

#[derive(Debug, EnumDiscriminants)]
pub(crate) enum HandlerError {
    Internal,
    InvalidPublicKey,
    InvalidSignature,
    MalformedPayload(String),
    PayloadExpired,
    SignatureVerification,
}

impl From<VerificationError> for HandlerError {
    fn from(e: VerificationError) -> Self {
        match e {
            VerificationError::InvalidPublicKey => Self::InvalidPublicKey,
            VerificationError::InvalidSignature => Self::InvalidSignature,
            VerificationError::SignatureVerification => Self::SignatureVerification,
        }
    }
}

impl IntoResponse for HandlerError {
    fn into_response(self) -> Response {
        let discriminant = HandlerErrorDiscriminants::from(&self);
        let (code, message) = match self {
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into()),
            Self::InvalidPublicKey => (StatusCode::BAD_REQUEST, "invalid public key".into()),
            Self::InvalidSignature => (StatusCode::BAD_REQUEST, "invalid signature".into()),
            Self::MalformedPayload(reason) => (
                StatusCode::BAD_REQUEST,
                format!("malformed payload: {reason}"),
            ),
            Self::PayloadExpired => (StatusCode::BAD_REQUEST, "payload expired".into()),
            Self::SignatureVerification => (
                StatusCode::BAD_REQUEST,
                "signature verification failed".into(),
            ),
        };
        let response = RequestHandlerError::new(message, format!("{discriminant:?}"));
        (code, Json(response)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::extract::State;
    use mockall::predicate::eq;
    use nillion_nucs::k256::SecretKey;

    use super::*;
    use crate::tests::AppStateBuilder;
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
            request: SignedRequest,
        ) -> Result<SubscriptionStatusResponse, HandlerError> {
            let state = self.builder.build();
            let request = Json(request);
            handler(State(state), request).await.map(|r| r.0)
        }
    }

    #[tokio::test]
    async fn valid_request() {
        let mut handler = Handler::default();
        let key = SecretKey::random(&mut rand::thread_rng());
        let now = Utc::now();
        let timestamp = Utc::now();
        handler
            .builder
            .time_service
            .expect_current_time()
            .returning(move || now);

        handler
            .builder
            .account_db
            .expect_find_subscription_end()
            .with(eq(key.public_key()))
            .return_once(move |_| Ok(Some(timestamp)));

        let payload = Payload {
            nonce: rand::random(),
            expires_at: now + Duration::from_secs(60),
        };
        let request = SignedRequest::new(&key, &payload);
        let response = handler.invoke(request).await.expect("handler failed");
        assert!(response.subscribed);
        assert_eq!(
            response.subscription,
            Some(Subscription {
                expires_at: timestamp
            })
        );
    }

    #[tokio::test]
    async fn request_expired() {
        let mut handler = Handler::default();
        let key = SecretKey::random(&mut rand::thread_rng());
        let now = Utc::now();
        handler
            .builder
            .time_service
            .expect_current_time()
            .returning(move || now);

        let payload = Payload {
            nonce: rand::random(),
            expires_at: now - Duration::from_secs(60),
        };
        let request = SignedRequest::new(&key, &payload);
        let err = handler.invoke(request).await.expect_err("handler failed");
        assert!(matches!(err, HandlerError::PayloadExpired));
    }
}
