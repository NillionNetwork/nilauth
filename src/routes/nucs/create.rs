use crate::routes::Json;
use crate::{routes::RequestHandlerError, state::SharedState};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use nillion_nucs::k256::{
    ecdsa::{signature::Verifier, Signature},
    PublicKey,
};
use nillion_nucs::{builder::NucTokenBuilder, k256::ecdsa::VerifyingKey, token::Did};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

#[derive(Deserialize)]
pub(crate) struct CreateNucRequest {
    #[serde(deserialize_with = "hex::serde::deserialize")]
    public_key: [u8; 33],

    #[serde(deserialize_with = "hex::serde::deserialize")]
    signature: [u8; 64],

    #[serde(deserialize_with = "hex::serde::deserialize")]
    payload: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignablePayload {
    // A nonce, to add entropy.
    #[allow(dead_code)]
    #[serde(
        serialize_with = "hex::serde::serialize",
        deserialize_with = "hex::serde::deserialize"
    )]
    nonce: [u8; 16],

    // When this payload is no longer considered valid, to prevent reusing this forever if it
    // leaks.
    #[serde(
        deserialize_with = "chrono::serde::ts_seconds::deserialize",
        serialize_with = "chrono::serde::ts_seconds::serialize"
    )]
    expires_at: DateTime<Utc>,

    // Our public key, to ensure this request can't be redirected to another authority service.
    #[serde(
        serialize_with = "hex::serde::serialize",
        deserialize_with = "hex::serde::deserialize"
    )]
    target_public_key: [u8; 33],
}

#[derive(Debug, Serialize)]
pub(crate) struct CreateNucResponse {
    token: String,
}

pub(crate) async fn handler(
    state: SharedState,
    request: Json<CreateNucRequest>,
) -> Result<Json<CreateNucResponse>, HandlerError> {
    let request = request.0;
    // Validate the payload has the right shape and toss it away.
    let payload: SignablePayload = serde_json::from_slice(&request.payload)
        .map_err(|e| HandlerError::MalformedPayload(e.to_string()))?;
    if payload.expires_at < state.services.time.current_time() {
        return Err(HandlerError::PayloadExpired);
    } else if payload.target_public_key != *state.parameters.secret_key.public_key().to_sec1_bytes()
    {
        return Err(HandlerError::InvalidTargetPublicKey);
    }

    let verifying_key = VerifyingKey::from_sec1_bytes(&request.public_key)
        .map_err(|_| HandlerError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(&request.signature.into())
        .map_err(|_| HandlerError::InvalidSignature)?;
    verifying_key
        .verify(&request.payload, &signature)
        .map_err(|_| HandlerError::SignatureVerification)?;

    let expires_at = match state
        .databases
        .accounts
        .find_subscription_end(&PublicKey::from(verifying_key))
        .await
    {
        Ok(Some(timestamp)) => {
            if timestamp <= state.services.time.current_time() {
                return Err(HandlerError::SubscriptionExpired);
            } else {
                timestamp
            }
        }

        Ok(None) => return Err(HandlerError::NotSubscribed),
        Err(e) => {
            error!("Failed to look up subscription: {e}");
            return Err(HandlerError::Internal);
        }
    };

    let requestor_did = Did::new(request.public_key);
    info!("Minting token for {requestor_did}, expires at '{expires_at}'");
    let token = NucTokenBuilder::delegation([])
        .command(["nil"])
        .subject(requestor_did.clone())
        .audience(requestor_did)
        .expires_at(expires_at)
        .build(&state.parameters.secret_key.clone().into())
        .map_err(|e| {
            error!("Failed to sign token: {e}");
            HandlerError::Internal
        })?;
    let response = CreateNucResponse { token };
    Ok(Json(response))
}

#[derive(Debug)]
pub(crate) enum HandlerError {
    Internal,
    InvalidPublicKey,
    InvalidTargetPublicKey,
    InvalidSignature,
    MalformedPayload(String),
    NotSubscribed,
    PayloadExpired,
    SignatureVerification,
    SubscriptionExpired,
}

impl IntoResponse for HandlerError {
    fn into_response(self) -> Response {
        let (code, message) = match self {
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into()),
            Self::InvalidPublicKey => (StatusCode::BAD_REQUEST, "invalid public key".into()),
            Self::InvalidTargetPublicKey => {
                (StatusCode::BAD_REQUEST, "invalid target public key".into())
            }
            Self::InvalidSignature => (StatusCode::BAD_REQUEST, "invalid signature".into()),
            Self::MalformedPayload(reason) => (
                StatusCode::BAD_REQUEST,
                format!("malformed payload: {reason}"),
            ),
            Self::NotSubscribed => (StatusCode::PRECONDITION_FAILED, "not subscribed".into()),
            Self::PayloadExpired => (StatusCode::PRECONDITION_FAILED, "payload is expired".into()),
            Self::SignatureVerification => (
                StatusCode::BAD_REQUEST,
                "signature verification failed".into(),
            ),
            Self::SubscriptionExpired => (
                StatusCode::PRECONDITION_FAILED,
                "subscription expired".into(),
            ),
        };
        let response = RequestHandlerError { message };
        (code, Json(response)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{AppStateBuilder, PublicKeyExt};
    use axum::extract::State;
    use mockall::predicate::eq;
    use nillion_nucs::{
        envelope::NucTokenEnvelope,
        k256::{
            ecdsa::{signature::Signer, SigningKey},
            SecretKey,
        },
    };
    use rstest::rstest;
    use std::time::Duration;

    enum InputModifier {
        Nonce,
        Signature,
        PublicKey,
    }

    struct Handler {
        builder: AppStateBuilder,
    }

    impl Default for Handler {
        fn default() -> Self {
            let mut builder = AppStateBuilder::default();
            builder
                .time_service
                .expect_current_time()
                .returning(|| Utc::now() - Duration::from_secs(60));
            Self { builder }
        }
    }

    impl Handler {
        async fn invoke(
            self,
            request: CreateNucRequest,
        ) -> Result<CreateNucResponse, HandlerError> {
            let state = self.builder.build();
            let request = Json(request);
            handler(State(state), request).await.map(|r| r.0)
        }

        fn expect_subscription_ends(&mut self, public_key: PublicKey, time: Option<DateTime<Utc>>) {
            self.builder
                .account_db
                .expect_find_subscription_end()
                .with(eq(public_key))
                .return_once(move |_| Ok(time));
        }
    }

    #[tokio::test]
    async fn valid_request() {
        let mut handler = Handler::default();
        let client_key = SecretKey::random(&mut rand::thread_rng());
        let now = Utc::now();
        handler
            .expect_subscription_ends(client_key.public_key(), Some(now + Duration::from_secs(60)));
        handler.builder.set_current_time(now);

        let payload = serde_json::to_string(&SignablePayload {
            nonce: [0; 16],
            expires_at: now + Duration::from_secs(1),
            target_public_key: handler.builder.public_key().try_into().unwrap(),
        })
        .unwrap();
        let signature: Signature = SigningKey::from(client_key.clone()).sign(payload.as_bytes());
        let signature = signature.to_bytes().try_into().unwrap();
        let request = CreateNucRequest {
            public_key: client_key.public_key().to_bytes(),
            signature,
            payload: payload.as_bytes().to_vec(),
        };
        let response = handler.invoke(request).await.expect("failed to mint token");
        NucTokenEnvelope::decode(&response.token)
            .expect("invalid token")
            .validate_signatures()
            .expect("invalid signatures");
    }

    #[tokio::test]
    async fn no_subscription() {
        let mut handler = Handler::default();
        let client_key = SecretKey::random(&mut rand::thread_rng());
        handler.expect_subscription_ends(client_key.public_key(), None);

        let payload = serde_json::to_string(&SignablePayload {
            nonce: [0; 16],
            expires_at: Utc::now(),
            target_public_key: handler.builder.public_key().try_into().unwrap(),
        })
        .unwrap();
        let signature: Signature = SigningKey::from(client_key.clone()).sign(payload.as_bytes());
        let signature = signature.to_bytes().try_into().unwrap();
        let request = CreateNucRequest {
            public_key: client_key.public_key().to_bytes(),
            signature,
            payload: payload.as_bytes().to_vec(),
        };
        let err = handler
            .invoke(request)
            .await
            .expect_err("request succeeded");
        assert!(matches!(err, HandlerError::NotSubscribed));
    }

    #[tokio::test]
    async fn expired_subscription() {
        let mut handler = Handler::default();
        let client_key = SecretKey::random(&mut rand::thread_rng());
        let now = Utc::now();
        handler
            .expect_subscription_ends(client_key.public_key(), Some(now - Duration::from_secs(1)));
        handler.builder.set_current_time(now);

        let payload = serde_json::to_string(&SignablePayload {
            nonce: [0; 16],
            expires_at: now + Duration::from_secs(1),
            target_public_key: handler.builder.public_key().try_into().unwrap(),
        })
        .unwrap();
        let signature: Signature = SigningKey::from(client_key.clone()).sign(payload.as_bytes());
        let signature = signature.to_bytes().try_into().unwrap();
        let request = CreateNucRequest {
            public_key: client_key.public_key().to_bytes(),
            signature,
            payload: payload.as_bytes().to_vec(),
        };
        let err = handler
            .invoke(request)
            .await
            .expect_err("request succeeded");
        assert!(matches!(err, HandlerError::SubscriptionExpired));
    }

    #[tokio::test]
    #[rstest]
    #[case::nonce(InputModifier::Nonce)]
    #[case::signature(InputModifier::Signature)]
    #[case::public_key(InputModifier::PublicKey)]
    async fn invalid_signature(#[case] modifier: InputModifier) {
        let handler = Handler::default();
        let client_key = SecretKey::random(&mut rand::thread_rng());
        let payload = serde_json::to_string(&SignablePayload {
            nonce: [0; 16],
            expires_at: Utc::now(),
            target_public_key: handler.builder.public_key().try_into().unwrap(),
        })
        .unwrap();
        let signature: Signature = SigningKey::from(client_key.clone()).sign(payload.as_bytes());
        let signature = signature.to_bytes().try_into().unwrap();
        let mut request = CreateNucRequest {
            public_key: client_key.public_key().to_bytes(),
            signature,
            payload: payload.into(),
        };
        match modifier {
            InputModifier::Nonce => {
                request.payload = serde_json::to_string(&SignablePayload {
                    nonce: [1; 16],
                    expires_at: Utc::now(),
                    target_public_key: handler.builder.public_key().try_into().unwrap(),
                })
                .unwrap()
                .into()
            }
            InputModifier::Signature => request.signature[10] ^= 1,
            InputModifier::PublicKey => request.public_key[10] ^= 1,
        };
        handler.invoke(request).await.expect_err("token was minted");
    }

    #[tokio::test]
    async fn expired_request() {
        let handler = Handler::default();
        let client_key = SecretKey::random(&mut rand::thread_rng());
        let payload = serde_json::to_string(&SignablePayload {
            nonce: [0; 16],
            expires_at: Utc::now() - Duration::from_secs(3600),
            target_public_key: handler.builder.public_key().try_into().unwrap(),
        })
        .unwrap();
        let signature: Signature = SigningKey::from(client_key.clone()).sign(payload.as_bytes());
        let signature = signature.to_bytes().try_into().unwrap();
        let request = CreateNucRequest {
            public_key: client_key.public_key().to_bytes(),
            signature,
            payload: payload.as_bytes().to_vec(),
        };
        let err = handler
            .invoke(request)
            .await
            .expect_err("token minted successfully");
        assert!(matches!(err, HandlerError::PayloadExpired));
    }

    #[tokio::test]
    async fn invalid_target_public_key() {
        let handler = Handler::default();
        let client_key = SecretKey::random(&mut rand::thread_rng());
        let payload = serde_json::to_string(&SignablePayload {
            nonce: [0; 16],
            expires_at: Utc::now(),
            target_public_key: [0; 33],
        })
        .unwrap();
        let signature: Signature = SigningKey::from(client_key.clone()).sign(payload.as_bytes());
        let signature = signature.to_bytes().try_into().unwrap();
        let request = CreateNucRequest {
            public_key: client_key.public_key().to_bytes(),
            signature,
            payload: payload.as_bytes().to_vec(),
        };
        let err = handler
            .invoke(request)
            .await
            .expect_err("token minted successfully");
        assert!(matches!(err, HandlerError::InvalidTargetPublicKey));
    }
}
