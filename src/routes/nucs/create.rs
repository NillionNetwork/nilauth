use crate::db::subscriptions::BlindModule;
use crate::routes::Json;
use crate::signed::{SignedRequest, VerificationError};
use crate::{routes::RequestHandlerError, state::SharedState};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use nillion_nucs::{builder::NucTokenBuilder, token::Did};
use serde::{Deserialize, Serialize};
use strum::EnumDiscriminants;
use tracing::{error, info};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct SignablePayload {
    // A nonce to add entropy in hex form.
    #[allow(dead_code)]
    #[serde(with = "hex::serde")]
    #[schema(value_type = String, examples(crate::docs::nonce))]
    nonce: [u8; 16],

    // When this payload is no longer considered valid, to prevent reusing this forever if it
    // leaks.
    #[serde(with = "chrono::serde::ts_seconds")]
    #[schema(value_type = u64, examples(crate::docs::epoch_timestamp))]
    expires_at: DateTime<Utc>,

    // Our public key, to ensure this request can't be redirected to another authority service,
    // encoded in hex.
    #[serde(with = "hex::serde")]
    #[schema(value_type = String, examples(crate::docs::public_key))]
    target_public_key: [u8; 33],

    // The blind_module we want a token for.
    blind_module: BlindModule,
}

/// The response to a NUC create request.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CreateNucResponse {
    /// The token in JWT serialized form.
    #[schema(examples(crate::docs::nuc))]
    token: String,
}

/// Create a NUC.
#[utoipa::path(
    post,
    path = "/nucs/create",
    responses(
        (status = OK, body = CreateNucResponse, description = "A NUC that can be used to delegate access to blind modules"),
        (status = 400, body = RequestHandlerError),
        (status = 412, body = RequestHandlerError),
    )
)]
pub(crate) async fn handler(
    state: SharedState,
    request: Json<SignedRequest>,
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

    let requestor_did = Did::new(request.public_key);
    let public_key = request.verify()?;
    let expires_at = match state
        .databases
        .subscriptions
        .find_subscription_end(&public_key, &payload.blind_module)
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

    let segment = match payload.blind_module {
        BlindModule::NilAi => "ai",
        BlindModule::NilDb => "db",
    };

    info!("Minting token for {requestor_did}, expires at '{expires_at}'");
    let token = NucTokenBuilder::delegation([])
        .command(["nil", segment])
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

#[derive(Debug, EnumDiscriminants)]
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
    use nillion_nucs::{
        envelope::NucTokenEnvelope,
        k256::{PublicKey, SecretKey},
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
        async fn invoke(self, request: SignedRequest) -> Result<CreateNucResponse, HandlerError> {
            let state = self.builder.build();
            let request = Json(request);
            handler(State(state), request).await.map(|r| r.0)
        }

        fn expect_subscription_ends(
            &mut self,
            public_key: PublicKey,
            time: Option<DateTime<Utc>>,
            blind_module: BlindModule,
        ) {
            self.builder
                .subscriptions_db
                .expect_find_subscription_end()
                .with(eq(public_key), eq(blind_module))
                .return_once(move |_, _| Ok(time));
        }
    }

    #[tokio::test]
    async fn valid_request() {
        let mut handler = Handler::default();
        let client_key = SecretKey::random(&mut rand::thread_rng());
        let now = Utc::now();
        let blind_module = BlindModule::NilDb;
        handler.expect_subscription_ends(
            client_key.public_key(),
            Some(now + Duration::from_secs(60)),
            blind_module,
        );
        handler.builder.set_current_time(now);

        let payload = SignablePayload {
            nonce: [0; 16],
            expires_at: now + Duration::from_secs(1),
            target_public_key: handler.builder.public_key().try_into().unwrap(),
            blind_module,
        };
        let request = SignedRequest::new(&client_key, &payload);
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
        let blind_module = BlindModule::NilDb;
        handler.expect_subscription_ends(client_key.public_key(), None, blind_module);

        let payload = SignablePayload {
            nonce: [0; 16],
            expires_at: Utc::now(),
            target_public_key: handler.builder.public_key().try_into().unwrap(),
            blind_module,
        };
        let request = SignedRequest::new(&client_key, &payload);
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
        let blind_module = BlindModule::NilDb;
        handler.expect_subscription_ends(
            client_key.public_key(),
            Some(now - Duration::from_secs(1)),
            blind_module,
        );
        handler.builder.set_current_time(now);

        let payload = &SignablePayload {
            nonce: [0; 16],
            expires_at: now + Duration::from_secs(1),
            target_public_key: handler.builder.public_key().try_into().unwrap(),
            blind_module,
        };
        let request = SignedRequest::new(&client_key, &payload);
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
        let blind_module = BlindModule::NilDb;
        let payload = SignablePayload {
            nonce: [0; 16],
            expires_at: Utc::now(),
            target_public_key: handler.builder.public_key().try_into().unwrap(),
            blind_module,
        };
        let mut request = SignedRequest::new(&client_key, &payload);
        match modifier {
            InputModifier::Nonce => {
                request.payload = serde_json::to_string(&SignablePayload {
                    nonce: [1; 16],
                    expires_at: Utc::now(),
                    target_public_key: handler.builder.public_key().try_into().unwrap(),
                    blind_module,
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
        let payload = SignablePayload {
            nonce: [0; 16],
            expires_at: Utc::now() - Duration::from_secs(3600),
            target_public_key: handler.builder.public_key().try_into().unwrap(),
            blind_module: BlindModule::NilDb,
        };
        let request = SignedRequest::new(&client_key, &payload);
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
        let payload = SignablePayload {
            nonce: [0; 16],
            expires_at: Utc::now(),
            target_public_key: [0; 33],
            blind_module: BlindModule::NilDb,
        };
        let request = SignedRequest::new(&client_key, &payload);
        let err = handler
            .invoke(request)
            .await
            .expect_err("token minted successfully");
        assert!(matches!(err, HandlerError::InvalidTargetPublicKey));
    }
}
