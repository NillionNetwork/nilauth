use crate::auth::IdentityNuc;
use crate::db::subscriptions::BlindModule;
use crate::routes::Json;
use crate::signed::{SignedRequest, VerificationError};
use crate::{routes::RequestHandlerError, state::SharedState};
use axum::extract::FromRequestParts;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use metrics::counter;
use nillion_nucs::token::Command;
use nillion_nucs::{builder::DelegationBuilder, did::Did};
use serde::{Deserialize, Serialize};
use strum::EnumDiscriminants;
use tracing::{error, info};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct LegacySignablePayload {
    #[serde(with = "hex::serde")]
    nonce: [u8; 16],
    #[serde(with = "chrono::serde::ts_seconds")]
    expires_at: DateTime<Utc>,
    #[serde(with = "hex::serde")]
    target_public_key: [u8; 33],
    blind_module: BlindModule,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateNucRequest {
    blind_module: BlindModule,
}

/// The response to a Nuc create request.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CreateNucResponse {
    /// The token in JWT serialized form.
    #[schema(examples(crate::docs::nuc))]
    token: String,
}

/// Optional identity Nuc authentication wrapper that rejects invalid tokens
pub(crate) struct OptionalIdentityNuc(Option<IdentityNuc>);

impl<S> FromRequestParts<S> for OptionalIdentityNuc
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<RequestHandlerError>);

    async fn from_request_parts(parts: &mut axum::http::request::Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Check if Authorization header exists
        if !parts.headers.contains_key("Authorization") {
            return Ok(Self(None));
        }

        // Try to extract IdentityNuc, propagate errors if token is invalid
        match IdentityNuc::from_request_parts(parts, state).await {
            Ok(auth) => Ok(Self(Some(auth))),
            Err(rejection) => Err(rejection),
        }
    }
}

async fn handle_modern_auth(auth: IdentityNuc, request: serde_json::Value) -> Result<(Did, BlindModule), HandlerError> {
    // Validate command scope
    let expected_command: Command = ["nil", "auth", "nucs", "create"].into();
    if auth.0.token.command != expected_command {
        return Err(HandlerError::InvalidCommand(expected_command));
    }

    let modern_request: CreateNucRequest = serde_json::from_value(request)?;
    Ok((auth.0.token.subject, modern_request.blind_module))
}

async fn handle_legacy_auth(
    state: &SharedState,
    request: serde_json::Value,
) -> Result<(Did, BlindModule), HandlerError> {
    // This is the legacy flow which uses signed payload auth. This will be removed
    // when support for `did:nil` is dropped in the next major version.
    let legacy_request: SignedRequest = serde_json::from_value(request)?;
    let payload: LegacySignablePayload =
        serde_json::from_slice(&legacy_request.payload).map_err(|e| HandlerError::MalformedPayload(e.to_string()))?;

    if payload.expires_at < state.services.time.current_time() {
        return Err(HandlerError::PayloadExpired);
    }
    if payload.target_public_key != state.parameters.public_key {
        return Err(HandlerError::InvalidTargetPublicKey);
    }
    let _ = legacy_request.verify()?;
    #[allow(deprecated)] // Required for backward compatibility with legacy flow
    Ok((Did::nil(legacy_request.public_key), payload.blind_module))
}

/// Create a Nuc.
#[utoipa::path(
    post,
    path = "/nucs/create",
    request_body = CreateNucRequest,
    responses(
        (status = OK, body = CreateNucResponse, description = "A Nuc that can be used to delegate access to blind modules"),
        (status = 400, body = RequestHandlerError),
        (status = 401, body = RequestHandlerError),
        (status = 412, body = RequestHandlerError),
    )
)]
pub(crate) async fn handler(
    state: SharedState,
    OptionalIdentityNuc(opt_auth): OptionalIdentityNuc,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<CreateNucResponse>, HandlerError> {
    let (requestor_did, blind_module) = if let Some(auth) = opt_auth {
        handle_modern_auth(auth, request).await?
    } else {
        handle_legacy_auth(&state, request).await?
    };

    handle_nuc_creation(state, requestor_did, blind_module).await
}

async fn handle_nuc_creation(
    state: SharedState,
    requestor_did: Did,
    blind_module: BlindModule,
) -> Result<Json<CreateNucResponse>, HandlerError> {
    let expires_at = match state.databases.subscriptions.find_subscription_end(&requestor_did, &blind_module).await {
        Ok(Some(timestamp)) if timestamp > state.services.time.current_time() => timestamp,
        Ok(Some(_)) => return Err(HandlerError::SubscriptionExpired),
        Ok(None) => return Err(HandlerError::NotSubscribed),
        Err(e) => {
            error!("Failed to look up subscription: {e}");
            return Err(HandlerError::Internal);
        }
    };

    let segment = match blind_module {
        BlindModule::NilAi => "ai",
        BlindModule::NilDb => "db",
    };

    info!("Minting token for {requestor_did}, expires at '{expires_at}'");
    let signer = &state.parameters.signer;
    let token = DelegationBuilder::new()
        .command(["nil", segment])
        .subject(requestor_did)
        .audience(requestor_did)
        .expires_at(expires_at)
        .sign_and_serialize(signer.as_ref())
        .await
        .map_err(|e| {
            error!("Failed to sign token: {e}");
            HandlerError::Internal
        })?;

    counter!("nucs_minted_total", "module" => blind_module.to_string()).increment(1);
    let response = CreateNucResponse { token };
    Ok(Json(response))
}

#[derive(Debug, EnumDiscriminants)]
pub(crate) enum HandlerError {
    Internal,
    InvalidCommand(Command),
    InvalidPublicKey,
    InvalidTargetPublicKey,
    InvalidSignature,
    MalformedPayload(String),
    NotSubscribed,
    PayloadExpired,
    SignatureVerification,
    SubscriptionExpired,
}

impl From<serde_json::Error> for HandlerError {
    fn from(e: serde_json::Error) -> Self {
        Self::MalformedPayload(e.to_string())
    }
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
            Self::InvalidCommand(expected) => {
                (StatusCode::UNAUTHORIZED, format!("invalid command for identity token, expected '{expected}'"))
            }
            Self::InvalidPublicKey => (StatusCode::BAD_REQUEST, "invalid public key".into()),
            Self::InvalidTargetPublicKey => (StatusCode::BAD_REQUEST, "invalid target public key".into()),
            Self::InvalidSignature => (StatusCode::BAD_REQUEST, "invalid signature".into()),
            Self::MalformedPayload(reason) => (StatusCode::BAD_REQUEST, format!("malformed payload: {reason}")),
            Self::NotSubscribed => (StatusCode::PRECONDITION_FAILED, "not subscribed".into()),
            Self::PayloadExpired => (StatusCode::PRECONDITION_FAILED, "payload is expired".into()),
            Self::SignatureVerification => (StatusCode::BAD_REQUEST, "signature verification failed".into()),
            Self::SubscriptionExpired => (StatusCode::PRECONDITION_FAILED, "subscription expired".into()),
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
    use chrono::Duration;
    use mockall::predicate::eq;
    use nillion_nucs::k256::ecdsa::signature::Signer as _;
    use nillion_nucs::k256::ecdsa::{Signature, SigningKey};

    #[tokio::test]
    async fn legacy_flow_valid_request() {
        // 1. Setup
        let mut builder = AppStateBuilder::default();
        let now = Utc::now();
        builder.time_service.expect_current_time().return_const(now);

        let legacy_signing_key = SigningKey::random(&mut rand::thread_rng());
        let legacy_public_key: [u8; 33] =
            legacy_signing_key.verifying_key().to_sec1_bytes().as_ref().try_into().unwrap();
        #[allow(deprecated)]
        let legacy_did = Did::nil(legacy_public_key);
        let blind_module = BlindModule::NilDb;

        // 2. Mock the DB to return a valid subscription
        builder
            .subscriptions_db
            .expect_find_subscription_end()
            .with(eq(legacy_did), eq(blind_module))
            .return_once(move |_, _| Ok(Some(now + Duration::seconds(120))));

        let state = builder.build();

        // 3. Create a valid legacy signed request
        let signable_payload = LegacySignablePayload {
            nonce: rand::random(),
            expires_at: now + Duration::seconds(60),
            target_public_key: state.parameters.public_key,
            blind_module,
        };
        let payload_bytes = serde_json::to_vec(&signable_payload).unwrap();
        let ecdsa_signature: Signature = legacy_signing_key.sign(&payload_bytes);
        let signature: [u8; 64] = ecdsa_signature.to_bytes().into();

        // Manually construct the JSON since SignedRequest doesn't implement Serialize
        let request_json = serde_json::json!({
            "public_key": hex::encode(legacy_public_key),
            "signature": hex::encode(signature),
            "payload": hex::encode(&payload_bytes),
        });

        // 4. Invoke the handler and assert success
        let result = handler(State(state), OptionalIdentityNuc(None), Json(request_json)).await;
        assert!(result.is_ok(), "Handler failed with error: {result:?}");
    }
}
