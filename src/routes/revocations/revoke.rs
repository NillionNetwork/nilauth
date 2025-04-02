use crate::{
    auth::NucAuth,
    db::revocations::StoreRevocationError,
    routes::{Json, RequestHandlerError},
    state::SharedState,
};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use metrics::counter;
use nillion_nucs::{
    envelope::{InvalidSignature, NucEnvelopeParseError, NucTokenEnvelope},
    token::{Command, TokenBody},
};
use std::{iter, sync::LazyLock};
use strum::EnumDiscriminants;
use tracing::info;

const TOKEN_ARG: &str = "token";
static REVOCATION_CMD: LazyLock<Command> = LazyLock::new(|| ["nuc", "revoke"].into());

pub(crate) async fn handler(state: SharedState, auth: NucAuth) -> Result<Json<()>, HandlerError> {
    if auth.0.token.command != *REVOCATION_CMD {
        return Err(HandlerError::InvalidCommand);
    }
    let (token, proofs) = match auth.0.token.body {
        TokenBody::Invocation(args) => {
            let token = args.get(TOKEN_ARG).ok_or(HandlerError::MissingToken)?;

            let token = token.as_str().ok_or(HandlerError::StringToken)?;
            let envelope = NucTokenEnvelope::decode(token).map_err(HandlerError::MalformedToken)?;
            let envelope = envelope
                .validate_signatures()
                .map_err(HandlerError::InvalidSignature)?;
            let token = envelope.token().token();

            // The user sending the request must either be the issuer or the audience of the token
            // being revoked
            if ![&token.issuer, &token.audience].contains(&&auth.0.token.issuer) {
                return Err(HandlerError::IssuerNotAllowed);
            }
            envelope.into_parts()
        }
        TokenBody::Delegation(_) => return Err(HandlerError::NeedInvocation),
    };
    // Find the "latest" expiration; worst case walk to our root token and use that.
    let expires_at = iter::once(&token)
        .chain(&proofs)
        .filter_map(|t| t.token().expires_at)
        .next()
        .ok_or(HandlerError::NoExpiration)?;
    // If the token is already expired, return success since it's technically invalid already
    if expires_at < state.services.time.current_time() {
        info!("Ignoring token that already expired at {expires_at}");
        return Ok(Json(()));
    }
    let hash = token.compute_hash();
    let result = state
        .databases
        .revocations
        .store_revocation(&hash, expires_at)
        .await;
    match result {
        Ok(_) => {
            info!("Revoked token {hash}, expires at {expires_at}");
            counter!("revoked_tokens_total").increment(1);
            Ok(Json(()))
        }
        Err(StoreRevocationError::AlreadyRevoked) => {
            info!("Token {hash} already revoked, ignoring");
            Ok(Json(()))
        }
        Err(StoreRevocationError::Database) => Err(HandlerError::Database),
    }
}

#[derive(Debug, EnumDiscriminants)]
pub(crate) enum HandlerError {
    Database,
    InvalidCommand,
    InvalidSignature(InvalidSignature),
    IssuerNotAllowed,
    MalformedToken(NucEnvelopeParseError),
    MissingToken,
    NeedInvocation,
    NoExpiration,
    StringToken,
}

impl IntoResponse for HandlerError {
    fn into_response(self) -> Response {
        let discriminant = HandlerErrorDiscriminants::from(&self);
        let (code, message) = match self {
            Self::Database => (StatusCode::INTERNAL_SERVER_ERROR, "database error".into()),
            Self::InvalidCommand => (
                StatusCode::BAD_REQUEST,
                format!("expected command {}", *REVOCATION_CMD),
            ),
            Self::InvalidSignature(e) => {
                (StatusCode::BAD_REQUEST, format!("invalid signature: {e}"))
            }
            Self::IssuerNotAllowed => (
                StatusCode::BAD_REQUEST,
                "invocation issuer not allowed to revoke token".into(),
            ),
            Self::MalformedToken(e) => (StatusCode::BAD_REQUEST, format!("malformed token: {e}")),
            Self::MissingToken => (
                StatusCode::BAD_REQUEST,
                format!("missing `{TOKEN_ARG}` in NUC args"),
            ),
            Self::NeedInvocation => (
                // this should have been caught by the token validator, hence the 500 status code
                StatusCode::INTERNAL_SERVER_ERROR,
                "need an invocation".into(),
            ),
            Self::NoExpiration => (
                // there *must* be at least one expiration time since we set one in the root one
                StatusCode::INTERNAL_SERVER_ERROR,
                "no expiration time found in token chain".into(),
            ),
            Self::StringToken => (
                StatusCode::BAD_REQUEST,
                format!("expected string token in `{TOKEN_ARG}` arg"),
            ),
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
    use chrono::{DateTime, Utc};
    use mockall::predicate::eq;
    use nillion_nucs::{
        builder::NucTokenBuilder,
        k256::SecretKey,
        token::{Did, JsonObject},
        validator::ValidatedNucToken,
    };
    use serde_json::json;

    #[derive(Default)]
    struct Handler {
        builder: AppStateBuilder,
    }

    impl Handler {
        async fn invoke(
            self,
            key: &SecretKey,
            token_builder: NucTokenBuilder,
        ) -> Result<(), HandlerError> {
            let state = self.builder.build();
            let token = token_builder.build(&key.into()).expect("token build faled");
            let token = NucTokenEnvelope::decode(&token)
                .expect("invalid token")
                .into_parts()
                .0
                .into_token();
            let validated_token = ValidatedNucToken {
                token,
                proofs: Vec::new(),
            };
            handler(State(state), NucAuth(validated_token))
                .await
                .map(|r| r.0)
        }
    }

    trait JsonValueExt {
        fn into_object(self) -> JsonObject;
    }

    impl JsonValueExt for serde_json::Value {
        fn into_object(self) -> JsonObject {
            self.as_object().cloned().expect("not an object")
        }
    }

    fn make_revoked_token(audience_key: &SecretKey, expires_at: Option<DateTime<Utc>>) -> String {
        let mut builder = NucTokenBuilder::delegation([])
            .command(["nil", "hello"])
            .audience(Did::new(audience_key.public_key().to_bytes()))
            .subject(Did::new([0xaa; 33]));
        if let Some(expires_at) = expires_at {
            builder = builder.expires_at(expires_at);
        }
        builder
            .build(&SecretKey::random(&mut rand::thread_rng()).into())
            .expect("failed to build token to revoke")
    }

    #[tokio::test]
    async fn valid_revoke() {
        let mut handler = Handler::default();
        let invoker_key = SecretKey::random(&mut rand::thread_rng());
        let now = DateTime::from_timestamp(1743088537, 0).unwrap();
        let expires_at = DateTime::from_timestamp(1743088536, 0).unwrap();
        let revoked_token = make_revoked_token(&invoker_key, Some(expires_at));
        let hash = NucTokenEnvelope::decode(&revoked_token)
            .unwrap()
            .token()
            .compute_hash();

        let auth_token_builder =
            NucTokenBuilder::invocation(json!({"token": revoked_token}).into_object())
                .command(["nuc", "revoke"])
                .subject(Did::new([0xaa; 33]))
                .audience(Did::new(handler.builder.public_key().try_into().unwrap()));

        handler
            .builder
            .revocation_db
            .expect_store_revocation()
            .with(eq(hash), eq(expires_at))
            .return_once(move |_, _| Ok(()));
        handler
            .builder
            .time_service
            .expect_current_time()
            .return_once(move || now);
        handler
            .invoke(&invoker_key, auth_token_builder)
            .await
            .expect("handler failed");
    }

    #[tokio::test]
    async fn invalid_command() {
        let handler = Handler::default();
        let invoker_key = SecretKey::random(&mut rand::thread_rng());
        let expires_at = DateTime::from_timestamp(1743088536, 0).unwrap();
        let revoked_token = make_revoked_token(&invoker_key, Some(expires_at));
        let auth_token_builder =
            NucTokenBuilder::invocation(json!({"token": revoked_token}).into_object())
                .command(["nil", "db"])
                .subject(Did::new([0xaa; 33]))
                .audience(Did::new(handler.builder.public_key().try_into().unwrap()));

        let err = handler
            .invoke(&invoker_key, auth_token_builder)
            .await
            .expect_err("handler succeeded");
        assert!(matches!(err, HandlerError::InvalidCommand), "{err:?}");
    }

    #[tokio::test]
    async fn missing_token_arg() {
        let handler = Handler::default();
        let invoker_key = SecretKey::random(&mut rand::thread_rng());
        let auth_token_builder = NucTokenBuilder::invocation(Default::default())
            .command(["nuc", "revoke"])
            .subject(Did::new([0xaa; 33]))
            .audience(Did::new(handler.builder.public_key().try_into().unwrap()));

        let err = handler
            .invoke(&invoker_key, auth_token_builder)
            .await
            .expect_err("handler succeeded");
        assert!(matches!(err, HandlerError::MissingToken), "{err:?}");
    }

    #[tokio::test]
    async fn invalid_token_arg() {
        let handler = Handler::default();
        let invoker_key = SecretKey::random(&mut rand::thread_rng());
        let auth_token_builder =
            NucTokenBuilder::invocation(json!({"token": "beep"}).into_object())
                .command(["nuc", "revoke"])
                .subject(Did::new([0xaa; 33]))
                .audience(Did::new(handler.builder.public_key().try_into().unwrap()));

        let err = handler
            .invoke(&invoker_key, auth_token_builder)
            .await
            .expect_err("handler succeeded");
        assert!(matches!(err, HandlerError::MalformedToken(_)), "{err:?}");
    }

    #[tokio::test]
    async fn issuer_not_allowed_arg() {
        let handler = Handler::default();
        let invoker_key = SecretKey::random(&mut rand::thread_rng());
        // create a token where the audience is some other random key
        let revoked_token = make_revoked_token(&SecretKey::random(&mut rand::thread_rng()), None);
        let auth_token_builder =
            NucTokenBuilder::invocation(json!({"token": revoked_token}).into_object())
                .command(["nuc", "revoke"])
                .subject(Did::new([0xaa; 33]))
                .audience(Did::new(handler.builder.public_key().try_into().unwrap()));

        let err = handler
            .invoke(&invoker_key, auth_token_builder)
            .await
            .expect_err("handler succeeded");
        assert!(matches!(err, HandlerError::IssuerNotAllowed), "{err:?}");
    }
}
