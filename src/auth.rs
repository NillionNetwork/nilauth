use crate::routes::{Json, RequestHandlerError};
use axum::http::StatusCode;
use axum::{extract::FromRequestParts, http::request::Parts};
use axum::{Extension, RequestPartsExt};
use nillion_nucs::token::Did;
use nillion_nucs::validator::{NucValidator, TokenTypeRequirements, ValidationParameters};
use nillion_nucs::{envelope::NucTokenEnvelope, validator::ValidatedNucToken};
use std::sync::Arc;
use tracing::error;

const AUTHORIZATION_HEADER: &str = "Authorization";

/// A NUC token extractor.
#[derive(Debug)]
pub(crate) struct NucAuth(pub(crate) ValidatedNucToken);

impl<S> FromRequestParts<S> for NucAuth
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<RequestHandlerError>);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Extension(state) = parts
            .extract::<Extension<TokenValidatorState>>()
            .await
            .map_err(|_| {
                error!("Token validator state not configured");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(RequestHandlerError::new("internal error", "INTERNAL")),
                )
            })?;
        let payload = match parts.headers.get(AUTHORIZATION_HEADER) {
            Some(value) => value
                .to_str()
                .map_err(|_| make_unauthorized("header value is not valid utf8"))?,
            None => {
                return Err(make_unauthorized(format!(
                    "`{AUTHORIZATION_HEADER}` header missing"
                )));
            }
        };
        let payload = payload
            .strip_prefix("Bearer ")
            .ok_or_else(|| make_unauthorized("missing `Bearer ` prefix in header"))?;
        let token = NucTokenEnvelope::decode(payload)
            .map_err(|e| make_unauthorized(format!("malformed token: {e}")))?;
        let parameters = ValidationParameters {
            token_requirements: TokenTypeRequirements::Invocation(state.nilauth_did),
            ..Default::default()
        };
        let token = state
            .validator
            .validate(token, parameters, &Default::default())
            .map_err(|e| make_unauthorized(format!("invalid token: {e}")))?;
        Ok(Self(token))
    }
}

fn make_unauthorized(message: impl Into<String>) -> (StatusCode, Json<RequestHandlerError>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(RequestHandlerError::new(message, "UNAUTHORIZED")),
    )
}

#[derive(Clone)]
pub(crate) struct TokenValidatorState {
    validator: Arc<NucValidator>,
    nilauth_did: Did,
}

impl TokenValidatorState {
    pub(crate) fn new(validator: NucValidator, nilauth_did: Did) -> Self {
        Self {
            validator: Arc::new(validator),
            nilauth_did,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::random_public_key;
    use axum::http::Request;
    use nillion_nucs::{builder::NucTokenBuilder, k256::SecretKey};

    struct NucAuthBuilder {
        validator: NucValidator,
        nilauth_did: Did,
    }

    impl NucAuthBuilder {
        async fn build(
            self,
            header: String,
        ) -> Result<NucAuth, (StatusCode, Json<RequestHandlerError>)> {
            let extension = TokenValidatorState {
                validator: self.validator.into(),
                nilauth_did: self.nilauth_did,
            };
            let mut parts = Request::builder()
                .header("Authorization", format!("Bearer {header}"))
                .extension(extension)
                .body(())
                .expect("failed to build request")
                .into_parts()
                .0;
            NucAuth::from_request_parts(&mut parts, &()).await
        }
    }

    impl Default for NucAuthBuilder {
        fn default() -> Self {
            NucAuthBuilder {
                validator: NucValidator::new(&[]),
                nilauth_did: Did::new(random_public_key()),
            }
        }
    }

    #[tokio::test]
    async fn valid_token() {
        let builder = NucAuthBuilder::default();
        let serialized_token = NucTokenBuilder::invocation(Default::default())
            .command(["nil"])
            .audience(builder.nilauth_did.clone())
            .subject(Did::new(random_public_key()))
            .build(&SecretKey::random(&mut rand::thread_rng()).into())
            .expect("failed to build token");
        let token = NucTokenEnvelope::decode(&serialized_token).unwrap();
        let auth = builder
            .build(serialized_token)
            .await
            .expect("failed to build auth");
        assert_eq!(&auth.0.token, token.token().token());
    }

    #[tokio::test]
    async fn malformed_token() {
        let builder = NucAuthBuilder::default();
        let err = builder
            .build("boop".into())
            .await
            .expect_err("auth built")
            .1;
        assert!(err.0.message.contains("malformed token"), "{err:?}");
    }

    #[tokio::test]
    async fn invalid_signature() {
        let builder = NucAuthBuilder::default();
        let token = NucTokenBuilder::invocation(Default::default())
            .command(["nil"])
            .audience(builder.nilauth_did.clone())
            .subject(Did::new(random_public_key()))
            .build(&SecretKey::random(&mut rand::thread_rng()).into())
            .expect("failed to build token");
        let (head, _) = token.rsplit_once('.').unwrap();
        let token = format!("{head}.o3lnQxCjDCW10UuRABrHp8FpB_C6q1xgEGvfuXTb7Epp63ry8R2h0wHjToDKDFmkmUmO2jcBkrttuy8kftV6og");
        let err = builder.build(token).await.expect_err("auth built").1;
        assert!(err.0.message.contains("invalid signature"), "{err:?}");
    }
}
