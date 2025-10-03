use crate::routes::{Json, RequestHandlerError};
use axum::http::StatusCode;
use axum::{Extension, RequestPartsExt};
use axum::{extract::FromRequestParts, http::request::Parts};
use nillion_nucs::did::Did;
use nillion_nucs::envelope::NucEnvelopeParseError;
use nillion_nucs::validator::{NucValidator, TokenTypeRequirements, ValidationError, ValidationParameters};
use nillion_nucs::{envelope::NucTokenEnvelope, validator::ValidatedNucToken};
use std::sync::Arc;
use tracing::error;

const AUTHORIZATION_HEADER: &str = "Authorization";

enum TokenExtractionError {
    MissingHeader,
    InvalidHeaderValue,
    MissingBearerPrefix,
    MalformedToken(NucEnvelopeParseError),
    ValidationFailed(ValidationError),
}

impl TokenExtractionError {
    /// Converts the internal error into the final HTTP rejection tuple.
    fn into_rejection(self, token_type_name: &str) -> (StatusCode, Json<RequestHandlerError>) {
        let message = match self {
            Self::MissingHeader => format!("`{AUTHORIZATION_HEADER}` header missing"),
            Self::InvalidHeaderValue => "header value is not valid utf8".to_string(),
            Self::MissingBearerPrefix => "missing `Bearer ` prefix in header".to_string(),
            Self::MalformedToken(e) => format!("malformed token: {e}"),
            Self::ValidationFailed(e) => format!("invalid {token_type_name} token: {e}"),
        };
        make_unauthorized(message)
    }
}

/// A Nuc token extractor for capability tokens that must be delegated from nilauth's root key.
#[derive(Debug)]
pub(crate) struct CapabilityNuc(pub(crate) ValidatedNucToken);

impl<S> FromRequestParts<S> for CapabilityNuc
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<RequestHandlerError>);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Extension(state) = parts.extract::<Extension<TokenValidatorState>>().await.map_err(|_| {
            error!("Token validator state not configured");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(RequestHandlerError::new("internal error", "INTERNAL")))
        })?;

        extract_and_validate_token(parts, &state.validator, &state.nilauth_did)
            .await
            .map(Self)
            .map_err(|e| e.into_rejection("capability"))
    }
}

/// A Nuc token extractor for self-signed identity tokens.
#[derive(Debug)]
pub(crate) struct IdentityNuc(pub(crate) ValidatedNucToken);

impl<S> FromRequestParts<S> for IdentityNuc
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<RequestHandlerError>);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Extension(state) = parts.extract::<Extension<TokenValidatorState>>().await.map_err(|_| {
            error!("Token validator state not configured");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(RequestHandlerError::new("internal error", "INTERNAL")))
        })?;

        // Create a validator with no root keys to allow self-signed identity Nucs.
        let validator = NucValidator::new([]).unwrap();
        extract_and_validate_token(parts, &validator, &state.nilauth_did)
            .await
            .map(Self)
            .map_err(|e| e.into_rejection("identity"))
    }
}

async fn extract_and_validate_token(
    parts: &mut Parts,
    validator: &NucValidator,
    nilauth_did: &Did,
) -> Result<ValidatedNucToken, TokenExtractionError> {
    let value = parts.headers.get(AUTHORIZATION_HEADER).ok_or(TokenExtractionError::MissingHeader)?;
    let payload = value.to_str().map_err(|_| TokenExtractionError::InvalidHeaderValue)?;
    let payload = payload.strip_prefix("Bearer ").ok_or(TokenExtractionError::MissingBearerPrefix)?;

    let token = NucTokenEnvelope::decode(payload).map_err(TokenExtractionError::MalformedToken)?;

    let parameters = ValidationParameters {
        token_requirements: TokenTypeRequirements::Invocation(*nilauth_did),
        ..Default::default()
    };

    validator.validate(token, parameters, &Default::default()).map_err(TokenExtractionError::ValidationFailed)
}

fn make_unauthorized(message: impl Into<String>) -> (StatusCode, Json<RequestHandlerError>) {
    (StatusCode::UNAUTHORIZED, Json(RequestHandlerError::new(message, "UNAUTHORIZED")))
}

#[derive(Clone)]
pub(crate) struct TokenValidatorState {
    validator: Arc<NucValidator>,
    nilauth_did: Did,
}

impl TokenValidatorState {
    pub(crate) fn new(validator: NucValidator, nilauth_did: Did) -> Self {
        Self { validator: Arc::new(validator), nilauth_did }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::random_public_key;
    use axum::http::Request;
    use nillion_nucs::{DidMethod, Keypair, Signer, builder::InvocationBuilder};

    struct CapabilityNucBuilder {
        validator: NucValidator,
        nilauth_did: Did,
    }

    impl CapabilityNucBuilder {
        async fn build(self, header: String) -> Result<CapabilityNuc, (StatusCode, Json<RequestHandlerError>)> {
            let extension = TokenValidatorState { validator: self.validator.into(), nilauth_did: self.nilauth_did };
            let mut parts = Request::builder()
                .header("Authorization", format!("Bearer {header}"))
                .extension(extension)
                .body(())
                .expect("failed to build request")
                .into_parts()
                .0;
            CapabilityNuc::from_request_parts(&mut parts, &()).await
        }
    }

    impl Default for CapabilityNucBuilder {
        fn default() -> Self {
            CapabilityNucBuilder {
                validator: NucValidator::new([]).unwrap(),
                nilauth_did: Did::key(random_public_key()),
            }
        }
    }

    #[tokio::test]
    async fn valid_token() {
        let signer_keypair = Keypair::generate();
        let signer = signer_keypair.signer(DidMethod::Key);
        let validator = NucValidator::new([signer_keypair.public_key()]).unwrap();

        let builder = CapabilityNucBuilder { validator, nilauth_did: Did::key(random_public_key()) };

        let serialized_token = InvocationBuilder::new()
            .command(["nil"])
            .audience(builder.nilauth_did)
            .subject(Did::key(random_public_key()))
            .sign_and_serialize(&signer)
            .await
            .expect("failed to build token");
        let token = NucTokenEnvelope::decode(&serialized_token).unwrap();
        let auth = builder.build(serialized_token).await.expect("failed to build auth");
        assert_eq!(&auth.0.token, token.token().token());
    }

    #[tokio::test]
    async fn malformed_token() {
        let builder = CapabilityNucBuilder::default();
        let err = builder.build("boop".into()).await.expect_err("auth built").1;
        assert!(err.0.message.contains("malformed token"), "{err:?}");
    }

    #[tokio::test]
    async fn invalid_signature() {
        let builder = CapabilityNucBuilder::default();
        let signer = Keypair::generate().signer(DidMethod::Key);
        let token = InvocationBuilder::new()
            .command(["nil"])
            .audience(builder.nilauth_did)
            .subject(Did::key(random_public_key()))
            .sign_and_serialize(&signer)
            .await
            .expect("failed to build token");
        let (head, _) = token.rsplit_once('.').unwrap();
        let token =
            format!("{head}.o3lnQxCjDCW10UuRABrHp8FpB_C6q1xgEGvfuXTb7Epp63ry8R2h0wHjToDKDFmkmUmO2jcBkrttuy8kftV6og");
        let err = builder.build(token).await.expect_err("auth built").1;
        assert!(err.0.message.contains("invalid signature"), "{err:?}");
    }

    struct IdentityNucBuilder {
        nilauth_did: Did,
    }

    impl IdentityNucBuilder {
        async fn build(self, header: String) -> Result<IdentityNuc, (StatusCode, Json<RequestHandlerError>)> {
            let extension =
                TokenValidatorState { validator: NucValidator::new([]).unwrap().into(), nilauth_did: self.nilauth_did };
            let mut parts = Request::builder()
                .header("Authorization", format!("Bearer {header}"))
                .extension(extension)
                .body(())
                .expect("failed to build request")
                .into_parts()
                .0;
            IdentityNuc::from_request_parts(&mut parts, &()).await
        }
    }

    impl Default for IdentityNucBuilder {
        fn default() -> Self {
            IdentityNucBuilder { nilauth_did: Did::key(random_public_key()) }
        }
    }

    #[tokio::test]
    async fn identity_nuc_valid_self_signed() {
        let builder = IdentityNucBuilder::default();
        let signer = Keypair::generate().signer(DidMethod::Key);
        let serialized_token = InvocationBuilder::new()
            .command(["nil"])
            .audience(builder.nilauth_did)
            .subject(*signer.did())
            .sign_and_serialize(&signer)
            .await
            .expect("failed to build token");
        let token = NucTokenEnvelope::decode(&serialized_token).unwrap();
        let auth = builder.build(serialized_token).await.expect("failed to build auth");
        assert_eq!(&auth.0.token, token.token().token());
    }
}
