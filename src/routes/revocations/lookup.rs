use crate::db::revocations::RevokedToken;
use crate::routes::RequestHandlerError;
use crate::{routes::Json, state::SharedState};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use nillion_nucs::token::ProofHash;
use nillion_nucs::validator::ValidationParameters;
use serde::{Deserialize, Serialize};
use strum::EnumDiscriminants;
use utoipa::ToSchema;

/// A request to check whether a token is revoked.
#[derive(Deserialize, ToSchema)]
pub(crate) struct LookupRevocationRequest {
    /// The proof chain in the revocation being checked.
    #[schema(value_type = Vec<String>, examples(crate::docs::proof_hash))]
    hashes: Vec<ProofHash>,
}

/// The response to a request to look up a revocation.
#[derive(Serialize, ToSchema)]
pub(crate) struct LookupRevocationResponse {
    /// The details of the tokens in the proof chain that were revoked.
    revoked: Vec<RevokedToken>,
}

/// Lookup a revoked token.
#[utoipa::path(
    post,
    path = "/revocations/lookup",
    responses(
        (status = OK, body = LookupRevocationResponse, description = "The tokens in the proof chain that have been revoked"),
        (status = 400, body = RequestHandlerError),
    )
)]
pub(crate) async fn handler(
    state: SharedState,
    Json(request): Json<LookupRevocationRequest>,
) -> Result<Json<LookupRevocationResponse>, HandlerError> {
    // can't validate more hashes than allowed in a single token.
    if request.hashes.len() > ValidationParameters::default().max_chain_length {
        return Err(HandlerError::TooManyHashes);
    }
    let revocations =
        state.databases.revocations.lookup_revocations(&request.hashes).await.map_err(|_| HandlerError::Database)?;
    let response = LookupRevocationResponse { revoked: revocations };
    Ok(Json(response))
}

#[derive(Debug, EnumDiscriminants)]
pub(crate) enum HandlerError {
    Database,
    TooManyHashes,
}

impl IntoResponse for HandlerError {
    fn into_response(self) -> Response {
        let discriminant = HandlerErrorDiscriminants::from(&self);
        let (code, message) = match self {
            Self::Database => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into()),
            Self::TooManyHashes => (
                StatusCode::BAD_REQUEST,
                format!("can only look up to {} hashes", ValidationParameters::default().max_chain_length),
            ),
        };
        let response = RequestHandlerError::new(message, format!("{discriminant:?}"));
        (code, Json(response)).into_response()
    }
}
