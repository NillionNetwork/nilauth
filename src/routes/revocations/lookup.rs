use crate::db::revocations::RevokedToken;
use crate::routes::RequestHandlerError;
use crate::{routes::Json, state::SharedState};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use nillion_nucs::token::ProofHash;
use nillion_nucs::validator::ValidationParameters;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub(crate) struct LookupRevocationRequest {
    hashes: Vec<ProofHash>,
}

#[derive(Serialize)]
pub(crate) struct LookupRevocationResponse {
    revoked: Vec<RevokedToken>,
}

pub(crate) async fn handler(
    state: SharedState,
    Json(request): Json<LookupRevocationRequest>,
) -> Result<Json<LookupRevocationResponse>, HandlerError> {
    // can't validate more hashes than allowed in a single token.
    if request.hashes.len() > ValidationParameters::default().max_chain_length {
        return Err(HandlerError::TooManyHashes);
    }
    let revocations = state
        .databases
        .revocations
        .lookup_revocations(&request.hashes)
        .await
        .map_err(|_| HandlerError::Database)?;
    let response = LookupRevocationResponse {
        revoked: revocations,
    };
    Ok(Json(response))
}

pub(crate) enum HandlerError {
    Database,
    TooManyHashes,
}

impl IntoResponse for HandlerError {
    fn into_response(self) -> Response {
        let (code, message) = match self {
            Self::Database => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into()),
            Self::TooManyHashes => (
                StatusCode::BAD_REQUEST,
                format!(
                    "can only look up to {} hashes",
                    ValidationParameters::default().max_chain_length
                ),
            ),
        };
        let response = RequestHandlerError { message };
        (code, Json(response)).into_response()
    }
}
