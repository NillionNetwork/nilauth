use crate::state::SharedState;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use nillion_nucs::k256::ecdsa::{signature::Verifier, Signature};
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
    #[allow(dead_code)]
    nonce: [u8; 16],
}

#[derive(Debug, Serialize)]
pub(crate) struct CreateNucResponse {
    token: String,
}

pub(crate) async fn handler(
    state: SharedState,
    request: Json<CreateNucRequest>,
) -> Result<Json<CreateNucResponse>, Response> {
    let request = request.0;
    // Validate the payload has the right shape and toss it away.
    serde_json::from_slice::<SignablePayload>(&request.payload)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid payload: {e}")).into_response())?;

    let verifying_key = VerifyingKey::from_sec1_bytes(&request.public_key)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid public key").into_response())?;
    let signature = Signature::from_bytes(&request.signature.into())
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid signature").into_response())?;
    verifying_key
        .verify(&request.payload, &signature)
        .map_err(|_| (StatusCode::BAD_REQUEST, "signature verification failed").into_response())?;

    let requestor_did = Did::nil(request.public_key);
    info!("Minting token for {requestor_did}");
    let token = NucTokenBuilder::delegation([])
        .command(["nil"])
        .subject(requestor_did.clone())
        .audience(requestor_did)
        .build(&state.secret_key.clone().into())
        .map_err(|e| {
            error!("Failed to sign token: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;
    let response = CreateNucResponse { token };
    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use axum::extract::State;
    use nillion_nucs::{
        envelope::NucTokenEnvelope,
        k256::{
            ecdsa::{signature::Signer, SigningKey},
            SecretKey,
        },
    };
    use std::{ops::Deref, sync::Arc};

    #[tokio::test]
    async fn valid_request() {
        let server_key = SecretKey::random(&mut rand::thread_rng());
        let state = Arc::new(AppState {
            secret_key: server_key.clone(),
        });

        let client_key = SecretKey::random(&mut rand::thread_rng());
        let payload = serde_json::to_string(&SignablePayload { nonce: [0; 16] }).unwrap();
        let signature: Signature = SigningKey::from(client_key.clone()).sign(payload.as_bytes());
        let signature = signature.to_bytes().try_into().unwrap();
        let request = CreateNucRequest {
            public_key: client_key
                .public_key()
                .to_sec1_bytes()
                .deref()
                .try_into()
                .unwrap(),
            signature,
            payload: payload.as_bytes().to_vec(),
        };
        let response = handler(State(state), Json(request))
            .await
            .expect("failed to mint token");
        NucTokenEnvelope::decode(&response.token)
            .expect("invalid token")
            .validate_signatures()
            .expect("invalid signatures");
    }

    #[tokio::test]
    async fn invalid_signature() {
        let server_key = SecretKey::random(&mut rand::thread_rng());
        let state = Arc::new(AppState {
            secret_key: server_key.clone(),
        });

        let payload = serde_json::to_string(&SignablePayload { nonce: [0; 16] }).unwrap();
        let public_key =
            hex::decode("03ef993b7e986d25f7cfcd2ec75e752d3c364c2080df6f0d31fe7f58e5bf9a66a5")
                .unwrap()
                .try_into()
                .unwrap();
        let request = CreateNucRequest {
            public_key,
            signature: [0xab; 64],
            payload: payload.as_bytes().to_vec(),
        };
        handler(State(state), Json(request))
            .await
            .expect_err("token was minted");
    }
}
