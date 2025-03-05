use crate::state::SharedState;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
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
    let expires_at = Utc::now() + state.token_expiration;
    info!("Minting token for {requestor_did}, expires at '{expires_at}'");
    let token = NucTokenBuilder::delegation([])
        .command(["nil"])
        .subject(requestor_did.clone())
        .audience(requestor_did)
        .expires_at(expires_at)
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
    use rstest::rstest;
    use std::{ops::Deref, sync::Arc, time::Duration};

    enum InputModifier {
        Nonce,
        Signature,
        PublicKey,
    }

    #[tokio::test]
    async fn valid_request() {
        let server_key = SecretKey::random(&mut rand::thread_rng());
        let state = Arc::new(AppState {
            secret_key: server_key.clone(),
            token_expiration: Duration::from_secs(1),
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
    #[rstest]
    #[case::nonce(InputModifier::Nonce)]
    #[case::signature(InputModifier::Signature)]
    #[case::public_key(InputModifier::PublicKey)]
    async fn invalid_signature(#[case] modifier: InputModifier) {
        let server_key = SecretKey::random(&mut rand::thread_rng());
        let state = Arc::new(AppState {
            secret_key: server_key.clone(),
            token_expiration: Duration::from_secs(1),
        });

        let client_key = SecretKey::random(&mut rand::thread_rng());
        let payload = serde_json::to_string(&SignablePayload { nonce: [0; 16] }).unwrap();
        let signature: Signature = SigningKey::from(client_key.clone()).sign(payload.as_bytes());
        let signature = signature.to_bytes().try_into().unwrap();
        let mut request = CreateNucRequest {
            public_key: client_key
                .public_key()
                .to_sec1_bytes()
                .deref()
                .try_into()
                .unwrap(),
            signature,
            payload: payload.into(),
        };
        match modifier {
            InputModifier::Nonce => {
                request.payload = serde_json::to_string(&SignablePayload { nonce: [1; 16] })
                    .unwrap()
                    .into()
            }
            InputModifier::Signature => request.signature[10] ^= 1,
            InputModifier::PublicKey => request.public_key[5] ^= 1,
        };
        handler(State(state), Json(request))
            .await
            .expect_err("token was minted");
    }
}
