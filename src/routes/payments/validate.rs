use crate::state::SharedState;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use nillion_chain_client::tx::RetrieveError;
use nillion_nucs::k256::sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub(crate) struct ValidatePaymentRequest {
    tx_hash: String,

    #[serde(deserialize_with = "hex::serde::deserialize")]
    payload: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    #[allow(dead_code)]
    #[serde(
        serialize_with = "hex::serde::serialize",
        deserialize_with = "hex::serde::deserialize"
    )]
    nonce: [u8; 16],

    #[serde(
        serialize_with = "hex::serde::serialize",
        deserialize_with = "hex::serde::deserialize"
    )]
    service_public_key: Vec<u8>,
}

pub(crate) async fn handler(
    state: SharedState,
    request: Json<ValidatePaymentRequest>,
) -> Result<Json<()>, HandlerError> {
    let decoded_payload: Payload = serde_json::from_slice(&request.payload)
        .map_err(|e| HandlerError::MalformedPayload(e.to_string()))?;
    if decoded_payload.service_public_key != *state.secret_key.public_key().to_sec1_bytes() {
        return Err(HandlerError::UnknownPublicKey);
    }

    let tx = state
        .services
        .tx
        .get(&request.tx_hash)
        .await
        .map_err(HandlerError::RetrieveTransaction)?;
    let payload_hash = Sha256::digest(&request.payload);
    if tx.resource != payload_hash.as_slice() {
        return Err(HandlerError::HashMismatch);
    }
    Ok(Json(()))
}

#[derive(Debug)]
pub(crate) enum HandlerError {
    HashMismatch,
    MalformedPayload(String),
    UnknownPublicKey,
    RetrieveTransaction(RetrieveError),
}

impl IntoResponse for HandlerError {
    fn into_response(self) -> Response {
        let output = match self {
            Self::HashMismatch => (
                StatusCode::BAD_REQUEST,
                "payload hash does not match transaction nonce".into(),
            ),
            Self::MalformedPayload(reason) => (
                StatusCode::BAD_REQUEST,
                format!("malformed payload: {reason}"),
            ),
            Self::UnknownPublicKey => (
                StatusCode::BAD_REQUEST,
                "payload public key is different from ours".into(),
            ),
            Self::RetrieveTransaction(e) => match e {
                RetrieveError::NotCommitted => (
                    StatusCode::PRECONDITION_FAILED,
                    "transaction is not committed yet".into(),
                ),
                RetrieveError::Malformed(_) => {
                    (StatusCode::BAD_REQUEST, "transaction is malformed".into())
                }
                RetrieveError::TransactionFetch(_) => {
                    (StatusCode::NOT_FOUND, "transaction not found".into())
                }
            },
        };
        output.into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::AppStateBuilder;
    use axum::extract::State;
    use mockall::predicate::eq;
    use nillion_chain_client::{transactions::TokenAmount, tx::PaymentTransaction};

    #[derive(Default)]
    struct Handler {
        builder: AppStateBuilder,
    }

    impl Handler {
        async fn invoke(self, request: ValidatePaymentRequest) -> Result<(), HandlerError> {
            let state = self.builder.build();
            let request = Json(request);
            handler(State(state), request).await.map(|r| r.0)
        }

        fn expect_tx_retrieve(
            &mut self,
            tx_hash: String,
            response: Result<PaymentTransaction, RetrieveError>,
        ) {
            self.builder
                .tx_retriever
                .expect_get()
                .with(eq(tx_hash))
                .return_once(move |_| response);
        }
    }

    #[tokio::test]
    async fn validate_valid_payment() {
        let tx_hash = "0xdeadbeef".to_string();
        let mut handler = Handler::default();
        let payload = Payload {
            nonce: rand::random(),
            service_public_key: handler.builder.public_key(),
        };
        let payload = serde_json::to_vec(&payload).expect("failed to serialize");
        let payload_hash = Sha256::digest(&payload);
        handler.expect_tx_retrieve(
            tx_hash.clone(),
            Ok(PaymentTransaction {
                resource: payload_hash.to_vec(),
                from_address: "".into(),
                amount: TokenAmount::Unil(1),
            }),
        );
        handler
            .invoke(ValidatePaymentRequest { tx_hash, payload })
            .await
            .expect("request failed");
    }

    #[tokio::test]
    async fn validate_invalid_hash_payment() {
        let tx_hash = "0xdeadbeef".to_string();
        let mut handler = Handler::default();
        let payload = Payload {
            nonce: rand::random(),
            service_public_key: handler.builder.public_key(),
        };
        let payload = serde_json::to_vec(&payload).expect("failed to serialize");
        let payload_hash = Sha256::digest(b"hi mom");
        handler.expect_tx_retrieve(
            tx_hash.clone(),
            Ok(PaymentTransaction {
                resource: payload_hash.to_vec(),
                from_address: "".into(),
                amount: TokenAmount::Unil(1),
            }),
        );
        let err = handler
            .invoke(ValidatePaymentRequest { tx_hash, payload })
            .await
            .expect_err("request succeeded");
        assert!(matches!(err, HandlerError::HashMismatch));
    }

    #[tokio::test]
    async fn validate_tx_hash_not_found() {
        let tx_hash = "0xdeadbeef".to_string();
        let mut handler = Handler::default();
        let payload = Payload {
            nonce: rand::random(),
            service_public_key: handler.builder.public_key(),
        };
        let payload = serde_json::to_vec(&payload).expect("failed to serialize");
        handler.expect_tx_retrieve(tx_hash.clone(), Err(RetrieveError::NotCommitted));
        let err = handler
            .invoke(ValidatePaymentRequest { tx_hash, payload })
            .await
            .expect_err("request succeeded");
        assert!(matches!(err, HandlerError::RetrieveTransaction(_)));
    }
}
