use crate::{db::account::CreditPaymentError, state::SharedState};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use nillion_chain_client::tx::RetrieveError;
use nillion_nucs::k256::{
    sha2::{Digest, Sha256},
    PublicKey,
};
use serde::{Deserialize, Serialize};
use tracing::error;

#[derive(Deserialize)]
pub(crate) struct ValidatePaymentRequest {
    tx_hash: String,

    #[serde(deserialize_with = "hex::serde::deserialize")]
    payload: Vec<u8>,

    #[serde(deserialize_with = "hex::serde::deserialize")]
    public_key: [u8; 33],
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
    Json(request): Json<ValidatePaymentRequest>,
) -> Result<Json<()>, HandlerError> {
    let public_key = PublicKey::from_sec1_bytes(&request.public_key)
        .map_err(|_| HandlerError::InvalidPublicKey)?;
    let decoded_payload: Payload = serde_json::from_slice(&request.payload)
        .map_err(|e| HandlerError::MalformedPayload(e.to_string()))?;
    if decoded_payload.service_public_key != *state.secret_key.public_key().to_sec1_bytes() {
        return Err(HandlerError::UnknownPublicKey);
    }

    let tx_hash = request.tx_hash;
    let tx = state
        .services
        .tx
        .get(&tx_hash)
        .await
        .map_err(HandlerError::RetrieveTransaction)?;
    let payload_hash = Sha256::digest(&request.payload);
    if tx.resource != payload_hash.as_slice() {
        if let Err(e) = state
            .databases
            .accounts
            .store_invalid_payment(&tx_hash, public_key)
            .await
        {
            error!("Failed to store invalid payment with tx hash {tx_hash}: {e}");
        }
        return Err(HandlerError::HashMismatch);
    }

    state
        .databases
        .accounts
        .credit_payment(&tx_hash, public_key)
        .await
        .map_err(HandlerError::CreditPayment)?;
    Ok(Json(()))
}

#[derive(Debug)]
pub(crate) enum HandlerError {
    CreditPayment(CreditPaymentError),
    HashMismatch,
    InvalidPublicKey,
    MalformedPayload(String),
    UnknownPublicKey,
    RetrieveTransaction(RetrieveError),
}

impl IntoResponse for HandlerError {
    fn into_response(self) -> Response {
        let output = match self {
            Self::CreditPayment(CreditPaymentError::Database) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
            }
            Self::CreditPayment(e) => (
                StatusCode::PRECONDITION_FAILED,
                format!("failed to credit payment: {e}"),
            ),
            Self::HashMismatch => (
                StatusCode::BAD_REQUEST,
                "payload hash does not match transaction nonce".into(),
            ),
            Self::InvalidPublicKey => (
                StatusCode::BAD_REQUEST,
                "invalid public key in request".into(),
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
    use crate::tests::{random_public_key, AppStateBuilder, PublicKeyExt};
    use axum::extract::State;
    use mockall::predicate::eq;
    use nillion_chain_client::{transactions::TokenAmount, tx::PaymentTransaction};
    use nillion_nucs::k256::SecretKey;

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

        let public_key = SecretKey::random(&mut rand::thread_rng()).public_key();
        handler
            .builder
            .account_db
            .expect_credit_payment()
            .with(eq(tx_hash.clone()), eq(public_key.clone()))
            .return_once(move |_, _| Ok(()));
        handler
            .invoke(ValidatePaymentRequest {
                tx_hash,
                payload,
                public_key: public_key.to_bytes(),
            })
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
        let public_key = SecretKey::random(&mut rand::thread_rng()).public_key();
        handler.expect_tx_retrieve(
            tx_hash.clone(),
            Ok(PaymentTransaction {
                resource: payload_hash.to_vec(),
                from_address: "".into(),
                amount: TokenAmount::Unil(1),
            }),
        );

        handler
            .builder
            .account_db
            .expect_store_invalid_payment()
            .with(eq(tx_hash.clone()), eq(public_key.clone()))
            .return_once(|_, _| Ok(()));
        let err = handler
            .invoke(ValidatePaymentRequest {
                tx_hash,
                payload,
                public_key: public_key.to_bytes(),
            })
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
            .invoke(ValidatePaymentRequest {
                tx_hash,
                payload,
                public_key: random_public_key(),
            })
            .await
            .expect_err("request succeeded");
        assert!(matches!(err, HandlerError::RetrieveTransaction(_)));
    }
}
