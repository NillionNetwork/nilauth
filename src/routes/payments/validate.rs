use crate::db::subscriptions::BlindModule;
use crate::routes::Json;
use crate::{
    db::subscriptions::CreditPaymentError, routes::RequestHandlerError, state::SharedState,
};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use metrics::counter;
use nilauth_client::nilchain_client::tx::RetrieveError;
use nillion_nucs::k256::{
    sha2::{Digest, Sha256},
    PublicKey,
};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use strum::EnumDiscriminants;
use tracing::{error, info, warn};
use utoipa::ToSchema;

/// A request to validate a payment.
#[derive(Deserialize, ToSchema)]
pub(crate) struct ValidatePaymentRequest {
    /// The transaction hash that contains proof of this payment.
    #[schema(examples("f7512550e93528be609eb2410b1d31aa4062e95a83a35f86800edbf1b1b7a51c"))]
    tx_hash: String,

    /// The payload in hex-encoded form.
    #[serde(with = "hex::serde")]
    #[schema(value_type = String, examples(crate::docs::hex_payload))]
    payload: Vec<u8>,

    /// The public key for the user the subscription is for, in hex form.
    #[serde(with = "hex::serde")]
    #[schema(value_type = String, examples(crate::docs::public_key))]
    public_key: [u8; 33],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    #[allow(dead_code)]
    #[serde(with = "hex::serde")]
    nonce: [u8; 16],

    #[serde(with = "hex::serde")]
    service_public_key: Vec<u8>,

    blind_module: BlindModule,
}

/// Validate a subscription payment.
#[utoipa::path(
    post,
    path = "/payments/validate",
    responses(
        (status = OK, body = ()),
        (status = 400, body = RequestHandlerError),
        (status = 412, body = RequestHandlerError),
    )
)]
pub(crate) async fn handler(
    state: SharedState,
    Json(request): Json<ValidatePaymentRequest>,
) -> Result<Json<()>, HandlerError> {
    let public_key = PublicKey::from_sec1_bytes(&request.public_key)
        .map_err(|_| HandlerError::InvalidPublicKey)?;
    let decoded_payload: Payload = serde_json::from_slice(&request.payload)
        .map_err(|e| HandlerError::MalformedPayload(e.to_string()))?;
    if decoded_payload.service_public_key
        != *state.parameters.secret_key.public_key().to_sec1_bytes()
    {
        return Err(HandlerError::UnknownPublicKey);
    }

    // Make sure the client has proven they made the transaction
    let tx_hash = request.tx_hash;
    let tx = state.services.tx.get(&tx_hash).await?;
    let payload_hash = Sha256::digest(&request.payload);
    if tx.resource != payload_hash.as_slice() {
        store_invalid_payment(&state, &tx_hash, public_key).await;
        counter!("invalid_payments_total", "reason" => "hash").increment(1);
        return Err(HandlerError::HashMismatch);
    }
    // Make sure they paid enough
    let blind_module = decoded_payload.blind_module;
    match state
        .services
        .subscription_cost
        .blind_module_cost(blind_module)
        .await
    {
        Ok(cost_unils) => {
            let unil_paid = Decimal::from(tx.amount.to_unil());
            let minimum_payment = Decimal::from(cost_unils)
                * (Decimal::from(1) - state.parameters.subscription_cost_slippage);
            if unil_paid < minimum_payment {
                warn!("Expected payment for {minimum_payment} but got {unil_paid} unils");
                counter!("invalid_payments_total", "reason" => "underpaid").increment(1);
                return Err(HandlerError::InsufficientPayment);
            }
            counter!("payments_valid_total", "module" => blind_module.to_string()).increment(1);
            info!("Processed payment for {unil_paid}unil, minimum was {minimum_payment}");
        }
        Err(_) => {
            error!("Can't process transaction because we can't fetch subscription cost");
            return Err(HandlerError::Internal);
        }
    };

    state
        .databases
        .subscriptions
        .credit_payment(&tx_hash, public_key, &blind_module)
        .await?;
    Ok(Json(()))
}

async fn store_invalid_payment(state: &SharedState, tx_hash: &str, public_key: PublicKey) {
    let result = state
        .databases
        .subscriptions
        .store_invalid_payment(tx_hash, public_key)
        .await;
    match result {
        Ok(_) => (),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            info!("Invalid transaction {tx_hash} was already processed, ignoring")
        }
        Err(e) => {
            error!("Failed to store invalid payment with tx hash {tx_hash}: {e}")
        }
    };
}

#[derive(Debug, EnumDiscriminants)]
pub(crate) enum HandlerError {
    CannotRenewYet,
    HashMismatch,
    InsufficientPayment,
    Internal,
    InvalidPublicKey,
    MalformedPayload(String),
    MalformedTransaction,
    PaymentAlreadyProcessed,
    TransactionLookup,
    TransactionNotCommitted,
    UnknownPublicKey,
}

impl From<RetrieveError> for HandlerError {
    fn from(e: RetrieveError) -> Self {
        match e {
            RetrieveError::NotCommitted => Self::TransactionNotCommitted,
            RetrieveError::Malformed(_) => Self::MalformedTransaction,
            RetrieveError::TransactionFetch(_) => Self::TransactionLookup,
        }
    }
}

impl From<CreditPaymentError> for HandlerError {
    fn from(e: CreditPaymentError) -> Self {
        match e {
            CreditPaymentError::DuplicateKey => Self::PaymentAlreadyProcessed,
            CreditPaymentError::Database => Self::Internal,
            CreditPaymentError::CannotRenewYet => Self::CannotRenewYet,
        }
    }
}

impl IntoResponse for HandlerError {
    fn into_response(self) -> Response {
        let discriminant = HandlerErrorDiscriminants::from(&self);
        let (code, message) = match self {
            Self::CannotRenewYet => (
                StatusCode::PRECONDITION_FAILED,
                "cannot renew subscription yet".into(),
            ),
            Self::PaymentAlreadyProcessed => (
                StatusCode::PRECONDITION_FAILED,
                "payment transaction already processed".into(),
            ),
            Self::HashMismatch => (
                StatusCode::BAD_REQUEST,
                "payload hash does not match transaction nonce".into(),
            ),
            Self::InvalidPublicKey => (
                StatusCode::BAD_REQUEST,
                "invalid public key in request".into(),
            ),
            Self::InsufficientPayment => (
                StatusCode::PRECONDITION_FAILED,
                "insufficient payment".into(),
            ),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into()),
            Self::MalformedPayload(reason) => (
                StatusCode::BAD_REQUEST,
                format!("malformed payload: {reason}"),
            ),
            Self::UnknownPublicKey => (
                StatusCode::BAD_REQUEST,
                "payload public key is different from ours".into(),
            ),
            Self::TransactionNotCommitted => (
                StatusCode::PRECONDITION_FAILED,
                "transaction is not yet committed".into(),
            ),
            Self::MalformedTransaction => (
                StatusCode::BAD_REQUEST,
                "transaction payload is malformed".into(),
            ),
            Self::TransactionLookup => (StatusCode::NOT_FOUND, "transaction not found".into()),
        };
        let response = RequestHandlerError::new(message, format!("{discriminant:?}"));
        (code, Json(response)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{random_public_key, AppStateBuilder, PublicKeyExt};
    use axum::extract::State;
    use mockall::predicate::eq;
    use nilauth_client::nilchain_client::{transactions::TokenAmount, tx::PaymentTransaction};
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
        let blind_module = BlindModule::NilDb;
        let payload = Payload {
            nonce: rand::random(),
            service_public_key: handler.builder.public_key(),
            blind_module,
        };
        let payload = serde_json::to_vec(&payload).expect("failed to serialize");
        let payload_hash = Sha256::digest(&payload);
        handler.expect_tx_retrieve(
            tx_hash.clone(),
            Ok(PaymentTransaction {
                resource: payload_hash.to_vec(),
                from_address: "".into(),
                // Pay 99% of the cost
                amount: TokenAmount::Unil(990_000),
            }),
        );

        let public_key = SecretKey::random(&mut rand::thread_rng()).public_key();
        handler
            .builder
            .subscriptions_db
            .expect_credit_payment()
            .with(
                eq(tx_hash.clone()),
                eq(public_key.clone()),
                eq(blind_module),
            )
            .return_once(move |_, _, _| Ok(()));
        handler
            .builder
            .subscription_costs_service
            .expect_blind_module_cost()
            .with(eq(blind_module))
            .return_once(|_| Ok(1));
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
    async fn validate_underpayment() {
        let tx_hash = "0xdeadbeef".to_string();
        let mut handler = Handler::default();
        let blind_module = BlindModule::NilDb;
        let payload = Payload {
            nonce: rand::random(),
            service_public_key: handler.builder.public_key(),
            blind_module,
        };
        let payload = serde_json::to_vec(&payload).expect("failed to serialize");
        let payload_hash = Sha256::digest(&payload);
        handler.expect_tx_retrieve(
            tx_hash.clone(),
            Ok(PaymentTransaction {
                resource: payload_hash.to_vec(),
                from_address: "".into(),
                // Pay one unil less than 99% of the cost
                amount: TokenAmount::Unil(989_999),
            }),
        );

        let public_key = SecretKey::random(&mut rand::thread_rng()).public_key();
        handler
            .builder
            .subscription_costs_service
            .expect_blind_module_cost()
            .with(eq(blind_module))
            .return_once(|_| Ok(1_000_000));
        handler
            .invoke(ValidatePaymentRequest {
                tx_hash,
                payload,
                public_key: public_key.to_bytes(),
            })
            .await
            .expect_err("request succeeded");
    }

    #[tokio::test]
    async fn validate_invalid_hash_payment() {
        let tx_hash = "0xdeadbeef".to_string();
        let mut handler = Handler::default();
        let payload = Payload {
            nonce: rand::random(),
            service_public_key: handler.builder.public_key(),
            blind_module: BlindModule::NilDb,
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
            .subscriptions_db
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
            blind_module: BlindModule::NilDb,
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
        assert!(matches!(err, HandlerError::TransactionNotCommitted));
    }
}
