use crate::auth::IdentityNuc;
use crate::db::subscriptions::BlindModule;
use crate::routes::Json;
use crate::{db::subscriptions::CreditPaymentError, routes::RequestHandlerError, state::SharedState};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use metrics::counter;
use nilauth_client::nilchain_client::tx::RetrieveError;
use nillion_nucs::did::Did;
use nillion_nucs::k256::sha2::{Digest, Sha256};
use nillion_nucs::token::Command;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use strum::EnumDiscriminants;
use tracing::{error, info, warn};
use utoipa::ToSchema;

/// The plaintext payload that is hashed and stored on-chain.
#[derive(Serialize, Deserialize, Clone, ToSchema)]
#[serde(deny_unknown_fields)]
struct OnChainPaymentPayload {
    /// The public key of the nilauth service this payment is for.
    #[serde(with = "hex::serde")]
    #[schema(value_type = String)]
    service_public_key: [u8; 33],
    /// A random value to ensure the hash of this payload is unique
    #[serde(with = "hex::serde")]
    #[schema(value_type = String)]
    nonce: [u8; 16],
    /// The nillion blind module
    /// being subscribe to.
    blind_module: BlindModule,
    /// The user paying for the subscription.
    #[schema(value_type = String)]
    payer_did: Did,
    /// The user the subscription is for.
    #[schema(value_type = String)]
    subscriber_did: Did,
}

/// A request to validate a payment.
#[derive(Deserialize, ToSchema)]
pub(crate) struct ValidatePaymentRequest {
    /// The transaction hash that contains proof of this payment.
    tx_hash: String,
    /// The full, unhashed payload that was committed to the chain.
    payload: OnChainPaymentPayload,
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
    auth: IdentityNuc,
    Json(request): Json<ValidatePaymentRequest>,
) -> Result<Json<()>, HandlerError> {
    // Validate command scope
    let expected_command: Command = ["nil", "auth", "payments", "validate"].into();
    if auth.0.token.command != expected_command {
        return Err(HandlerError::InvalidCommand(expected_command));
    }

    // Verify that the Nuc subject matches the payload payer
    if auth.0.token.subject != request.payload.payer_did {
        return Err(HandlerError::PayerMismatch);
    }

    // Serialize the payload for hashing
    let payload_bytes =
        serde_json::to_vec(&request.payload).map_err(|e| HandlerError::MalformedPayload(e.to_string()))?;

    if request.payload.service_public_key != state.parameters.public_key {
        return Err(HandlerError::UnknownPublicKey);
    }

    // Verify the received payload hash matches the on-chain resource hash
    let tx_hash = request.tx_hash.to_lowercase();
    let tx = state.services.tx.get(&tx_hash).await?;
    let payload_hash = Sha256::digest(&payload_bytes);

    #[allow(deprecated)]
    if tx.resource != payload_hash.as_slice() {
        store_invalid_payment(&state, &tx_hash, &request.payload.subscriber_did).await;
        counter!("invalid_payments_total", "reason" => "hash").increment(1);
        return Err(HandlerError::HashMismatch);
    }

    // Ensure payment is sufficient
    let blind_module = request.payload.blind_module;
    match state.services.subscription_cost.blind_module_cost(blind_module).await {
        Ok(cost_unils) => {
            let unil_paid = Decimal::from(tx.amount.to_unil());
            let minimum_payment =
                Decimal::from(cost_unils) * (Decimal::from(1) - state.parameters.subscription_cost_slippage);
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

    // Credit the payment to the subscriber identified *in the payload*
    state.databases.subscriptions.credit_payment(&tx_hash, &request.payload.subscriber_did, &blind_module).await?;
    Ok(Json(()))
}

async fn store_invalid_payment(state: &SharedState, tx_hash: &str, subscriber_did: &Did) {
    let result = state.databases.subscriptions.store_invalid_payment(tx_hash, subscriber_did).await;
    if let Err(sqlx::Error::Database(e)) = result {
        if e.is_unique_violation() {
            info!("Invalid transaction {tx_hash} was already processed, ignoring");
        } else {
            error!("Failed to store invalid payment with tx hash {tx_hash}: {e}");
        }
    }
}

#[derive(Debug, EnumDiscriminants)]
pub(crate) enum HandlerError {
    CannotRenewYet,
    HashMismatch,
    InsufficientPayment,
    Internal,
    InvalidCommand(Command),
    MalformedPayload(String),
    MalformedTransaction,
    PaymentAlreadyProcessed,
    PayerMismatch,
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
            Self::CannotRenewYet => (StatusCode::PRECONDITION_FAILED, "cannot renew subscription yet".into()),
            Self::PaymentAlreadyProcessed => {
                (StatusCode::PRECONDITION_FAILED, "payment transaction already processed".into())
            }
            Self::HashMismatch => (StatusCode::BAD_REQUEST, "payload hash does not match transaction nonce".into()),
            Self::InsufficientPayment => (StatusCode::PRECONDITION_FAILED, "insufficient payment".into()),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into()),
            Self::InvalidCommand(expected) => {
                (StatusCode::UNAUTHORIZED, format!("invalid command for identity token, expected '{expected}'"))
            }
            Self::MalformedPayload(reason) => (StatusCode::BAD_REQUEST, format!("malformed payload: {reason}")),
            Self::UnknownPublicKey => (StatusCode::BAD_REQUEST, "payload public key is different from ours".into()),
            Self::TransactionNotCommitted => {
                (StatusCode::PRECONDITION_FAILED, "transaction is not yet committed".into())
            }
            Self::MalformedTransaction => (StatusCode::BAD_REQUEST, "transaction payload is malformed".into()),
            Self::PayerMismatch => {
                (StatusCode::BAD_REQUEST, "authenticated user does not match payer in payload".into())
            }
            Self::TransactionLookup => (StatusCode::NOT_FOUND, "transaction not found".into()),
        };
        let response = RequestHandlerError::new(message, format!("{discriminant:?}"));
        (code, Json(response)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{AppStateBuilder, random_public_key};
    use axum::extract::State;
    use mockall::predicate::eq;
    use nilauth_client::nilchain_client::{transactions::TokenAmount, tx::PaymentTransaction};

    #[derive(Default)]
    struct Handler {
        builder: AppStateBuilder,
    }

    impl Handler {
        async fn invoke(self, request: ValidatePaymentRequest) -> Result<(), HandlerError> {
            let state = self.builder.build();
            let auth = IdentityNuc(nillion_nucs::validator::ValidatedNucToken {
                token: nillion_nucs::token::NucToken {
                    issuer: request.payload.payer_did,
                    audience: state.parameters.did,
                    subject: request.payload.payer_did,
                    not_before: None,
                    expires_at: None,
                    command: ["nil", "auth", "payments", "validate"].into(),
                    body: nillion_nucs::token::TokenBody::Invocation(Default::default()),
                    meta: None,
                    nonce: vec![],
                    proofs: vec![],
                },
                proofs: vec![],
            });
            handler(State(state), auth, Json(request)).await.map(|_| ())
        }

        fn expect_tx_retrieve(&mut self, tx_hash: String, response: Result<PaymentTransaction, RetrieveError>) {
            self.builder.tx_retriever.expect_get().with(eq(tx_hash)).return_once(move |_| response);
        }
    }

    #[tokio::test]
    async fn validate_valid_payment() {
        let tx_hash = "0xdeadbeef".to_string();
        let mut handler = Handler::default();
        let blind_module = BlindModule::NilDb;
        let payer_did = Did::key(random_public_key());
        let subscriber_did = Did::key(random_public_key());
        let payload = OnChainPaymentPayload {
            nonce: rand::random(),
            payer_did,
            subscriber_did,
            blind_module,
            service_public_key: handler.builder.public_key(),
        };
        let payload_bytes = serde_json::to_vec(&payload).expect("failed to serialize");
        let payload_hash = Sha256::digest(&payload_bytes);
        handler.expect_tx_retrieve(
            tx_hash.clone(),
            Ok(PaymentTransaction {
                resource: payload_hash.to_vec(),
                from_address: "".into(),
                amount: TokenAmount::Unil(990_000),
            }),
        );

        handler
            .builder
            .subscriptions_db
            .expect_credit_payment()
            .with(eq(tx_hash.clone()), eq(subscriber_did), eq(blind_module))
            .return_once(|_, _, _| Ok(()));
        handler
            .builder
            .subscription_costs_service
            .expect_blind_module_cost()
            .with(eq(blind_module))
            .return_once(|_| Ok(1_000_000));

        handler.invoke(ValidatePaymentRequest { tx_hash, payload }).await.expect("request failed");
    }

    #[tokio::test]
    async fn validate_underpayment() {
        let tx_hash = "0xdeadbeef".to_string();
        let mut handler = Handler::default();
        let blind_module = BlindModule::NilDb;
        let payer_did = Did::key(random_public_key());
        let subscriber_did = Did::key(random_public_key());
        let payload = OnChainPaymentPayload {
            nonce: rand::random(),
            payer_did,
            subscriber_did,
            blind_module,
            service_public_key: handler.builder.public_key(),
        };
        let payload_bytes = serde_json::to_vec(&payload).expect("failed to serialize");
        let payload_hash = Sha256::digest(&payload_bytes);
        handler.expect_tx_retrieve(
            tx_hash.clone(),
            Ok(PaymentTransaction {
                resource: payload_hash.to_vec(),
                from_address: "".into(),
                amount: TokenAmount::Unil(989_999), // Insufficient amount
            }),
        );

        handler
            .builder
            .subscription_costs_service
            .expect_blind_module_cost()
            .with(eq(blind_module))
            .return_once(|_| Ok(1_000_000));

        let err = handler.invoke(ValidatePaymentRequest { tx_hash, payload }).await.expect_err("request succeeded");
        assert!(matches!(err, HandlerError::InsufficientPayment));
    }
}
