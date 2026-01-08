use crate::auth::IdentityNuc;
use crate::db::subscriptions::{BlindModule, PaymentRecord};
use crate::routes::Json;
use crate::services::ethereum_rpc::EthereumRpcError;
use crate::{db::subscriptions::CreditPaymentError, routes::RequestHandlerError, state::SharedState};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use metrics::counter;
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
    /// The nillion blind module being subscribed to.
    blind_module: BlindModule,
    /// The user paying for the subscription.
    #[schema(value_type = String)]
    payer_did: Did,
    /// The user the subscription is for.
    #[schema(value_type = String)]
    subscriber_did: Did,
    /// The Ethereum chain ID this payment was made on.
    chain_id: u64,
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

    // Verify chain ID in payload matches the configured chain
    if request.payload.chain_id != state.parameters.chain_id {
        return Err(HandlerError::ChainIdMismatch {
            expected: state.parameters.chain_id,
            actual: request.payload.chain_id,
        });
    }

    // Serialize the payload using RFC 8785 canonical JSON for consistent hashing
    let payload_bytes =
        serde_jcs::to_vec(&request.payload).map_err(|e| HandlerError::MalformedPayload(e.to_string()))?;

    if request.payload.service_public_key != state.parameters.public_key {
        return Err(HandlerError::UnknownPublicKey);
    }

    // Compute the expected digest from the payload
    let payload_hash = Sha256::digest(&payload_bytes);
    let expected_digest = format!("0x{}", hex::encode(payload_hash));

    // Query Ethereum for the burn event
    let tx_hash = request.tx_hash.to_lowercase();
    let event = state.services.ethereum_event_retriever.get_event_by_tx_hash(&tx_hash).await?;

    // Verify the event digest matches our computed digest
    let actual_digest = format!("0x{}", hex::encode(event.digest.as_slice()));
    let payer_address = format!("{:?}", event.payer);
    let service_public_key = hex::encode(request.payload.service_public_key);
    let amount_wei_str = event.amount.to_string();

    // Helper to build a PaymentRecord from the current context
    let make_payment_record = || PaymentRecord {
        tx_hash: tx_hash.clone(),
        chain_id: event.chain_id,
        amount_wei: amount_wei_str.clone(),
        digest: actual_digest.clone(),
        payer_address: payer_address.clone(),
        service_public_key: service_public_key.clone(),
        blind_module: request.payload.blind_module,
        payer_did: request.payload.payer_did,
        subscriber_did: request.payload.subscriber_did,
    };

    if actual_digest != expected_digest {
        store_invalid_payment(&state, make_payment_record()).await;
        counter!("invalid_payments_total", "reason" => "digest_mismatch").increment(1);
        return Err(HandlerError::DigestMismatch);
    }

    // Verify chain ID from event matches
    if event.chain_id != state.parameters.chain_id {
        warn!("Event chain ID {} does not match configured chain ID {}", event.chain_id, state.parameters.chain_id);
        counter!("invalid_payments_total", "reason" => "chain_id").increment(1);
        return Err(HandlerError::ChainIdMismatch { expected: state.parameters.chain_id, actual: event.chain_id });
    }

    // Ensure payment is sufficient
    let blind_module = request.payload.blind_module;
    match state.services.subscription_cost.blind_module_cost(blind_module).await {
        Ok(cost_unils) => {
            // The NIL token has 6 decimals, meaning 1 NIL = 1,000,000 smallest units.
            // We define 1 unil (micro-NIL) as 10^-6 NIL, which equals exactly 1 smallest unit.
            // Therefore, the on-chain amount is already in unils - no conversion needed.
            let amount_wei = event.amount.to::<u128>();
            let amount_unils = amount_wei; // 1 unil = 1 smallest token unit (6 decimals)

            let minimum_payment =
                Decimal::from(cost_unils) * (Decimal::from(1) - state.parameters.subscription_cost_slippage);

            if Decimal::from(amount_unils) < minimum_payment {
                warn!("Expected payment for {minimum_payment} but got {amount_unils} unils (from {amount_wei} wei)");
                counter!("invalid_payments_total", "reason" => "underpaid").increment(1);
                return Err(HandlerError::InsufficientPayment);
            }
            counter!("payments_valid_total", "module" => blind_module.to_string()).increment(1);
            info!("Processed payment for {amount_unils}unil ({amount_wei}wei), minimum was {minimum_payment}unil");
        }
        Err(_) => {
            error!("Can't process transaction because we can't fetch subscription cost");
            return Err(HandlerError::Internal);
        }
    };

    // Credit the payment to the subscriber identified *in the payload*
    state.databases.subscriptions.credit_payment(make_payment_record()).await?;
    Ok(Json(()))
}

async fn store_invalid_payment(state: &SharedState, payment: PaymentRecord) {
    let result = state.databases.subscriptions.store_invalid_payment(payment).await;
    if let Err(sqlx::Error::Database(e)) = result {
        if e.is_unique_violation() {
            info!("Invalid transaction was already processed, ignoring");
        } else {
            error!("Failed to store invalid payment: {e}");
        }
    }
}

#[derive(Debug, EnumDiscriminants)]
pub(crate) enum HandlerError {
    CannotRenewYet,
    ChainIdMismatch { expected: u64, actual: u64 },
    DigestMismatch,
    InsufficientPayment,
    Internal,
    InvalidCommand(Command),
    MalformedPayload(String),
    PaymentAlreadyProcessed,
    PayerMismatch,
    EthereumRpcError(String),
    UnknownPublicKey,
}

impl From<EthereumRpcError> for HandlerError {
    fn from(e: EthereumRpcError) -> Self {
        match e {
            EthereumRpcError::EventNotFound(tx) => {
                warn!("Event not found for transaction: {}", tx);
                Self::EthereumRpcError(format!("Event not found for transaction: {}", tx))
            }
            EthereumRpcError::InvalidLogData(msg) => {
                error!("Invalid log data: {}", msg);
                Self::EthereumRpcError(format!("Invalid log data: {}", msg))
            }
            e => {
                error!("Ethereum RPC error: {}", e);
                Self::EthereumRpcError(e.to_string())
            }
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
            Self::ChainIdMismatch { expected, actual } => {
                (StatusCode::BAD_REQUEST, format!("chain ID mismatch: expected {}, got {}", expected, actual))
            }
            Self::DigestMismatch => (StatusCode::BAD_REQUEST, "payload digest does not match event digest".into()),
            Self::InsufficientPayment => (StatusCode::PRECONDITION_FAILED, "insufficient payment".into()),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into()),
            Self::InvalidCommand(expected) => {
                (StatusCode::UNAUTHORIZED, format!("invalid command for identity token, expected '{expected}'"))
            }
            Self::MalformedPayload(reason) => (StatusCode::BAD_REQUEST, format!("malformed payload: {reason}")),
            Self::UnknownPublicKey => (StatusCode::BAD_REQUEST, "payload public key is different from ours".into()),
            Self::PayerMismatch => {
                (StatusCode::BAD_REQUEST, "authenticated user does not match payer in payload".into())
            }
            Self::EthereumRpcError(msg) => (StatusCode::BAD_REQUEST, format!("Ethereum RPC error: {}", msg)),
        };
        let response = RequestHandlerError::new(message, format!("{discriminant:?}"));
        (code, Json(response)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::ethereum_rpc::{BurnWithDigestEvent, EthereumRpcError};
    use crate::tests::{AppStateBuilder, random_public_key};
    use alloy::primitives::{Address, B256, U256};
    use axum::extract::State;
    use mockall::predicate::eq;

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

        fn expect_event_retrieve(&mut self, tx_hash: String, response: Result<BurnWithDigestEvent, EthereumRpcError>) {
            self.builder
                .ethereum_event_retriever
                .expect_get_event_by_tx_hash()
                .with(eq(tx_hash))
                .return_once(move |_| response);
        }
    }

    #[tokio::test]
    async fn validate_valid_payment() {
        let tx_hash = "0xdeadbeef".to_string();
        let mut handler = Handler::default();
        let blind_module = BlindModule::NilDb;
        let payer_did = Did::key(random_public_key());
        let subscriber_did = Did::key(random_public_key());
        let chain_id = 31337u64; // Anvil default

        let payload = OnChainPaymentPayload {
            nonce: rand::random(),
            payer_did,
            subscriber_did,
            blind_module,
            service_public_key: handler.builder.public_key(),
            chain_id,
        };
        let payload_bytes = serde_jcs::to_vec(&payload).expect("failed to serialize");
        let payload_hash = Sha256::digest(&payload_bytes);

        // NIL token has 6 decimals: 1 NIL = 1,000,000 smallest units = 1,000,000 unils
        // Since 1 unil = 1 smallest token unit, we pass the unil amount directly.
        let amount_unils = 1_000_000u128; // 1 NIL = 1,000,000 unils

        handler.expect_event_retrieve(
            tx_hash.clone(),
            Ok(BurnWithDigestEvent {
                payer: Address::ZERO,
                amount: U256::from(amount_unils),
                digest: B256::from_slice(payload_hash.as_ref()),
                timestamp: U256::from(1234567890u64),
                tx_hash: B256::ZERO,
                block_number: 100,
                log_index: 0,
                chain_id,
            }),
        );

        handler
            .builder
            .subscriptions_db
            .expect_credit_payment()
            .withf(move |p| {
                p.tx_hash == "0xdeadbeef" && p.subscriber_did == subscriber_did && p.blind_module == blind_module
            })
            .return_once(|_| Ok(()));
        handler
            .builder
            .subscription_costs_service
            .expect_blind_module_cost()
            .with(eq(blind_module))
            .return_once(|_| Ok(1_000_000)); // 1M unils

        handler.invoke(ValidatePaymentRequest { tx_hash, payload }).await.expect("request failed");
    }

    #[tokio::test]
    async fn validate_chain_id_mismatch() {
        let tx_hash = "0xdeadbeef".to_string();
        let handler = Handler::default();
        let blind_module = BlindModule::NilDb;
        let payer_did = Did::key(random_public_key());
        let subscriber_did = Did::key(random_public_key());

        // Payload says chain 1 (mainnet), but we're configured for chain 31337 (anvil)
        let payload = OnChainPaymentPayload {
            nonce: rand::random(),
            payer_did,
            subscriber_did,
            blind_module,
            service_public_key: handler.builder.public_key(),
            chain_id: 1, // Wrong chain!
        };

        let err = handler.invoke(ValidatePaymentRequest { tx_hash, payload }).await.expect_err("request succeeded");
        assert!(matches!(err, HandlerError::ChainIdMismatch { expected: 31337, actual: 1 }));
    }
}
