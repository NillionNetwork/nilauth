use super::PostgresPool;
use crate::config::SubscriptionConfig;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use nillion_nucs::did::Did;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use std::fmt;
use tracing::{error, info};
use utoipa::ToSchema;

/// Details of an Ethereum payment to be recorded in the database.
pub(crate) struct PaymentRecord {
    pub tx_hash: String,
    pub chain_id: u64,
    pub amount_wei: String,
    pub digest: String,
    pub payer_address: String,
    pub service_public_key: String,
    pub blind_module: BlindModule,
    pub payer_did: Did,
    pub subscriber_did: Did,
}

/// An interface for managing user subscriptions in the database.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub(crate) trait SubscriptionDb: Send + Sync + 'static {
    /// Finds the expiration timestamp for a given subscriber and blind module.
    ///
    /// Returns `Ok(Some(DateTime<Utc>))` if a subscription exists, or `Ok(None)` if not.
    async fn find_subscription_end(
        &self,
        subscriber_did: &Did,
        blind_module: &BlindModule,
    ) -> sqlx::Result<Option<DateTime<Utc>>>;

    /// Credits a payment to a subscriber, extending their subscription period.
    ///
    /// This operation is transactional and idempotent based on the `tx_hash`.
    /// It will fail if the subscription is not yet within its renewable window.
    async fn credit_payment(&self, payment: PaymentRecord) -> Result<(), CreditPaymentError>;

    /// Stores a record of an invalid payment attempt.
    ///
    /// This is used to prevent replay attacks with invalid payloads.
    async fn store_invalid_payment(&self, payment: PaymentRecord) -> sqlx::Result<()>;
}

/// The Nillion blind compute modules that require a subscription.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum BlindModule {
    NilAi,
    NilDb,
}

impl fmt::Display for BlindModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NilDb => write!(f, "nildb"),
            Self::NilAi => write!(f, "nilai"),
        }
    }
}

/// A Postgres implementation of the `SubscriptionDb` trait.
pub(crate) struct PostgresSubscriptionDb {
    pool: PostgresPool,
    config: SubscriptionConfig,
}

impl PostgresSubscriptionDb {
    pub(crate) fn new(pool: PostgresPool, config: SubscriptionConfig) -> Self {
        Self { pool, config }
    }

    async fn find_subscription_end_for_update(
        &self,
        subscriber_did: &str,
        blind_module: &str,
        conn: &mut PgConnection,
    ) -> sqlx::Result<Option<DateTime<Utc>>> {
        let row = sqlx::query!(
            "SELECT ends_at FROM subscriptions WHERE subscriber_did = $1 AND blind_module = $2 FOR UPDATE",
            subscriber_did,
            blind_module
        )
        .fetch_optional(&mut *conn)
        .await?;
        Ok(row.map(|r| r.ends_at))
    }
}

#[async_trait]
impl SubscriptionDb for PostgresSubscriptionDb {
    async fn find_subscription_end(
        &self,
        subscriber_did: &Did,
        blind_module: &BlindModule,
    ) -> sqlx::Result<Option<DateTime<Utc>>> {
        let subscriber_did_str = subscriber_did.to_string();
        let blind_module_str = blind_module.to_string();
        let row = sqlx::query!(
            "SELECT ends_at FROM subscriptions WHERE subscriber_did = $1 AND blind_module = $2",
            subscriber_did_str,
            blind_module_str
        )
        .fetch_optional(&self.pool.0)
        .await?;
        Ok(row.map(|r| r.ends_at))
    }

    async fn credit_payment(&self, payment: PaymentRecord) -> Result<(), CreditPaymentError> {
        let mut tx = self.pool.0.begin().await?;
        let subscriber_did_str = payment.subscriber_did.to_string();
        let blind_module_str = payment.blind_module.to_string();
        let subscription_ends_at =
            self.find_subscription_end_for_update(&subscriber_did_str, &blind_module_str, &mut *tx).await?;
        if let Some(ends_at) = subscription_ends_at
            && ends_at > Utc::now() + self.config.renewal_threshold
        {
            info!("Subscription can't be renewed because it ends at {ends_at}");
            return Err(CreditPaymentError::CannotRenewYet);
        }

        let payer_did_str = payment.payer_did.to_string();
        sqlx::query!(
            r#"INSERT INTO payments (tx_hash, chain_id, amount_wei, digest, payer_address, service_public_key, blind_module, payer_did, subscriber_did, is_valid)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true)"#,
            payment.tx_hash,
            payment.chain_id as i64,
            payment.amount_wei,
            payment.digest,
            payment.payer_address,
            payment.service_public_key,
            blind_module_str,
            payer_did_str,
            subscriber_did_str
        )
        .execute(&mut *tx)
        .await?;

        // Try to extend it if it's not there yet
        let default_ends_at = Utc::now() + self.config.length;
        let ends_at = subscription_ends_at
            .map(|ends_at| ends_at + self.config.length)
            .unwrap_or(default_ends_at)
            .max(default_ends_at);
        sqlx::query!(
            r#"INSERT INTO subscriptions (subscriber_did, blind_module, ends_at) VALUES ($1, $2, $3)
            ON CONFLICT(subscriber_did, blind_module) DO UPDATE SET ends_at = $3"#,
            subscriber_did_str,
            blind_module_str,
            ends_at
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn store_invalid_payment(&self, payment: PaymentRecord) -> sqlx::Result<()> {
        let subscriber_did_str = payment.subscriber_did.to_string();
        let payer_did_str = payment.payer_did.to_string();
        let blind_module_str = payment.blind_module.to_string();
        sqlx::query!(
            r#"INSERT INTO payments (tx_hash, chain_id, amount_wei, digest, payer_address, service_public_key, blind_module, payer_did, subscriber_did, is_valid)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false)"#,
            payment.tx_hash,
            payment.chain_id as i64,
            payment.amount_wei,
            payment.digest,
            payment.payer_address,
            payment.service_public_key,
            blind_module_str,
            payer_did_str,
            subscriber_did_str
        )
        .execute(&self.pool.0)
        .await?;
        Ok(())
    }
}

/// An error that can occur when attempting to credit a payment.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CreditPaymentError {
    #[error("duplicate key")]
    DuplicateKey,

    #[error("database error")]
    Database,

    #[error("subscription can't be renewed yet")]
    CannotRenewYet,
}

impl From<sqlx::Error> for CreditPaymentError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::Database(e) if e.is_unique_violation() => Self::DuplicateKey,
            _ => {
                error!("Query execution failed: {e}");
                Self::Database
            }
        }
    }
}
