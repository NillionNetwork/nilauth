use super::PostgresPool;
use crate::config::SubscriptionConfig;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hex::ToHex;
use nillion_nucs::k256::PublicKey;
use sqlx::{prelude::FromRow, query, query_as};
use std::ops::DerefMut;
use tracing::{error, info};

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait AccountDb: Send + Sync + 'static {
    async fn credit_payment(
        &self,
        tx_hash: &str,
        public_key: PublicKey,
    ) -> Result<(), CreditPaymentError>;

    async fn store_invalid_payment(
        &self,
        tx_hash: &str,
        public_key: PublicKey,
    ) -> Result<(), sqlx::Error>;
}

pub struct PostgresAccountDb {
    pool: PostgresPool,
    config: SubscriptionConfig,
}

impl PostgresAccountDb {
    pub fn new(pool: PostgresPool, config: SubscriptionConfig) -> Self {
        Self { pool, config }
    }
}

#[async_trait]
impl AccountDb for PostgresAccountDb {
    async fn credit_payment(
        &self,
        tx_hash: &str,
        public_key: PublicKey,
    ) -> Result<(), CreditPaymentError> {
        #[derive(FromRow)]
        struct Row {
            ends_at: DateTime<Utc>,
        }
        let mut tx = self.pool.0.begin().await?;
        let public_key: String = public_key.to_sec1_bytes().encode_hex();
        let subscription: Option<Row> =
            query_as("SELECT ends_at FROM subscriptions WHERE public_key = $1 FOR UPDATE")
                .bind(&public_key)
                .fetch_optional(tx.deref_mut())
                .await?;
        if let Some(subscription) = &subscription {
            if subscription.ends_at > Utc::now() + self.config.renewal_threshold {
                info!(
                    "Subscription can't be renewed because it ends at {}",
                    subscription.ends_at
                );
                return Err(CreditPaymentError::CannotRenewYet);
            }
        }

        query("INSERT INTO payments (tx_hash, subscription_public_key, is_valid) VALUES ($1, $2, true)")
            .bind(tx_hash)
            .bind(&public_key)
            .execute(tx.deref_mut())
            .await?;

        // Try to extend it if it's not there yet
        let default_ends_at = Utc::now() + self.config.length;
        let ends_at = subscription
            .map(|s| s.ends_at + self.config.length)
            .unwrap_or(default_ends_at)
            .max(default_ends_at);
        query("INSERT INTO subscriptions (public_key, ends_at) VALUES ($1, $2) ON CONFLICT(public_key) DO UPDATE SET ends_at = $2")
            .bind(&public_key)
            .bind(ends_at)
            .execute(tx.deref_mut()).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn store_invalid_payment(
        &self,
        tx_hash: &str,
        public_key: PublicKey,
    ) -> Result<(), sqlx::Error> {
        let public_key: String = public_key.to_sec1_bytes().encode_hex();
        query("INSERT INTO payments (tx_hash, subscription_public_key, is_valid) VALUES ($1, $2, false)")
            .bind(tx_hash)
            .bind(&public_key)
            .execute(&self.pool.0)
            .await?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CreditPaymentError {
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
