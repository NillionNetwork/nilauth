use crate::config::SubscriptionConfig;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hex::ToHex;
use nillion_nucs::k256::PublicKey;
use sqlx::{prelude::FromRow, query, query_as};
use std::ops::DerefMut;
use tracing::error;

use super::PostgresPool;

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait AccountDb: Send + Sync + 'static {
    async fn credit_payment(
        &self,
        tx_hash: String,
        account: PublicKey,
    ) -> Result<(), CreditPaymentError>;
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
        tx_hash: String,
        public_key: PublicKey,
    ) -> Result<(), CreditPaymentError> {
        let mut tx = self.pool.0.begin().await?;
        let public_key: String = public_key.to_sec1_bytes().encode_hex();
        let subscription: Option<Subscription> =
            query_as("SELECT * FROM subscriptions WHERE public_key = $1 FOR UPDATE")
                .bind(&public_key)
                .fetch_optional(tx.deref_mut())
                .await?;
        if let Some(subscription) = &subscription {
            if subscription.ends_at > Utc::now() + self.config.renewal_threshold {
                return Err(CreditPaymentError::CannotRenewYet);
            }
        }

        query("INSERT INTO payments (tx_hash, subscription_public_key) VALUES ($1, $2)")
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
}

#[derive(FromRow)]
struct Subscription {
    #[allow(dead_code)]
    public_key: String,
    ends_at: DateTime<Utc>,
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
