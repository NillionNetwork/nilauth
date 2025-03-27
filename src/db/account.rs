use super::PostgresPool;
use crate::config::SubscriptionConfig;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hex::ToHex;
use nillion_nucs::k256::PublicKey;
use sqlx::{prelude::FromRow, query, query_as, Executor, Postgres};
use std::ops::DerefMut;
use tracing::{error, info};

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub(crate) trait AccountDb: Send + Sync + 'static {
    async fn find_subscription_end(
        &self,
        public_key: &PublicKey,
    ) -> sqlx::Result<Option<DateTime<Utc>>>;

    async fn credit_payment(
        &self,
        tx_hash: &str,
        public_key: PublicKey,
    ) -> Result<(), CreditPaymentError>;

    async fn store_invalid_payment(&self, tx_hash: &str, public_key: PublicKey)
        -> sqlx::Result<()>;
}

pub(crate) struct PostgresAccountDb {
    pool: PostgresPool,
    config: SubscriptionConfig,
}

impl PostgresAccountDb {
    pub(crate) fn new(pool: PostgresPool, config: SubscriptionConfig) -> Self {
        Self { pool, config }
    }

    async fn do_find_subscription_end<'a, E>(
        &self,
        public_key: &PublicKey,
        executor: E,
        for_update: bool,
    ) -> sqlx::Result<Option<DateTime<Utc>>>
    where
        E: Executor<'a, Database = Postgres>,
    {
        #[derive(FromRow)]
        struct Row {
            ends_at: DateTime<Utc>,
        }
        let public_key: String = public_key.to_sec1_bytes().encode_hex();
        let for_update_suffix = if for_update { " FOR UPDATE" } else { "" };
        let row: Option<Row> = query_as(&format!(
            "SELECT ends_at FROM subscriptions WHERE public_key = $1{for_update_suffix}"
        ))
        .bind(&public_key)
        .fetch_optional(executor)
        .await?;
        Ok(row.map(|r| r.ends_at))
    }
}

#[async_trait]
impl AccountDb for PostgresAccountDb {
    async fn find_subscription_end(
        &self,
        public_key: &PublicKey,
    ) -> sqlx::Result<Option<DateTime<Utc>>> {
        self.do_find_subscription_end(public_key, &self.pool.0, false)
            .await
    }

    async fn credit_payment(
        &self,
        tx_hash: &str,
        public_key: PublicKey,
    ) -> Result<(), CreditPaymentError> {
        let mut tx = self.pool.0.begin().await?;
        let subscription_ends_at = self
            .do_find_subscription_end(&public_key, tx.deref_mut(), true)
            .await?;
        if let Some(ends_at) = subscription_ends_at {
            if ends_at > Utc::now() + self.config.renewal_threshold {
                info!("Subscription can't be renewed because it ends at {ends_at}");
                return Err(CreditPaymentError::CannotRenewYet);
            }
        }

        let public_key: String = public_key.to_sec1_bytes().encode_hex();
        query("INSERT INTO payments (tx_hash, subscription_public_key, is_valid) VALUES ($1, $2, true)")
            .bind(tx_hash)
            .bind(&public_key)
            .execute(tx.deref_mut())
            .await?;

        // Try to extend it if it's not there yet
        let default_ends_at = Utc::now() + self.config.length;
        let ends_at = subscription_ends_at
            .map(|ends_at| ends_at + self.config.length)
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
    ) -> sqlx::Result<()> {
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
