use super::PostgresPool;
use crate::config::SubscriptionConfig;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use nillion_nucs::did::Did;
use serde::{Deserialize, Serialize};
use sqlx::{prelude::FromRow, query, query_as, Executor, Postgres};
use std::{fmt, ops::DerefMut};
use tracing::{error, info};
use utoipa::ToSchema;

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
    async fn credit_payment(
        &self,
        tx_hash: &str,
        subscriber_did: &Did,
        blind_module: &BlindModule,
    ) -> Result<(), CreditPaymentError>;

    /// Stores a record of an invalid payment attempt.
    ///
    /// This is used to prevent replay attacks with invalid payloads.
    async fn store_invalid_payment(&self, tx_hash: &str, subscriber_did: &Did) -> sqlx::Result<()>;
}

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

pub(crate) struct PostgresSubscriptionDb {
    pool: PostgresPool,
    config: SubscriptionConfig,
}

impl PostgresSubscriptionDb {
    pub(crate) fn new(pool: PostgresPool, config: SubscriptionConfig) -> Self {
        Self { pool, config }
    }

    async fn do_find_subscription_end<'a, E>(
        &self,
        subscriber_did: &Did,
        blind_module: &BlindModule,
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
        let subscriber_did_str = subscriber_did.to_string();
        let for_update_suffix = if for_update { " FOR UPDATE" } else { "" };
        let row: Option<Row> = query_as(&format!(
            "SELECT ends_at FROM subscriptions WHERE subscriber_did = $1 AND blind_module = $2{for_update_suffix}"
        ))
        .bind(&subscriber_did_str)
        .bind(blind_module.to_string())
        .fetch_optional(executor)
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
        self.do_find_subscription_end(subscriber_did, blind_module, &self.pool.0, false).await
    }

    async fn credit_payment(
        &self,
        tx_hash: &str,
        subscriber_did: &Did,
        blind_module: &BlindModule,
    ) -> Result<(), CreditPaymentError> {
        let mut tx = self.pool.0.begin().await?;
        let subscription_ends_at =
            self.do_find_subscription_end(subscriber_did, blind_module, tx.deref_mut(), true).await?;
        if let Some(ends_at) = subscription_ends_at {
            if ends_at > Utc::now() + self.config.renewal_threshold {
                info!("Subscription can't be renewed because it ends at {ends_at}");
                return Err(CreditPaymentError::CannotRenewYet);
            }
        }

        let subscriber_did_str = subscriber_did.to_string();
        query("INSERT INTO payments (tx_hash, subscriber_did, is_valid) VALUES ($1, $2, true)")
            .bind(tx_hash)
            .bind(&subscriber_did_str)
            .execute(tx.deref_mut())
            .await?;

        // Try to extend it if it's not there yet
        let default_ends_at = Utc::now() + self.config.length;
        let ends_at = subscription_ends_at
            .map(|ends_at| ends_at + self.config.length)
            .unwrap_or(default_ends_at)
            .max(default_ends_at);
        query("INSERT INTO subscriptions (subscriber_did, blind_module, ends_at) VALUES ($1, $2, $3) ON CONFLICT(subscriber_did, blind_module) DO UPDATE SET ends_at = $3")
            .bind(&subscriber_did_str)
            .bind(blind_module.to_string())
            .bind(ends_at)
            .execute(tx.deref_mut()).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn store_invalid_payment(&self, tx_hash: &str, subscriber_did: &Did) -> sqlx::Result<()> {
        let subscriber_did_str = subscriber_did.to_string();
        query("INSERT INTO payments (tx_hash, subscriber_did, is_valid) VALUES ($1, $2, false)")
            .bind(tx_hash)
            .bind(&subscriber_did_str)
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
