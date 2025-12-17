use super::PostgresPool;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use nillion_nucs::token::ProofHash;
use serde::Serialize;
use tracing::error;
use utoipa::ToSchema;

/// An interface for managing token revocations in the database.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub(crate) trait RevocationDb: Send + Sync + 'static {
    /// Store a revocation for a given token hash.
    ///
    /// This operation is idempotent. If the token is already revoked, it succeeds silently.
    async fn store_revocation(
        &self,
        revocation: &ProofHash,
        expires_at: DateTime<Utc>,
    ) -> Result<(), StoreRevocationError>;

    /// Lookup which of the given token hashes have been revoked.
    async fn lookup_revocations(&self, hashes: &[ProofHash]) -> Result<Vec<RevokedToken>, LookupRevocationError>;

    /// Delete revoked tokens that expired before the given threshold.
    ///
    /// Returns the number of deleted records.
    async fn delete_expired(&self, threshold: DateTime<Utc>) -> Result<u64, sqlx::Error>;
}

/// An error when storing a revocation.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StoreRevocationError {
    #[error("already revoked")]
    AlreadyRevoked,

    #[error("database error")]
    Database,
}

impl From<sqlx::Error> for StoreRevocationError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::Database(e) if e.is_unique_violation() => Self::AlreadyRevoked,
            _ => {
                error!("Failed to store revocation: {e}");
                Self::Database
            }
        }
    }
}

/// An error when looking up a set of revocations.
#[derive(Debug, thiserror::Error)]
#[error("internal error")]
pub(crate) struct LookupRevocationError;

/// A Postgres implementation of the `RevocationDb` trait.
pub(crate) struct PostgresRevocationDb {
    pool: PostgresPool,
}

impl PostgresRevocationDb {
    /// Creates a new `PostgresRevocationDb`.
    pub fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RevocationDb for PostgresRevocationDb {
    async fn store_revocation(
        &self,
        revocation: &ProofHash,
        expires_at: DateTime<Utc>,
    ) -> Result<(), StoreRevocationError> {
        let token_hash = revocation.to_string();
        sqlx::query!("INSERT INTO revocations (token_hash, expires_at) VALUES ($1, $2)", token_hash, expires_at)
            .execute(&self.pool.0)
            .await?;
        Ok(())
    }

    async fn lookup_revocations(&self, hashes: &[ProofHash]) -> Result<Vec<RevokedToken>, LookupRevocationError> {
        if hashes.is_empty() {
            return Ok(Vec::new());
        }

        // Convert hashes to strings for the query
        let hash_strings: Vec<String> = hashes.iter().map(|h| h.to_string()).collect();

        let rows =
            sqlx::query!("SELECT token_hash, revoked_at FROM revocations WHERE token_hash = ANY($1)", &hash_strings)
                .fetch_all(&self.pool.0)
                .await
                .map_err(|e| {
                    error!("Failed to lookup revocations: {e}");
                    LookupRevocationError
                })?;

        let mut output = Vec::new();
        for row in rows {
            let token_hash = hex::decode(&row.token_hash).map_err(|_| {
                error!("Invalid hex public key in database: {}", row.token_hash);
                LookupRevocationError
            })?;
            output.push(RevokedToken { token_hash, revoked_at: row.revoked_at });
        }
        Ok(output)
    }

    async fn delete_expired(&self, threshold: DateTime<Utc>) -> Result<u64, sqlx::Error> {
        let result =
            sqlx::query!("DELETE FROM revocations WHERE expires_at < $1", threshold).execute(&self.pool.0).await?;
        Ok(result.rows_affected())
    }
}

/// A revoked token.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct RevokedToken {
    /// The token hash.
    #[serde(with = "hex::serde")]
    #[schema(value_type = String, examples(crate::docs::proof_hash))]
    pub(crate) token_hash: Vec<u8>,

    /// The timestamp at which the token was revoked.
    #[serde(with = "chrono::serde::ts_seconds")]
    #[schema(value_type = u64, examples(crate::docs::epoch_timestamp))]
    pub(crate) revoked_at: DateTime<Utc>,
}
