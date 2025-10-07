//! Database interaction logic, traits, and implementations.

use sqlx::{Pool, Postgres};
use tracing::info;

pub(crate) mod revocations;
pub(crate) mod subscriptions;

/// A newtype wrapper for a `sqlx::Pool<Postgres>` that runs migrations on creation.
#[derive(Clone)]
pub(crate) struct PostgresPool(Pool<Postgres>);

impl PostgresPool {
    /// Creates a new connection pool and runs pending database migrations.
    pub(crate) async fn new(url: &str) -> anyhow::Result<Self> {
        let pool = Pool::connect(url).await?;
        info!("Running migrations");
        sqlx::migrate!().run(&pool).await?;
        info!("Migrations ran successfully");
        Ok(Self(pool))
    }
}
