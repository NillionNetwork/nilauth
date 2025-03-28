use sqlx::{Pool, Postgres};
use tracing::info;

pub(crate) mod account;
pub(crate) mod revocations;

#[derive(Clone)]
pub(crate) struct PostgresPool(Pool<Postgres>);

impl PostgresPool {
    pub(crate) async fn new(url: &str) -> anyhow::Result<Self> {
        let pool = Pool::connect(url).await?;
        info!("Running migrations");
        sqlx::migrate!().run(&pool).await?;
        info!("Migrations ran successfully");
        Ok(Self(pool))
    }
}
