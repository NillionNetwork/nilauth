use sqlx::{Pool, Postgres};
use tracing::info;

pub mod account;

#[derive(Clone)]
pub struct PostgresPool(Pool<Postgres>);

impl PostgresPool {
    pub async fn new(url: &str) -> anyhow::Result<Self> {
        let pool = Pool::connect(url).await?;
        info!("Running migrations");
        sqlx::migrate!().run(&pool).await?;
        info!("Migrations ran successfully");
        Ok(Self(pool))
    }
}
