use sqlx::{Pool, Postgres};

pub mod account;

#[derive(Clone)]
pub struct PostgresPool(Pool<Postgres>);

impl PostgresPool {
    pub async fn new(url: &str) -> anyhow::Result<Self> {
        let pool = Pool::connect(url).await?;
        sqlx::migrate!().run(&pool).await?;
        Ok(Self(pool))
    }
}
