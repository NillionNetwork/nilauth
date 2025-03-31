use crate::{db::revocations::RevocationDb, time::TimeService};
use metrics::counter;
use std::{sync::Arc, time::Duration};
use tokio::time::sleep;
use tracing::{error, info};

const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const CLEANUP_GRACE_PERIOD: Duration = Duration::from_secs(60);

pub(crate) struct RevokedTokenCleaner {
    db: Arc<dyn RevocationDb>,
    time: Box<dyn TimeService>,
}

impl RevokedTokenCleaner {
    pub(crate) fn spawn(db: Arc<dyn RevocationDb>, time: Box<dyn TimeService>) {
        let this = Self { db, time };
        tokio::spawn(async move { this.run().await });
    }

    async fn run(self) {
        loop {
            if let Err(e) = self.try_delete().await {
                error!("Failed to delete expired revoked tokens: {e}");
            }
            info!("Sleeping for {CLEANUP_INTERVAL:?}");
            sleep(CLEANUP_INTERVAL).await;
        }
    }

    async fn try_delete(&self) -> anyhow::Result<()> {
        // Delete tokens expired a few seconds ago, just in case our clock drifted a little. We
        // don't want to risk allowing a revoked token to be considered valid.
        let cleanup_threshold = self.time.current_time() - CLEANUP_GRACE_PERIOD;
        info!("Deleting revoked tokens expired before {cleanup_threshold}");
        let expired_count = self.db.delete_expired(cleanup_threshold).await?;
        info!("Deleted {expired_count} expired revoked tokens");

        counter!("expired_revoked_tokens_removed_total").increment(expired_count);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{db::revocations::MockRevocationDb, time::MockTimeService};
    use chrono::Utc;
    use mockall::predicate::eq;

    #[tokio::test]
    async fn cleanup() {
        let mut db = MockRevocationDb::default();
        let mut time = MockTimeService::default();
        let now = Utc::now();
        time.expect_current_time().return_once(move || now);
        db.expect_delete_expired()
            .with(eq(now - CLEANUP_GRACE_PERIOD))
            .return_once(|_| Ok(1));

        let cleaner = RevokedTokenCleaner {
            db: Arc::new(db),
            time: Box::new(time),
        };
        cleaner.try_delete().await.expect("failed to delete");
    }
}
