use crate::db::revocations::MockRevocationDb;
use crate::db::subscriptions::MockSubscriptionDb;
use crate::services::subscription_cost::MockSubscriptionCostService;
use crate::state::{AppState, Databases, Parameters, Services};
use crate::time::MockTimeService;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mockall::mock;
use nilauth_client::nilchain_client::tx::{
    PaymentTransaction, PaymentTransactionRetriever, RetrieveError,
};
use nillion_nucs::k256::{PublicKey, SecretKey};
use rust_decimal::Decimal;
use std::sync::Arc;
use std::time::Duration;

mock! {
    pub(crate) PaymentRetriever {}

    #[async_trait]
    impl PaymentTransactionRetriever for PaymentRetriever {
        async fn get(&self, tx_hash: &str) -> Result<PaymentTransaction, RetrieveError>;
    }
}

pub(crate) struct AppStateBuilder {
    pub(crate) secret_key: SecretKey,
    pub(crate) tx_retriever: MockPaymentRetriever,
    pub(crate) time_service: MockTimeService,
    pub(crate) subscription_costs_service: MockSubscriptionCostService,
    pub(crate) subscriptions_db: MockSubscriptionDb,
    pub(crate) revocation_db: MockRevocationDb,
    pub(crate) subscription_renewal_threshold: Duration,
}

impl Default for AppStateBuilder {
    fn default() -> Self {
        Self {
            secret_key: SecretKey::random(&mut rand::thread_rng()),
            tx_retriever: Default::default(),
            time_service: Default::default(),
            subscription_costs_service: Default::default(),
            subscriptions_db: Default::default(),
            revocation_db: Default::default(),
            subscription_renewal_threshold: Duration::from_secs(60),
        }
    }
}

impl AppStateBuilder {
    pub(crate) fn build(self) -> Arc<AppState> {
        let Self {
            secret_key,
            tx_retriever,
            time_service,
            subscription_costs_service,
            subscriptions_db,
            revocation_db,
            subscription_renewal_threshold,
        } = self;

        Arc::new(AppState {
            parameters: Parameters {
                secret_key,
                started_at: Utc::now(),
                // 0.01
                subscription_cost_slippage: Decimal::new(1, 2),
                subscription_renewal_threshold,
            },
            services: Services {
                tx: Box::new(tx_retriever),
                time: Box::new(time_service),
                subscription_cost: Box::new(subscription_costs_service),
            },
            databases: Databases {
                subscriptions: Box::new(subscriptions_db),
                revocations: Arc::new(revocation_db),
            },
        })
    }

    pub(crate) fn public_key(&self) -> Vec<u8> {
        self.secret_key.public_key().to_sec1_bytes().to_vec()
    }

    pub(crate) fn set_current_time(&mut self, timestamp: DateTime<Utc>) {
        // reset any expectations and set a new one
        self.time_service.checkpoint();
        self.time_service
            .expect_current_time()
            .returning(move || timestamp);
    }
}

pub(crate) fn random_public_key() -> [u8; 33] {
    SecretKey::random(&mut rand::thread_rng())
        .public_key()
        .to_bytes()
}

pub(crate) trait PublicKeyExt {
    fn to_bytes(self) -> [u8; 33];
}

impl PublicKeyExt for PublicKey {
    fn to_bytes(self) -> [u8; 33] {
        self.to_sec1_bytes()
            .as_ref()
            .try_into()
            .expect("invalid public key")
    }
}
