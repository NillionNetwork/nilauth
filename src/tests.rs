use crate::db::account::MockAccountDb;
use crate::db::revocations::MockRevocationDb;
use crate::services::prices::MockTokenPriceService;
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
    pub(crate) token_price_service: MockTokenPriceService,
    pub(crate) account_db: MockAccountDb,
    pub(crate) revocation_db: MockRevocationDb,
    pub(crate) subscription_cost: Decimal,
    pub(crate) subscription_renewal_threshold: Duration,
}

impl Default for AppStateBuilder {
    fn default() -> Self {
        Self {
            secret_key: SecretKey::random(&mut rand::thread_rng()),
            tx_retriever: Default::default(),
            time_service: Default::default(),
            token_price_service: Default::default(),
            account_db: Default::default(),
            revocation_db: Default::default(),
            subscription_cost: 1.into(),
            subscription_renewal_threshold: Duration::from_secs(60),
        }
    }
}

impl AppStateBuilder {
    pub(crate) fn with_expectations<F>(mut self, callback: F) -> Self
    where
        F: FnOnce(&mut Self),
    {
        callback(&mut self);
        self
    }

    pub(crate) fn build(self) -> Arc<AppState> {
        let Self {
            secret_key,
            tx_retriever,
            time_service,
            token_price_service,
            account_db,
            revocation_db,
            subscription_cost,
            subscription_renewal_threshold,
        } = self;

        Arc::new(AppState {
            parameters: Parameters {
                secret_key,
                started_at: Utc::now(),
                subscription_cost,
                // 0.01
                subscription_cost_slippage: Decimal::new(1, 2),
                subscription_renewal_threshold,
            },
            services: Services {
                tx: Box::new(tx_retriever),
                time: Box::new(time_service),
                prices: Box::new(token_price_service),
            },
            databases: Databases {
                accounts: Box::new(account_db),
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
