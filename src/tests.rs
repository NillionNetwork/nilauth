use crate::db::account::MockAccountDb;
use crate::state::{AppState, Databases, Services};
use crate::time::MockTimeService;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mockall::mock;
use nillion_chain_client::tx::{PaymentTransaction, PaymentTransactionRetriever, RetrieveError};
use nillion_nucs::k256::{PublicKey, SecretKey};
use std::sync::Arc;

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
    pub(crate) account_db: MockAccountDb,
}

impl Default for AppStateBuilder {
    fn default() -> Self {
        Self {
            secret_key: SecretKey::random(&mut rand::thread_rng()),
            tx_retriever: Default::default(),
            time_service: Default::default(),
            account_db: Default::default(),
        }
    }
}

impl AppStateBuilder {
    pub(crate) fn build(self) -> Arc<AppState> {
        let Self {
            secret_key,
            tx_retriever,
            time_service,
            account_db,
        } = self;

        Arc::new(AppState {
            secret_key,
            services: Services {
                tx: Box::new(tx_retriever),
                time: Box::new(time_service),
            },
            databases: Databases {
                accounts: Box::new(account_db),
            },
            started_at: Utc::now(),
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
