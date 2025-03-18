use crate::state::{AppState, Services};
use crate::time::MockTimeService;
use async_trait::async_trait;
use mockall::mock;
use nillion_chain_client::tx::{PaymentTransaction, PaymentTransactionRetriever, RetrieveError};
use nillion_nucs::k256::SecretKey;
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
    pub(crate) token_expiration: Duration,
    pub(crate) tx_retriever: MockPaymentRetriever,
    pub(crate) time_service: MockTimeService,
}

impl Default for AppStateBuilder {
    fn default() -> Self {
        Self {
            secret_key: SecretKey::random(&mut rand::thread_rng()),
            token_expiration: Duration::from_secs(1),
            tx_retriever: Default::default(),
            time_service: Default::default(),
        }
    }
}

impl AppStateBuilder {
    pub(crate) fn build(self) -> Arc<AppState> {
        let Self {
            secret_key,
            token_expiration,
            tx_retriever,
            time_service,
        } = self;

        Arc::new(AppState {
            secret_key,
            token_expiration,
            services: Services {
                tx: Box::new(tx_retriever),
                time: Box::new(time_service),
            },
        })
    }

    pub(crate) fn public_key(&self) -> Vec<u8> {
        self.secret_key.public_key().to_sec1_bytes().to_vec()
    }
}
