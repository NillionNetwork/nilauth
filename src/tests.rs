use crate::db::revocations::MockRevocationDb;
use crate::db::subscriptions::MockSubscriptionDb;
use crate::services::ethereum_rpc::{BurnWithDigestEvent, BurnWithDigestEventRetriever, EthereumRpcError};
use crate::services::subscription_cost::MockSubscriptionCostService;
use crate::state::{AppState, Databases, Parameters, Services};
use crate::time::MockTimeService;
use async_trait::async_trait;
use chrono::Utc;
use mockall::mock;
use nillion_nucs::{DidMethod, NucSigner, Signer, did::Did};
use rust_decimal::Decimal;
use std::sync::Arc;
use std::time::Duration;

mock! {
    pub(crate) EthereumEventRetriever {}

    #[async_trait]
    impl BurnWithDigestEventRetriever for EthereumEventRetriever {
        async fn get_event_by_tx_hash(&self, tx_hash: &str) -> Result<BurnWithDigestEvent, EthereumRpcError>;
    }
}

pub(crate) struct AppStateBuilder {
    pub(crate) signer: Box<dyn NucSigner>,
    pub(crate) legacy_signer: Box<dyn NucSigner>,
    pub(crate) ethereum_event_retriever: MockEthereumEventRetriever,
    pub(crate) time_service: MockTimeService,
    pub(crate) subscription_costs_service: MockSubscriptionCostService,
    pub(crate) subscriptions_db: MockSubscriptionDb,
    pub(crate) revocation_db: MockRevocationDb,
    pub(crate) subscription_renewal_threshold: Duration,
    pub(crate) chain_id: u64,
}

impl Default for AppStateBuilder {
    fn default() -> Self {
        Self {
            signer: Signer::generate(DidMethod::Key),
            #[allow(deprecated)]
            legacy_signer: Signer::generate(DidMethod::Nil),
            ethereum_event_retriever: Default::default(),
            time_service: Default::default(),
            subscription_costs_service: Default::default(),
            subscriptions_db: Default::default(),
            revocation_db: Default::default(),
            subscription_renewal_threshold: Duration::from_secs(60),
            chain_id: 31337, // Anvil default
        }
    }
}

impl AppStateBuilder {
    pub(crate) fn build(self) -> Arc<AppState> {
        let Self {
            signer,
            legacy_signer,
            ethereum_event_retriever,
            time_service,
            subscription_costs_service,
            subscriptions_db,
            revocation_db,
            subscription_renewal_threshold,
            chain_id,
        } = self;

        let did = *signer.did();
        let public_key = match did {
            Did::Key { public_key } => public_key,
            _ => panic!("Test signer must be a did:key"),
        };

        Arc::new(AppState {
            services: Services {
                ethereum_event_retriever: Box::new(ethereum_event_retriever),
                time: Box::new(time_service),
                subscription_cost: Box::new(subscription_costs_service),
            },
            databases: Databases { subscriptions: Box::new(subscriptions_db), revocations: Arc::new(revocation_db) },
            parameters: Parameters {
                signer,
                legacy_signer,
                did,
                public_key,
                started_at: Utc::now(),
                subscription_cost_slippage: Decimal::new(3, 2), // 3%
                subscription_renewal_threshold,
                chain_id,
            },
        })
    }

    pub(crate) fn public_key(&self) -> [u8; 33] {
        let did = *self.signer.did();
        match did {
            Did::Key { public_key } => public_key,
            _ => panic!("Test signer must be a did:key"),
        }
    }
}

pub(crate) fn random_public_key() -> [u8; 33] {
    use rand::RngCore;
    let mut key = [0u8; 33];
    rand::thread_rng().fill_bytes(&mut key);
    key
}
