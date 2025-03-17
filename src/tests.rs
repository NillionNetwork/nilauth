use async_trait::async_trait;
use mockall::mock;
use nillion_chain_client::tx::PaymentTransactionRetriever;
use nillion_chain_client::tx::{PaymentTransaction, RetrieveError};

mock! {
    pub(crate) PaymentRetriever {}

    #[async_trait]
    impl PaymentTransactionRetriever for PaymentRetriever {
        async fn get(&self, tx_hash: &str) -> Result<PaymentTransaction, RetrieveError>;
    }
}
