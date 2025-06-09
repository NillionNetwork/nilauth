use crate::{
    config::BlindModuleCosts, db::subscriptions::BlindModule,
    services::token_price::TokenPriceService,
};
use async_trait::async_trait;
use metrics::counter;
use rust_decimal::Decimal;
use std::sync::Arc;
use tracing::error;

pub(crate) static UNIL_IN_NIL: u64 = 1_000_000;

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub(crate) trait SubscriptionCostService: Send + Sync + 'static {
    async fn blind_module_cost(
        &self,
        blind_module: BlindModule,
    ) -> Result<u64, SubscriptionCostError>;
}

pub(crate) struct DefaultSubscriptionCostService {
    token_price_service: Arc<dyn TokenPriceService>,
    costs: BlindModuleCosts,
}

impl DefaultSubscriptionCostService {
    pub(crate) fn new(
        token_price_service: Arc<dyn TokenPriceService>,
        costs: BlindModuleCosts,
    ) -> Self {
        Self {
            token_price_service,
            costs,
        }
    }
}

#[async_trait]
impl SubscriptionCostService for DefaultSubscriptionCostService {
    async fn blind_module_cost(
        &self,
        blind_module: BlindModule,
    ) -> Result<u64, SubscriptionCostError> {
        let token_price = self
            .token_price_service
            .nil_token_price()
            .await
            .map_err(|e| {
                error!("Failed to get token price: {e}");
                counter!("nil_token_price_fetch_errors_total").increment(1);
                SubscriptionCostError
            })?;
        let dollar_cost = match blind_module {
            BlindModule::NilAi => self.costs.nilai,
            BlindModule::NilDb => self.costs.nildb,
        };
        let cost = dollar_cost / token_price;
        let cost = cost * Decimal::from(UNIL_IN_NIL);
        let cost = cost.try_into().map_err(|_| {
            error!("Overflow when converting subscription price");
            SubscriptionCostError
        })?;
        Ok(cost)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("failed to get subscription cost")]
pub(crate) struct SubscriptionCostError;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::token_price::MockTokenPriceService;
    use rstest::rstest;

    #[rstest]
    #[case::nilai(BlindModule::NilAi, 3_000_000)]
    #[case::nildb(BlindModule::NilDb, 2_000_000)]
    #[tokio::test]
    async fn cost(#[case] blind_module: BlindModule, #[case] cost_unils: u64) {
        let mut token_price_service = MockTokenPriceService::default();
        token_price_service
            .expect_nil_token_price()
            .return_once(move || Ok(50.into()));
        let costs = BlindModuleCosts {
            nildb: 100.into(),
            nilai: 150.into(),
        };
        let service = DefaultSubscriptionCostService::new(Arc::new(token_price_service), costs);
        let cost = service
            .blind_module_cost(blind_module)
            .await
            .expect("failed to get cost");
        assert_eq!(cost, cost_unils);
    }
}
