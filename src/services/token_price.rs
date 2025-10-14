use crate::config::TokenPriceConfig;
use anyhow::{anyhow, bail};
use async_trait::async_trait;
use metrics::{counter, gauge, histogram};
use rust_decimal::Decimal;
use serde::Deserialize;
use std::{collections::HashMap, time::Duration};
use tokio::{sync::Mutex, time::Instant};
use tracing::info;

const PRICE_CACHE_DURATION: Duration = Duration::from_secs(60);

/// A service for retrieving the current price of the NIL token in USD.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub(crate) trait TokenPriceService: Send + Sync + 'static {
    /// Fetches the price of one NIL token in USD.
    async fn nil_token_price(&self) -> anyhow::Result<Decimal>;
}

/// An implementation of the token price service that uses CoinGecko to retrieve the price.
pub(crate) struct CoinGeckoTokenPriceService {
    client: reqwest::Client,
    api_key: String,
    coin_id: String,
    simple_price_url: String,
    last_price: Mutex<CachedPrice>,
}

impl CoinGeckoTokenPriceService {
    /// Creates a new `CoinGeckoTokenPriceService`.
    pub(crate) fn new(config: TokenPriceConfig) -> anyhow::Result<Self> {
        let TokenPriceConfig { base_url, api_key, coin_id, request_timeout } = config;
        let client = reqwest::Client::builder().timeout(request_timeout).build()?;
        Ok(Self {
            client,
            api_key,
            coin_id,
            simple_price_url: format!("{base_url}/api/v3/simple/price"),
            last_price: Mutex::new(CachedPrice {
                timestamp: Instant::now() - PRICE_CACHE_DURATION - Duration::from_secs(1),
                price: Decimal::from(0),
            }),
        })
    }
}

#[async_trait]
impl TokenPriceService for CoinGeckoTokenPriceService {
    async fn nil_token_price(&self) -> anyhow::Result<Decimal> {
        let mut last_price = self.last_price.lock().await;
        if last_price.timestamp.elapsed() < PRICE_CACHE_DURATION {
            counter!("nil_token_cache_hits_total").increment(1);
            return Ok(last_price.price);
        }

        let params = [("ids", self.coin_id.as_str()), ("vs_currencies", "usd")];
        info!("Fetching token price from CoinGecko from URL {}, and params {params:?}", self.simple_price_url);

        let now = Instant::now();
        let response = self
            .client
            .get(&self.simple_price_url)
            .query(&params)
            .header("X-CG-PRO-API-KEY", &self.api_key)
            .send()
            .await
            .and_then(|r| r.error_for_status());
        let elapsed = now.elapsed();
        histogram!("nil_token_price_fetch_seconds",).record(elapsed.as_millis() as f64 / 1000.0);

        let response = match response {
            Ok(response) => response,
            Err(e) => {
                bail!("Failed to fetch token price from CoinGecko: {e}");
            }
        };

        let response: HashMap<String, TokenPrice> =
            response.json().await.map_err(|e| anyhow!("invalid JSON response from CoinGecko: {e}"))?;

        let price = response
            .get(&self.coin_id)
            .map(|response| response.usd)
            .ok_or_else(|| anyhow!("CoinGecko response dot not contain the requested coin"))?;
        // Just in case...
        if price <= Decimal::from(0) {
            bail!("token price is <= 0: {price}")
        }
        if let Ok(price) = f64::try_from(price) {
            gauge!("nil_token_price").set(price);
        }

        info!("Token price from CoinGecko: {price}");

        *last_price = CachedPrice { timestamp: Instant::now(), price };
        Ok(price)
    }
}

/// A cached token price with its retrieval timestamp.
struct CachedPrice {
    timestamp: Instant,
    price: Decimal,
}

// The type returned from coingecko containing the usd price for a token.
#[derive(Debug, Deserialize)]
struct TokenPrice {
    usd: Decimal,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_price_parsing() {
        let input = "0.249524";
        serde_json::from_str::<Decimal>(input).expect("parse failed");
    }
}
