use ::nilauth::{config::Config, run::run};
use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, extract::Query};
use rstest::fixture;
use serde::Deserialize;
use serde_json::json;
use std::net::{Ipv4Addr, SocketAddr};
use std::{
    mem,
    sync::{LazyLock, Mutex},
    thread,
    time::Duration,
};
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{ContainerAsync, GenericImage, Image, runners::AsyncRunner},
};
use tokio::net::TcpListener;
use tokio::{runtime::Runtime, task::JoinHandle, time::sleep};
use tracing::{error, info};

static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| Runtime::new().expect("failed to create RUNTIME"));
static SERVICES: Mutex<Option<Services>> = Mutex::new(None);

const MAX_NILAUTH_START_RETRIES: u8 = 100;
const MAX_ANVIL_START_RETRIES: u8 = 60;
const TOKEN_PRICE_API_PORT: u16 = 59123;

/// Anvil default configuration
const ANVIL_CHAIN_ID: u64 = 31337;

/// Contract addresses from DeployLocal.s.sol
/// These are deterministic when deploying to a fresh Anvil instance
const NIL_TOKEN_ADDRESS: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
const BURN_CONTRACT_ADDRESS: &str = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";

/// override via NIL_ANVIL_IMAGE
const DEFAULT_NIL_ANVIL_IMAGE: &str = "public.ecr.aws/k5d9x2g2/nil-anvil:main";

fn nil_anvil_image() -> (String, String) {
    let full = std::env::var("NIL_ANVIL_IMAGE").unwrap_or_else(|_| DEFAULT_NIL_ANVIL_IMAGE.to_string());
    if let Some((image, tag)) = full.rsplit_once(':') {
        (image.to_string(), tag.to_string())
    } else {
        (full, "latest".to_string())
    }
}

struct Services {
    postgres_container: ContainerAsync<Postgres>,
    anvil_container: ContainerAsync<GenericImage>,
    nilauth_handle: JoinHandle<()>,
    token_price_handle: JoinHandle<()>,
    nilauth: NilAuth,
}

impl Services {
    async fn new() -> Self {
        let StartedContainer { container: postgres_container, port: postgres_port } = Self::start_postgres().await;
        let StartedContainer { container: anvil_container, port: anvil_port } = Self::start_anvil().await;

        let token_price_handle = Self::start_token_price_api().await;

        // Adjust parameters to point to containers
        let mut config = Config::load(Some("config.sample.yaml")).expect("invalid config");
        config.postgres.url = format!("postgres://postgres:postgres@127.0.0.1:{postgres_port}/postgres");
        config.payments.ethereum_rpc_url = format!("http://127.0.0.1:{anvil_port}");
        config.payments.nil_token_address = NIL_TOKEN_ADDRESS.to_string();
        config.payments.burn_contract_address = BURN_CONTRACT_ADDRESS.to_string();
        config.payments.chain_id = ANVIL_CHAIN_ID;
        config.payments.token_price.base_url = format!("http://127.0.0.1:{TOKEN_PRICE_API_PORT}");

        let (nilauth, nilauth_handle) = Self::start_nilauth(config).await;
        Self { postgres_container, anvil_container, nilauth_handle, token_price_handle, nilauth }
    }

    fn nilauth(&self) -> NilAuth {
        self.nilauth.clone()
    }

    async fn start_postgres() -> StartedContainer<Postgres> {
        let container = Postgres::default().start().await.expect("failed to start postgres");
        let port = container.get_host_port_ipv4(5432).await.expect("failed to get port");
        StartedContainer { container, port }
    }

    async fn start_anvil() -> StartedContainer<GenericImage> {
        let (image_name, tag) = nil_anvil_image();
        let image = GenericImage::new(&image_name, &tag).with_exposed_port(8545.into());
        let container = image.start().await.expect("failed to start nil-anvil");
        let port = container.get_host_port_ipv4(8545).await.expect("failed to get anvil port");

        // Wait for Anvil RPC to be ready AND contracts to be deployed.
        // by checking that the BurnWithDigest contract has code deployed.
        let rpc_url = format!("http://127.0.0.1:{port}");
        let client = reqwest::Client::new();

        for i in 0..MAX_ANVIL_START_RETRIES {
            // Check if BurnWithDigest contract has code deployed using eth_getCode
            let response = client
                .post(&rpc_url)
                .header("content-type", "application/json")
                .body(format!(
                    r#"{{"jsonrpc":"2.0","method":"eth_getCode","params":["{}","latest"],"id":1}}"#,
                    BURN_CONTRACT_ADDRESS
                ))
                .send()
                .await;

            if let Ok(resp) = response {
                if let Ok(body) = resp.text().await {
                    // eth_getCode returns "0x" for addresses with no code, or the bytecode
                    // A deployed contract will have a result longer than just "0x"
                    // Check for a result that's at least 10 chars (e.g., "0x608060...")
                    if let Some(start) = body.find("\"result\":\"") {
                        let result_start = start + 10;
                        if let Some(end) = body[result_start..].find('"') {
                            let code = &body[result_start..result_start + end];
                            // Code must be more than just "0x"
                            if code.len() > 4 {
                                info!(
                                    "Anvil ready with contracts deployed at {rpc_url} (code size: {} bytes)",
                                    (code.len() - 2) / 2
                                );
                                return StartedContainer { container, port };
                            }
                        }
                    }
                }
            }

            if i % 10 == 0 {
                info!("Waiting for Anvil contracts to deploy... attempt {i}/{MAX_ANVIL_START_RETRIES}");
            }
            sleep(Duration::from_millis(500)).await;
        }
        panic!("Anvil contracts did not deploy in time");
    }

    async fn start_nilauth(config: Config) -> (NilAuth, JoinHandle<()>) {
        let nilauth = NilAuth {
            endpoint: format!("http://127.0.0.1:{}", config.server.bind_endpoint.port()),
            config: config.clone(),
        };
        let handle = RUNTIME.spawn(async move {
            match run(config).await {
                Ok(_) => info!("nilauth finished successfully"),
                Err(e) => error!("nilauth finished with error: {e}"),
            };
        });
        for _ in 0..MAX_NILAUTH_START_RETRIES {
            if reqwest::get(format!("{}/about", nilauth.endpoint)).await.is_ok() {
                return (nilauth, handle);
            }
            sleep(Duration::from_millis(25)).await
        }
        panic!("nilauth did not start");
    }

    async fn start_token_price_api() -> JoinHandle<()> {
        let router = Router::new().route("/api/v3/simple/price", get(token_price_handler));
        let listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), TOKEN_PRICE_API_PORT))
            .await
            .expect("failed to bind token price api");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router).await {
                error!("Failed to run coin price API: {e}");
            }
        })
    }
}

struct StartedContainer<T: Image> {
    container: ContainerAsync<T>,
    port: u16,
}

#[derive(Clone)]
pub struct NilAuth {
    pub endpoint: String,
    pub config: Config,
}

#[fixture]
pub fn nilauth() -> NilAuth {
    // spin up services in a separate thread/runtime
    let mut services = SERVICES.lock().expect("lock poisoned");
    if services.is_none() {
        tracing_subscriber::fmt().init();
        let s = thread::scope(|scope| {
            scope.spawn(|| RUNTIME.block_on(Services::new())).join().expect("waiting for dependencies to start")
        });

        *services = Some(s);
        // call the cleanup function to stop all services
        unsafe { libc::atexit(cleanup_at_exit) };
    }
    services.as_ref().unwrap().nilauth()
}

extern "C" fn cleanup_at_exit() {
    let mut services = SERVICES.lock().expect("lock poisoned");
    let Some(services) = mem::take(&mut *services) else {
        return;
    };
    RUNTIME.block_on(async move {
        let _ = services.postgres_container.rm().await;
        let _ = services.anvil_container.rm().await;
        services.nilauth_handle.abort();
        services.token_price_handle.abort();
    });
}

#[derive(Deserialize)]
struct TokenPriceParameters {
    ids: String,
    vs_currencies: String,
}

async fn token_price_handler(query: Query<TokenPriceParameters>) -> Result<Json<serde_json::Value>, StatusCode> {
    if query.ids != "nillion" || query.vs_currencies != "usd" {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Json(json!({
        "nillion": {
            "usd" : 1
        }
    })))
}
