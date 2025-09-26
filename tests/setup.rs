use ::nilauth::{config::Config, run::run};
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use axum::{extract::Query, Json};
use nilauth_client::nilchain_client::{client::NillionChainClient, key::NillionChainPrivateKey};
use rstest::fixture;
use serde::Deserialize;
use serde_json::json;
use std::net::{Ipv4Addr, SocketAddr};
use std::{
    mem,
    sync::{Arc, LazyLock, Mutex},
    thread,
    time::Duration,
};
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{
        core::{wait::LogWaitStrategy, ContainerPort, WaitFor},
        runners::AsyncRunner,
        ContainerAsync, GenericImage, Image, ImageExt,
    },
};
use tokio::net::TcpListener;
use tokio::{runtime::Runtime, task::JoinHandle, time::sleep};
use tracing::{error, info};

static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| Runtime::new().expect("failed to create RUNTIME"));
static SERVICES: Mutex<Option<Services>> = Mutex::new(None);

const MAX_NILAUTH_START_RETRIES: u8 = 100;
const TOKEN_PRICE_API_PORT: u16 = 59123;

struct Services {
    postgres_container: ContainerAsync<Postgres>,
    nilchaind_container: ContainerAsync<GenericImage>,
    nilauth_handle: JoinHandle<()>,
    token_price_handle: JoinHandle<()>,
    nilauth: NilAuth,
}

impl Services {
    async fn new() -> Self {
        let StartedContainer { container: postgres_container, port: postgres_port } = Self::start_postgres().await;

        let StartedContainer { container: nilchaind_container, port: nilchaind_port } = Self::start_nilchaind().await;

        let token_price_handle = Self::start_token_price_api().await;

        // adjust parameters so we point to the containers
        let mut config = Config::load(Some("config.sample.yaml")).expect("invalid config");
        config.postgres.url = format!("postgres://postgres:postgres@127.0.0.1:{postgres_port}/postgres");
        config.payments.nilchain_url = format!("http://127.0.0.1:{nilchaind_port}");
        config.payments.token_price.base_url = format!("http://127.0.0.1:{TOKEN_PRICE_API_PORT}");

        let (nilauth, nilauth_handle) = Self::start_nilauth(config).await;
        Self { postgres_container, nilchaind_container, nilauth_handle, token_price_handle, nilauth }
    }

    fn nilauth(&self) -> NilAuth {
        self.nilauth.clone()
    }

    async fn start_postgres() -> StartedContainer<Postgres> {
        let container = Postgres::default().start().await.expect("failed to start postgres");
        let port = container.get_host_port_ipv4(5432).await.expect("failed to get port");
        StartedContainer { container, port }
    }

    async fn start_nilchaind() -> StartedContainer<GenericImage> {
        let container = GenericImage::new("ghcr.io/nillionnetwork/nilchain-devnet", "v0.1.0")
            .with_wait_for(WaitFor::Log(LogWaitStrategy::stdout(b"Starting RPC HTTP server")))
            .with_exposed_port(ContainerPort::Tcp(26648))
            .with_exposed_port(ContainerPort::Tcp(26649))
            .with_exposed_port(ContainerPort::Tcp(26650))
            .with_env_var("NILCHAIND_CONSENSUS_TIMEOUT_COMMIT", "200ms")
            .start()
            .await
            .expect("failed to start nilchain");
        let port = container.get_host_port_ipv4(26648).await.expect("failed to get port");
        StartedContainer { container, port }
    }

    async fn start_nilauth(config: Config) -> (NilAuth, JoinHandle<()>) {
        let payments_key = NillionChainPrivateKey::from_bytes(
            b"\x97\xf4\x98\x89\xfc\xee\xd8\x8a\x9c\xdd\xdb\x16\xa1a\xd1?j\x120|+9\x16?<<9|<-$4",
        )
        .expect("invalid payments key");
        let nilchain_client = NillionChainClient::new(config.payments.nilchain_url.clone(), payments_key)
            .await
            .expect("failed to create payments client");
        let nilauth = NilAuth {
            endpoint: format!("http://127.0.0.1:{}", config.server.bind_endpoint.port()),
            nilchain_client: Arc::new(tokio::sync::Mutex::new(nilchain_client)),
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
    pub nilchain_client: Arc<tokio::sync::Mutex<NillionChainClient>>,
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
        let _ = services.nilchaind_container.rm().await;
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
