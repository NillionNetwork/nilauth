use authority_service::{config::Config, run::run};
use nillion_chain_client::{client::NillionChainClient, key::NillionChainPrivateKey};
use rstest::fixture;
use std::{
    mem,
    path::Path,
    sync::{Arc, LazyLock, Mutex},
    thread,
    time::Duration,
};
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{
        core::{wait::LogWaitStrategy, ContainerPort, Mount, WaitFor},
        runners::AsyncRunner,
        ContainerAsync, GenericImage, Image, ImageExt,
    },
};
use tokio::{runtime::Runtime, task::JoinHandle, time::sleep};
use tracing::{error, info};

static RUNTIME: LazyLock<Runtime> =
    LazyLock::new(|| Runtime::new().expect("failed to create RUNTIME"));
static SERVICES: Mutex<Option<Services>> = Mutex::new(None);

const MAX_NILAUTH_START_RETRIES: u8 = 100;

struct Services {
    postgres_container: ContainerAsync<Postgres>,
    nilchaind_container: ContainerAsync<GenericImage>,
    handle: JoinHandle<()>,
    nilauth: NilAuth,
}

impl Services {
    async fn new() -> Self {
        let StartedContainer {
            container: postgres_container,
            port: postgres_port,
        } = Self::start_postgres().await;

        let StartedContainer {
            container: nilchaind_container,
            port: nilchaind_port,
        } = Self::start_nilchaind().await;

        // adjust parameters so we point to the containers
        let mut config = Config::load(Some("config.sample.yaml")).expect("invalid config");
        config.postgres.url =
            format!("postgres://postgres:postgres@127.0.0.1:{postgres_port}/postgres");
        config.payments.nilchain_url = format!("http://127.0.0.1:{nilchaind_port}");

        let (nilauth, handle) = Self::start_nilauth(config).await;
        Self {
            postgres_container,
            nilchaind_container,
            handle,
            nilauth,
        }
    }

    fn nilauth(&self) -> NilAuth {
        self.nilauth.clone()
    }

    async fn start_postgres() -> StartedContainer<Postgres> {
        let container = Postgres::default()
            .start()
            .await
            .expect("failed to start postgres");
        let port = container
            .get_host_port_ipv4(5432)
            .await
            .expect("failed to get port");
        StartedContainer { container, port }
    }

    async fn start_nilchaind() -> StartedContainer<GenericImage> {
        let nilchain_config_path = Path::new("./nilchaind")
            .canonicalize()
            .expect("canonicalize failed")
            .to_string_lossy()
            .into_owned();

        let container = GenericImage::new("ghcr.io/nillionnetwork/nilchaind", "v0.2.5")
            .with_entrypoint("/bin/sh")
            .with_wait_for(WaitFor::Log(LogWaitStrategy::stdout(b"Starting RPC HTTP server")))
            .with_exposed_port(ContainerPort::Tcp(26648))
            .with_exposed_port(ContainerPort::Tcp(26649))
            .with_exposed_port(ContainerPort::Tcp(26650))
            .with_mount(Mount::bind_mount(nilchain_config_path, "/opt/nilchaind-configs"))
            .with_cmd(["-c", "cp -r /opt/nilchaind-configs /opt/nilchaind && nilchaind start --home /opt/nilchaind"])
            .start()
            .await
            .expect("failed to start nilchain");
        let port = container
            .get_host_port_ipv4(26648)
            .await
            .expect("failed to get port");
        StartedContainer { container, port }
    }

    async fn start_nilauth(config: Config) -> (NilAuth, JoinHandle<()>) {
        let payments_key = NillionChainPrivateKey::from_bytes(
            b"\x97\xf4\x98\x89\xfc\xee\xd8\x8a\x9c\xdd\xdb\x16\xa1a\xd1?j\x120|+9\x16?<<9|<-$4",
        )
        .expect("invalid payments key");
        let nilchain_client =
            NillionChainClient::new(config.payments.nilchain_url.clone(), payments_key)
                .await
                .expect("failed to create payments client");
        let nilauth = NilAuth {
            endpoint: format!("http://127.0.0.1:{}", config.server.bind_endpoint.port()),
            nilchain_client: Arc::new(tokio::sync::Mutex::new(nilchain_client)),
        };
        let handle = RUNTIME.spawn(async move {
            match run(config).await {
                Ok(_) => info!("nilauth finished successfully"),
                Err(e) => error!("nilauth finished with error: {e}"),
            };
        });
        for _ in 0..MAX_NILAUTH_START_RETRIES {
            if reqwest::get(format!("{}/about", nilauth.endpoint))
                .await
                .is_ok()
            {
                return (nilauth, handle);
            }
            sleep(Duration::from_millis(25)).await
        }
        panic!("nilauth did not start");
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
}

#[fixture]
pub(crate) fn nilauth() -> NilAuth {
    // spin up services in a separate thread/runtime
    let mut services = SERVICES.lock().expect("lock poisoned");
    if services.is_none() {
        tracing_subscriber::fmt().init();
        let s = thread::scope(|scope| {
            scope
                .spawn(|| RUNTIME.block_on(Services::new()))
                .join()
                .expect("waiting for dependencies to start")
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
        services.handle.abort();
    });
}
