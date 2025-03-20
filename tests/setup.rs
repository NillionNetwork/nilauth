use authority_service::{config::Config, run::run};
use rstest::fixture;
use std::{
    mem,
    path::Path,
    sync::{LazyLock, Mutex},
    thread,
};
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{
        core::{ContainerPort, Mount},
        runners::AsyncRunner,
        ContainerAsync, GenericImage, ImageExt,
    },
};
use tokio::{runtime::Runtime, task::JoinHandle};
use tracing::{error, info};

static RUNTIME: LazyLock<Runtime> =
    LazyLock::new(|| Runtime::new().expect("failed to create RUNTIME"));
static SERVICES: Mutex<Option<Services>> = Mutex::new(None);

struct Services {
    postgres_container: ContainerAsync<Postgres>,
    nilchaind_container: ContainerAsync<GenericImage>,
    handle: JoinHandle<()>,
    nilauth: NilAuth,
}

impl Services {
    async fn new() -> Self {
        let postgres_container = Postgres::default()
            .start()
            .await
            .expect("failed to start postgres");
        let postgres_port = postgres_container
            .get_host_port_ipv4(5432)
            .await
            .expect("failed to get port");

        let nilchain_config_path = Path::new("./nilchaind")
            .canonicalize()
            .expect("canonicalize failed")
            .to_string_lossy()
            .into_owned();

        println!("{nilchain_config_path}");
        let nilchaind_container = GenericImage::new("ghcr.io/nillionnetwork/nilchaind", "v0.2.5")
            .with_entrypoint("/bin/sh")
            .with_exposed_port(ContainerPort::Tcp(26648))
            .with_exposed_port(ContainerPort::Tcp(26649))
            .with_exposed_port(ContainerPort::Tcp(26650))
            .with_mount(Mount::bind_mount(nilchain_config_path, "/opt/nilchaind-configs"))
            .with_cmd(["-c", "cp -r /opt/nilchaind-configs /opt/nilchaind && nilchaind start --home /opt/nilchaind"])
            .start()
            .await
            .expect("failed to start nilchain");
        let nilchaind_port = nilchaind_container
            .get_host_port_ipv4(26648)
            .await
            .expect("failed to get port");

        let mut config = Config::load(Some("config.sample.yaml")).expect("invalid config");
        config.postgres.url = format!("postgres://postgres:postgres@127.0.0.1:{postgres_port}");
        config.payments.nilchain_url = format!("http://127.0.0.1:{nilchaind_port}");

        let nilauth = NilAuth {
            endpoint: format!("127.0.0.1:{}", config.server.bind_endpoint.port()),
        };
        let handle = RUNTIME.spawn(async move {
            match run(config).await {
                Ok(_) => info!("nilauth finished successfully"),
                Err(e) => error!("nilauth finished with error: {e}"),
            };
        });
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
}

#[derive(Clone)]
pub struct NilAuth {
    pub endpoint: String,
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
