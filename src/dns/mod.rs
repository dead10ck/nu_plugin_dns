use std::sync::Arc;

use futures_util::Future;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_resolver::{config::ResolverConfig, Resolver};
use nu_plugin::{Plugin, PluginCommand};
use nu_protocol::LabeledError;
use tokio::task::JoinHandle;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use self::commands::query::DnsQueryPluginResolver;
pub use config::Config;

pub mod client;
pub mod commands;
pub mod config;
pub mod constants;
pub mod serde;
#[macro_use]
pub mod util;

pub type DnsResolver = Resolver<TokioRuntimeProvider>;

pub struct Dns {
    main_runtime: tokio::runtime::Runtime,
    runtime_provider: TokioRuntimeProvider,
    tasks: TaskTracker,
    cancel: CancellationToken,
    resolver: DnsQueryPluginResolver,
}

impl Plugin for Dns {
    fn commands(&self) -> Vec<Box<dyn PluginCommand<Plugin = Self>>> {
        vec![Box::new(commands::query::DnsQuery)]
    }

    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").into()
    }
}

impl Dns {
    pub const PLUGIN_NAME: &str = "dns";

    pub fn new() -> Self {
        Self {
            main_runtime: tokio::runtime::Runtime::new().unwrap(),
            runtime_provider: TokioRuntimeProvider::new(),
            tasks: TaskTracker::new(),
            cancel: CancellationToken::new(),
            resolver: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    pub async fn dns_client(&self, config: &Config) -> Result<DnsResolver, LabeledError> {
        // Since the plug-in binary is left running in the background by the
        // nushell engine between invocations, we leave a handle to it attached
        // to the plug-in object instance so we can reuse it across invocations.
        // If there is one already, use it.
        //
        // We could use OnceLock once get_or_try_init is stable
        if let Some(resolver) = &*self.resolver.read().await {
            return Ok(resolver.clone());
        }

        let mut resolver_guard = self.resolver.write().await;

        // it is cheap to clone and hand back an owned client because underneath
        // it is just a mpsc::Sender
        match &mut *resolver_guard {
            Some(resolver) => Ok(resolver.clone()),
            None => {
                let (client, client_bg) = self.make_dns_client(config).await?;
                *resolver_guard = Some(client.clone());
                Ok(client)
            }
        }
    }

    async fn make_dns_client(&self, config: &Config) -> Result<DnsResolver, LabeledError> {
        // let resolver_config = ResolverConfig::tls()
        let resolver = DnsResolver::new(config, self.runtime_provider.clone()).await?;
        tracing::info!(client.addr = ?config.server, client.protocol = ?config.protocol);
        Ok(resolver)
    }

    pub fn spawn<F>(&self, future: F)
    where
        F: Future<Output = Result<(), LabeledError>> + Send + 'static,
    {
        self.tasks.spawn(future);
    }

    pub async fn spawn_blocking<F>(&self, future: F)
    where
        F: FnOnce() -> Result<(), LabeledError> + Send + 'static,
    {
        self.tasks.spawn_blocking(future);
    }

    pub async fn close(&self) {
        self.tasks.close();
        self.tasks.wait().await;
    }
}

impl Default for Dns {
    fn default() -> Self {
        Self::new()
    }
}
