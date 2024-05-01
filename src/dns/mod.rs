use std::sync::Arc;

use futures_util::Future;
use nu_protocol::LabeledError;
use tokio::task::JoinSet;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use self::{client::DnsClient, commands::query::DnsQueryPluginClient, config::Config};

mod client;
mod commands;
mod config;
mod constants;
mod serde;
#[macro_use]
mod util;

pub struct Dns {
    runtime: tokio::runtime::Runtime,
    tasks: TaskTracker,
    cancel: CancellationToken,
    client: DnsQueryPluginClient,
}

impl Dns {
    pub fn new() -> Self {
        Self {
            runtime: tokio::runtime::Runtime::new().unwrap(),
            tasks: TaskTracker::new(),
            cancel: CancellationToken::new(),
            client: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    pub async fn dns_client(&self, config: &Config) -> Result<DnsClient, LabeledError> {
        // we could use OnceLock once get_or_try_init is stable
        if let Some((client, _)) = &*self.client.read().await {
            return Ok(client.clone());
        }

        let mut client_guard = self.client.write().await;

        // it is cheap to clone and hand back an owned client because underneath
        // it is just a mpsc::Sender
        match &mut *client_guard {
            Some((client, _)) => Ok(client.clone()),
            None => {
                let (client, client_bg) = self.make_dns_client(config).await?;
                *client_guard = Some((client.clone(), client_bg));
                Ok(client)
            }
        }
    }

    async fn make_dns_client(
        &self,
        config: &Config,
    ) -> Result<
        (
            DnsClient,
            JoinSet<Result<(), hickory_proto::error::ProtoError>>,
        ),
        LabeledError,
    > {
        let (client, bg) = DnsClient::new(config).await?;
        tracing::info!(client.addr = ?config.server, client.protocol = ?config.protocol);
        Ok((client, bg))
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
