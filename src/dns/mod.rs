use std::sync::Arc;

use futures_util::{
    stream::{FuturesOrdered, FuturesUnordered},
    Future, StreamExt,
};
use hickory_client::client::ClientHandle;

use nu_plugin::{EngineInterface, EvaluatedCall};
use nu_protocol::{LabeledError, ListStream, PipelineData, Span, Value};

use tokio::task::{JoinHandle, JoinSet};
use tracing_subscriber::prelude::*;

use self::{client::DnsClient, config::Config, serde::Query};

mod client;
mod config;
mod constants;
mod nu;
mod serde;
#[macro_use]
mod util;

type DnsQueryJoinHandle = JoinHandle<Result<(), LabeledError>>;
type DnsQueryResult = FuturesUnordered<Result<Value, LabeledError>>;
type DnsQueryPluginClient = Arc<
    tokio::sync::RwLock<
        Option<(
            DnsClient,
            JoinSet<Result<(), hickory_proto::error::ProtoError>>,
        )>,
    >,
>;

pub struct Dns {
    runtime: tokio::runtime::Runtime,
    tasks: Arc<std::sync::Mutex<Vec<DnsQueryJoinHandle>>>,
    client: DnsQueryPluginClient,
}

impl Dns {
    pub fn new() -> Self {
        Self {
            runtime: tokio::runtime::Runtime::new().unwrap(),
            tasks: Arc::new(std::sync::Mutex::new(Vec::new())),
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
        self.tasks.lock().unwrap().push(self.runtime.spawn(future));
    }

    pub fn spawn_blocking<F>(&self, future: F)
    where
        F: FnOnce() -> Result<(), LabeledError> + Send + 'static,
    {
        self.tasks
            .lock()
            .unwrap()
            .push(self.runtime.spawn_blocking(future));
    }
}

impl Default for Dns {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct DnsQuery;

impl DnsQuery {
    async fn run_impl(
        &self,
        plugin: &Dns,
        engine: &EngineInterface,
        call: &EvaluatedCall,
        input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        let _ = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();

        let config = Config::from_nu(engine.get_plugin_config()?, call)?;
        let arg_inputs: Value = call.nth(0).unwrap_or(Value::nothing(call.head));

        let input: PipelineData = match input {
            PipelineData::Empty | PipelineData::Value(Value::Nothing { .. }, _) => {
                PipelineData::Value(arg_inputs, None)
            }
            val => {
                if !arg_inputs.is_empty() {
                    return Err(LabeledError::new("ambiguous input").with_label(
                        "Input should either be positional args or piped, but not both",
                        val.span().unwrap_or(Span::unknown()),
                    ));
                }

                val
            }
        };

        let client = tokio::time::timeout(config.timeout.item, plugin.dns_client(&config))
            .await
            .map_err(|_| {
                LabeledError::new("timed out").with_label(
                    format!("connecting to {} timed out", config.server.item),
                    config.server.span,
                )
            })??;

        let config = Arc::new(config);

        match input {
            PipelineData::Value(val, _) => {
                if tracing::enabled!(tracing::Level::TRACE) {
                    tracing::trace!(phase = "input", data.kind = "value", ?val);
                } else {
                    tracing::debug!(phase = "input", data.kind = "value");
                }

                let values = Self::query(config, val, client.clone()).await;

                let val = PipelineData::Value(
                    Value::list(
                        values.into_iter().collect::<Result<Vec<_>, _>>()?,
                        Span::unknown(),
                    ),
                    None,
                );

                tracing::trace!(phase = "return", ?val);

                Ok(val)
            }
            PipelineData::ListStream(mut stream, _) => {
                tracing::debug!(phase = "input", data.kind = "stream");

                let (request_tx, mut request_rx) = tokio::sync::mpsc::channel(config.tasks.item);
                let (resp_tx, mut resp_rx) = tokio::sync::mpsc::channel(config.tasks.item);

                plugin.spawn({
                    let client = client.clone();

                    async move {
                        let mut buf = Vec::with_capacity(config.tasks.item);
                        let mut result_queue = FuturesOrdered::new();

                        while request_rx.recv_many(&mut buf, config.tasks.item).await > 0 {
                            for val in buf.drain(..) {
                                tracing::trace!(query = ?val, query.phase = "received");

                                let config = config.clone();
                                let client = client.clone();

                                let handle =
                                    tokio::spawn(
                                        async move { Self::query(config, val, client).await },
                                    );

                                result_queue.push_back(handle);
                            }

                            while let Some(query_result) = result_queue.next().await {
                                let query_result = query_result.map_err(|err| {
                                    LabeledError::new("internal error").with_label(
                                        format!("task panicked: {}", err),
                                        Span::unknown(),
                                    )
                                })?;

                                for resp in query_result.into_iter() {
                                    resp_tx.send(resp).await.map_err(|send_err| {
                                        LabeledError::new("internal error").with_label(
                                            format!(
                                                "failed to send dns query result: {}",
                                                send_err
                                            ),
                                            Span::unknown(),
                                        )
                                    })?;
                                }
                            }
                        }

                        Ok(())
                    }
                });

                plugin.spawn_blocking(move || {
                    stream
                        .stream
                        .try_for_each(|val| {
                            tracing::trace!(query = ?val, query.phase = "send");
                            request_tx.blocking_send(val)
                        })
                        .map_err(|send_err| {
                            LabeledError::new("internal error").with_label(
                                format!("failed to send dns query result: {}", send_err),
                                Span::unknown(),
                            )
                        })
                });

                Ok(PipelineData::ListStream(
                    ListStream::from_stream(
                        std::iter::from_fn(move || {
                            resp_rx.blocking_recv().map(|resp| {
                                resp.unwrap_or_else(|err| Value::error(err.into(), Span::unknown()))
                            })
                        })
                        .inspect(|val| tracing::debug!(phase = "return", ?val)),
                        stream.ctrlc,
                    ),
                    None,
                ))
            }
            data => Err(LabeledError::new("invalid input").with_label(
                "Only values can be passed as input",
                data.span().unwrap_or(Span::unknown()),
            )),
        }
    }

    async fn query(config: Arc<Config>, input: Value, client: DnsClient) -> DnsQueryResult {
        let in_span = input.span();
        let queries = match Query::try_from_value(&input, &config) {
            Ok(queries) => queries,
            Err(err) => {
                return vec![Ok(Value::error(err.into(), in_span))]
                    .into_iter()
                    .collect()
            }
        };

        tracing::debug!(request.queries = ?queries);

        futures_util::stream::iter(queries)
            .then(|query| {
                let mut client = client.clone();
                let config = config.clone();

                async move {
                    let parts = query.0.into_parts();

                    if tracing::enabled!(tracing::Level::TRACE) {
                        tracing::trace!(query.phase = "start", query.parts = ?parts);
                    } else {
                        tracing::debug!(query.phase = "start");
                    }

                    let request = tokio::time::timeout(
                        config.timeout.item,
                        client.query(parts.name, parts.query_class, parts.query_type),
                    );

                    request
                        .await
                        .map_err(|_| {
                            LabeledError::new("timed out").with_label(
                                format!("request to {} timed out", config.server.item),
                                config.server.span,
                            )
                        })?
                        .map_err(|err| {
                            LabeledError::new("DNS error")
                                .with_label(format!("Error in DNS response: {:?}", err), in_span)
                        })
                        .and_then(|resp: hickory_proto::xfer::DnsResponse| {
                            let msg = serde::Message::new(resp.into_message());
                            msg.into_value(&config)
                        })
                        .inspect_err(
                            |err| tracing::debug!(query.phase = "finish", query.error = ?err),
                        )
                        .inspect(
                            |resp| tracing::debug!(query.phase = "finish", query.response = ?resp),
                        )
                }
            })
            .collect::<FuturesUnordered<_>>()
            .await
    }
}
