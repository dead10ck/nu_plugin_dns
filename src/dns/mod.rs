use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use futures_util::{stream::FuturesUnordered, Future, StreamExt};
use hickory_client::client::ClientHandle;

use nu_plugin::{EngineInterface, EvaluatedCall};
use nu_protocol::{LabeledError, ListStream, PipelineData, Span, Value};

use hickory_resolver::config::{Protocol, ResolverConfig};

use tokio::task::{JoinHandle, JoinSet};
use tracing_subscriber::prelude::*;

use self::{client::DnsClient, constants::flags, serde::Query};

mod client;
mod constants;
mod nu;
mod serde;

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

    pub async fn dns_client(&self, call: &EvaluatedCall) -> Result<DnsClient, LabeledError> {
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
                let (client, client_bg) = self.make_dns_client(call).await?;
                *client_guard = Some((client.clone(), client_bg));
                Ok(client)
            }
        }
    }

    async fn make_dns_client(
        &self,
        call: &EvaluatedCall,
    ) -> Result<
        (
            DnsClient,
            JoinSet<Result<(), hickory_proto::error::ProtoError>>,
        ),
        LabeledError,
    > {
        let protocol = match call.get_flag_value(flags::PROTOCOL) {
            None => None,
            Some(val) => Some(serde::Protocol::try_from(val).map(|serde::Protocol(proto)| proto)?),
        };

        let (addr, addr_span, protocol) = match call.get_flag_value(flags::SERVER) {
            Some(ref value @ Value::String { .. }) => {
                let protocol = protocol.unwrap_or(Protocol::Udp);
                let addr = SocketAddr::from_str(value.as_str().unwrap())
                    .or_else(|_| {
                        IpAddr::from_str(value.as_str().unwrap()).map(|ip| {
                            SocketAddr::new(ip, constants::config::default_port(protocol))
                        })
                    })
                    .map_err(|err| {
                        LabeledError::new("invalid server")
                            .with_label(err.to_string(), value.clone().span())
                    })?;

                (addr, Some(value.span()), protocol)
            }
            None => {
                let (config, _) =
                    hickory_resolver::system_conf::read_system_conf().unwrap_or_default();
                tracing::debug!(?config);
                match config.name_servers() {
                    [ns, ..] => (ns.socket_addr, None, ns.protocol),
                    [] => {
                        let config = ResolverConfig::default();
                        let ns = config.name_servers().first().unwrap();

                        // if protocol is explicitly configured, it should take
                        // precedence over the system config
                        (ns.socket_addr, None, protocol.unwrap_or(ns.protocol))
                    }
                }
            }
            Some(val) => {
                return Err(LabeledError::new("invalid server address")
                    .with_label("server address should be a string", val.span()));
            }
        };

        let (client, bg) = DnsClient::new(addr, addr_span, protocol, call).await?;

        tracing::debug!(client.addr = ?addr, client.protocol = ?protocol);

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
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        let _ = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();

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

        let client = plugin.dns_client(call).await?;
        let call = Arc::new(call.clone());

        match input {
            PipelineData::Value(val, _) => {
                if tracing::enabled!(tracing::Level::TRACE) {
                    tracing::trace!(phase = "input", data.kind = "value", ?val);
                } else {
                    tracing::debug!(phase = "input", data.kind = "value");
                }

                let values = Self::query(call, val, client.clone()).await;

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

                let (request_tx, mut request_rx) = tokio::sync::mpsc::channel(16);
                let (resp_tx, mut resp_rx) = tokio::sync::mpsc::channel(16);

                plugin.spawn({
                    let call = call.clone();
                    let client = client.clone();

                    async move {
                        let mut queue = FuturesUnordered::new();

                        while let Some(val) = Box::pin(request_rx.recv()).await {
                            tracing::trace!(query = ?val, query.phase = "received");

                            let call = call.clone();
                            let client = client.clone();
                            let resp_tx = resp_tx.clone();

                            let handle = tokio::spawn(async move {
                                let resps = Self::query(call, val, client).await;

                                for resp in resps.into_iter() {
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

                                Ok(())
                            });

                            queue.push(handle);

                            if queue.len() == 100 {
                                Self::drain_queue(&mut queue).await?;
                            }
                        }

                        Self::drain_queue(&mut queue).await
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

    async fn drain_queue(
        queue: &mut FuturesUnordered<DnsQueryJoinHandle>,
    ) -> Result<(), LabeledError> {
        for send in queue.iter_mut() {
            send.await.map_err(|join_err| {
                LabeledError::new("internal error")
                    .with_label(format!("task panicked: {}", join_err), Span::unknown())
            })??;
        }

        tracing::debug!(queue.phase = "drain");

        queue.clear();
        Ok(())
    }

    async fn query(call: Arc<EvaluatedCall>, input: Value, client: DnsClient) -> DnsQueryResult {
        let in_span = input.span();
        let queries = match Query::try_from_value(&input, &call) {
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
                let call = call.clone();

                async move {
                    let parts = query.0.into_parts();

                    if tracing::enabled!(tracing::Level::TRACE) {
                        tracing::trace!(query.phase = "start", query.parts = ?parts);
                    } else {
                        tracing::debug!(query.phase = "start");
                    }

                    client
                        .query(parts.name, parts.query_class, parts.query_type)
                        .await
                        .map_err(|err| {
                            LabeledError::new("DNS error")
                                .with_label(format!("Error in DNS response: {:?}", err), in_span)
                        })
                        .and_then(|resp: hickory_proto::xfer::DnsResponse| {
                            let msg = serde::Message::new(resp.into_message());
                            msg.into_value(&call)
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
