use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use futures_util::{stream::FuturesUnordered, StreamExt};
use hickory_client::client::ClientHandle;
use nu_plugin::{EngineInterface, EvaluatedCall};
use nu_protocol::{LabeledError, ListStream, PipelineData, Span, Value};

use hickory_resolver::config::{Protocol, ResolverConfig};

use tokio::{sync::mpsc::error::SendError, task::JoinHandle};
use tracing_subscriber::prelude::*;

use self::{client::DnsClient, constants::flags, serde::Query};

mod client;
mod constants;
mod nu;
mod serde;

#[derive(Debug)]
pub struct Dns;

#[derive(Debug)]
pub struct DnsQuery;

type ChannelSendJoinHandle =
    FuturesUnordered<JoinHandle<Result<(), SendError<Result<Vec<Value>, LabeledError>>>>>;

impl DnsQuery {
    async fn run_impl(
        &self,
        _plugin: &Dns,
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

        let (client, _bg) = DnsClient::new(addr, addr_span, protocol, call).await?;
        let call = Arc::new(call.clone());

        match input {
            PipelineData::Value(val, _) => {
                let values = Self::query(call, val, client.clone()).await?;
                Ok(PipelineData::Value(
                    Value::list(values, Span::unknown()),
                    None,
                ))
            }
            PipelineData::ListStream(mut stream, _) => {
                let (request_tx, mut request_rx) = tokio::sync::mpsc::channel(16);
                let (resp_tx, mut resp_rx) = tokio::sync::mpsc::channel(16);

                tokio::spawn({
                    let call = call.clone();
                    let client = client.clone();

                    async move {
                        let mut queue = FuturesUnordered::new();

                        while let Some(val) = Box::pin(request_rx.recv()).await {
                            let call = call.clone();
                            let client = client.clone();
                            let resp_tx = resp_tx.clone();

                            let handle = tokio::spawn(async move {
                                let resp = Self::query(call, val, client).await;
                                resp_tx.send(resp).await
                            });

                            queue.push(handle);

                            if queue.len() == 100 {
                                Self::drain_queue(&mut queue).await?;
                            }
                        }

                        Self::drain_queue(&mut queue).await
                    }
                });

                tokio::spawn(async move {
                    stream
                        .stream
                        .try_for_each(|val| request_tx.blocking_send(val))
                });

                Ok(PipelineData::ListStream(
                    ListStream::from_stream(
                        std::iter::from_fn(move || {
                            resp_rx.blocking_recv().map(|result| {
                                result.unwrap_or_else(|err| {
                                    vec![Value::error(err.into(), Span::unknown())]
                                })
                            })
                        })
                        .flatten(),
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

    async fn drain_queue(queue: &mut ChannelSendJoinHandle) -> Result<(), LabeledError> {
        for send in queue.iter_mut() {
            send.await
                .map_err(|join_err| {
                    LabeledError::new("internal error")
                        .with_label(format!("task panicked: {}", join_err), Span::unknown())
                })?
                .map_err(|send_err| {
                    LabeledError::new("internal error").with_label(
                        format!("failed to send dns query result: {}", send_err),
                        Span::unknown(),
                    )
                })?;
        }

        queue.clear();
        Ok(())
    }

    async fn query(
        call: Arc<EvaluatedCall>,
        input: Value,
        client: DnsClient,
    ) -> Result<Vec<Value>, LabeledError> {
        let in_span = input.span();
        let queries = Query::try_from_value(&input, &call)?;

        futures_util::stream::iter(queries)
            .then(|query| {
                let mut client = client.clone();
                let call = call.clone();

                async move {
                    let parts = query.0.into_parts();

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
                }
            })
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
    }
}
