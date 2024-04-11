use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use futures_util::{future, StreamExt};
use hickory_client::client::ClientHandle;
use nu_plugin::{EngineInterface, EvaluatedCall};
use nu_protocol::{LabeledError, ListStream, PipelineData, Span, Value};

use hickory_resolver::config::{Protocol, ResolverConfig};

use tokio::{stream, sync::Mutex};
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
        let client = Arc::new(Mutex::new(client));

        // .await
        // .unwrap_or_else(|err| Value::string(err.to_string(), Span::unknown()))
        match input {
            PipelineData::Value(val, _) => {
                let values = self.query(call, val, client.clone()).await?;
                Ok(PipelineData::Value(
                    Value::list(values, Span::unknown()),
                    None,
                ))
            }
            PipelineData::ListStream(stream, _) => {
                // let query_stream = futures_util::stream::iter(stream.stream);
                // .map(|val| self.query(call, val, client.clone()));

                let (request_tx, mut request_rx) = tokio::sync::mpsc::channel(16);
                let (resp_tx, mut resp_rx) = tokio::sync::mpsc::channel(16);

                let query_handle = tokio::spawn(async move {
                    while let Some(val) = request_rx.recv().await {
                        let client = client.clone();
                        let resp_tx = resp_tx.clone();
                        tokio::spawn(async move {
                            let client = client.clone();
                            let resp_tx = resp_tx.clone();
                            let resp = self.query(call, val, client).await;
                            resp_tx.send(resp).await
                        });
                    }
                });

                let pipeline_handle = tokio::spawn(async move {
                    stream
                        .stream
                        .try_for_each(|val| request_tx.blocking_send(val))
                });

                Ok(PipelineData::ListStream(
                    ListStream::from_stream(
                        std::iter::from_fn(|| {
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

    async fn query(
        &self,
        call: &EvaluatedCall,
        input: Value,
        client: Arc<Mutex<DnsClient>>,
    ) -> Result<Vec<Value>, LabeledError> {
        let queries: Vec<Query> = Query::try_from_value(&input, call)?;

        let mut client = client.lock_owned().await;

        futures_util::future::join_all(queries.into_iter().map(|query| {
            let parts = query.0.into_parts();
            client.query(parts.name, parts.query_class, parts.query_type)
        }))
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            LabeledError::new("DNS error")
                .with_label(format!("Error in DNS response: {:?}", err), input.span())
        })?
        .into_iter()
        .map(|resp: hickory_proto::xfer::DnsResponse| {
            let msg = serde::Message::new(resp.into_message());
            msg.into_value(call)
        })
        .collect::<Result<_, _>>()
    }
}
