use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use futures_util::{
    stream::{FuturesOrdered, FuturesUnordered},
    StreamExt,
};
use hickory_client::client::ClientHandle;
use nu_plugin::{EngineInterface, EvaluatedCall, Plugin, PluginCommand};
use nu_protocol::{
    Example, LabeledError, ListStream, PipelineData, Signature, Span, SyntaxShape, Type, Value,
};
use tokio::task::JoinSet;
use tracing_subscriber::prelude::*;

use crate::{
    dns::{
        client::DnsClient,
        config::Config,
        constants,
        serde::{self, Query},
    },
    Dns,
};

pub type DnsQueryResult = FuturesUnordered<Result<Value, LabeledError>>;
pub type DnsQueryPluginClient = Arc<
    tokio::sync::RwLock<
        Option<(
            DnsClient,
            JoinSet<Result<(), hickory_proto::error::ProtoError>>,
        )>,
    >,
>;

#[derive(Debug)]
pub struct DnsQuery;

impl DnsQuery {
    pub(crate) async fn run_impl(
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

                let ctrlc = stream.ctrlc.clone();
                let (request_tx, mut request_rx) = tokio::sync::mpsc::channel(config.tasks.item);
                let (resp_tx, mut resp_rx) = tokio::sync::mpsc::channel(config.tasks.item);

                plugin
                    .spawn({
                        tracing::trace!(task.query_coordinator.phase = "start");

                        let client = client.clone();
                        let ctrlc = ctrlc.clone();

                        async move {
                            let mut buf = Vec::with_capacity(config.tasks.item);
                            let mut result_queue = FuturesOrdered::new();

                            while request_rx.recv_many(&mut buf, config.tasks.item).await > 0 {
                                tracing::trace!(
                                    query.phase = "batch received",
                                    query.batchsize = buf.len()
                                );

                                check_ctrlc(ctrlc.clone())?;

                                for val in buf.drain(..) {
                                    let ctrlc = ctrlc.clone();
                                    tracing::trace!(query = ?val, query.phase = "received");

                                    let config = config.clone();
                                    let client = client.clone();

                                    let handle = tokio::spawn(async move {
                                        tracing::trace!(task.query_exec.phase = "start");

                                        if let Err(err) = check_ctrlc(ctrlc) {
                                            return vec![Err(err)]
                                                .into_iter()
                                                .collect::<DnsQueryResult>();
                                        };

                                        let result = Self::query(config, val, client).await;

                                        tracing::trace!(
                                            task.query_exec.phase = "end",
                                            task.query_exec.result = ?result
                                        );

                                        result
                                    });

                                    result_queue.push_back(handle);
                                }

                                while let Some(query_result) = result_queue.next().await {
                                    check_ctrlc(ctrlc.clone())?;

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

                            tracing::trace!(task.query_coordinator.phase = "exit");

                            Ok(())
                        }
                    })
                    .await;

                plugin
                    .spawn_blocking(move || {
                        tracing::trace!(task.sender.phase = "start");

                        let result = stream.stream.try_for_each(|val| {
                            let ctrlc = ctrlc.clone();
                            tracing::trace!(query = ?val, query.phase = "send");
                            check_ctrlc(ctrlc)?;

                            request_tx.blocking_send(val).map_err(|send_err| {
                                LabeledError::new("internal error").with_label(
                                    format!("failed to send dns query result: {}", send_err),
                                    Span::unknown(),
                                )
                            })
                        });

                        tracing::trace!(task.sender.phase = "exit", task.sender.result = ?result);

                        result
                    })
                    .await;

                Ok(PipelineData::ListStream(
                    ListStream::from_stream(
                        std::iter::from_fn(move || {
                            tokio::task::block_in_place(|| {
                                resp_rx.blocking_recv().map(|resp| {
                                    resp.unwrap_or_else(|err| {
                                        Value::error(err.into(), Span::unknown())
                                    })
                                })
                            })
                        })
                        .inspect(|val| log_response_val(val, "return")),
                        stream.ctrlc.clone(),
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

    pub(crate) async fn query(
        config: Arc<Config>,
        input: Value,
        client: DnsClient,
    ) -> DnsQueryResult {
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
                        .inspect(|resp| {
                            log_response_val(resp, "finish");
                        })
                }
            })
            .collect::<FuturesUnordered<_>>()
            .await
    }
}

pub(crate) fn log_response_val(resp: &Value, phase: &str) {
    if tracing::enabled!(tracing::Level::TRACE) {
        tracing::trace!(query.phase = phase, query.response = ?resp)
    } else {
        let question = resp.get_data_by_key("question");
        let answer = resp.get_data_by_key("answer");
        tracing::debug!(
            query.phase = phase,
            query.response.question = ?question,
            query.response.answer = ?answer
        );
    }
}

pub(crate) fn check_ctrlc(ctrlc: Option<Arc<AtomicBool>>) -> Result<(), LabeledError> {
    let canceled = ctrlc
        .as_ref()
        .is_some_and(|ctrlc| ctrlc.load(Ordering::Relaxed));

    tracing::trace!("ctrlc: {canceled}");

    if canceled {
        return Err(LabeledError::new("internal error").with_label("cancelled", Span::unknown()));
    }

    Ok(())
}

impl Plugin for Dns {
    fn commands(&self) -> Vec<Box<dyn PluginCommand<Plugin = Self>>> {
        vec![Box::new(DnsQuery)]
    }
}

impl PluginCommand for DnsQuery {
    type Plugin = Dns;

    fn run(
        &self,
        plugin: &Self::Plugin,
        engine: &EngineInterface,
        call: &EvaluatedCall,
        input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        plugin
            .runtime
            .block_on(self.run_impl(plugin, engine, call, input))
    }

    fn name(&self) -> &str {
        constants::commands::QUERY
    }

    fn usage(&self) -> &str {
        "Perform a DNS query"
    }

    fn signature(&self) -> nu_protocol::Signature {
        Signature::build(self.name())
            .input_output_types(vec![
                (Type::String, Type::Any),
                (Type::List(Type::Any.into()), Type::Any),
            ])
            .rest(
                constants::flags::NAME,
                SyntaxShape::OneOf(vec![
                    SyntaxShape::String,
                    SyntaxShape::List(Box::new(SyntaxShape::OneOf(vec![
                        SyntaxShape::String,
                        SyntaxShape::Binary,
                        SyntaxShape::Int,
                        SyntaxShape::Boolean,
                    ]))),
                ]),
                "DNS record name",
            )
            .named(
                constants::flags::SERVER,
                SyntaxShape::String,
                "Nameserver to query (defaults to system config or 8.8.8.8)",
                Some('s'),
            )
            .named(
                constants::flags::PROTOCOL,
                SyntaxShape::String,
                "Protocol to use to connect to the nameserver: UDP, TCP. (default: UDP)",
                Some('p'),
            )
            .named(constants::flags::TYPE, SyntaxShape::Any, "Query type", Some('t'))
            .named(constants::flags::CLASS, SyntaxShape::Any, "Query class", None)
            .switch(
                constants::flags::CODE,
                "Return code fields with both string and numeric representations",
                Some('c'),
            )
            .named(
                constants::flags::DNSSEC,
                SyntaxShape::String,
                "Perform DNSSEC validation on records. Choices are: \"none\", \"strict\" (error if record has no RRSIG or does not validate), \"opportunistic\" (validate if RRSIGs present, otherwise no validation; default)",
                Some('d'),
            )
            .named(
                constants::flags::DNS_NAME,
                SyntaxShape::String,
                "DNS name of the TLS certificate in use by the nameserver (for TLS and HTTPS only)",
                Some('n'),
            )
            .named(
                constants::flags::TASKS,
                SyntaxShape::Int,
                format!("Number of concurrent tasks to execute queries. Default: {}", constants::config::default::TASKS),
                Some('j'),
            )
            .named(
                constants::flags::TIMEOUT,
                SyntaxShape::Duration,
                format!("How long a request can take before timing out. Be aware the concurrency level can affect this. Default: {}sec", constants::config::default::TIMEOUT.as_secs()),
                None,
            )
    }

    fn examples(&self) -> Vec<nu_protocol::Example> {
        vec![
            Example {
                example: "dns query google.com",
                description: "simple query for A / AAAA records",
                result: None,
            },
            Example {
                example: "dns query --type CNAME google.com",
                description: "specify query type",
                result: None,
            },
            Example {
                example: "dns query --type [cname, mx] -c google.com",
                description: "specify multiple query types",
                result: None,
            },
            Example {
                example: "dns query --type [5, 15] -c google.com",
                description: "specify query types by numeric ID, and get numeric IDs in output",
                result: None,
            },
            Example {
                example: "'google.com' | dns query",
                description: "pipe name to command",
                result: None,
            },
            Example {
                example: "['google.com', 'amazon.com'] | dns query",
                description: "pipe lists of names to command",
                result: None,
            },
            Example {
                example: "[{{name: 'google.com', type: 'A'}}, {{name: 'amazon.com', type: 'A'}}] | dns query",
                description: "pipe table of queries to command (ignores --type flag)",
                result: None,
            },
        ]
    }

    fn search_terms(&self) -> Vec<&str> {
        vec!["dns", "network", "dig"]
    }
}
