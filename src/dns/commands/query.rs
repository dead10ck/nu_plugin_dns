use std::{
    pin::Pin,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use futures_util::{stream::FuturesOrdered, Future, FutureExt, StreamExt, TryStreamExt};
use hickory_client::client::ClientHandle;
use nu_plugin::{EngineInterface, EvaluatedCall, PluginCommand};
use nu_protocol::{
    Example, IntoValue, LabeledError, ListStream, PipelineData, Signals, Signature, Span,
    SyntaxShape, Value,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::prelude::*;

use crate::{
    dns::{
        client::{BgHandle, DnsClient},
        config::Config,
        constants,
        serde::{self, Query},
    },
    Dns,
};

pub type DnsQueryResult =
    FuturesOrdered<Pin<Box<dyn Future<Output = Result<Value, LabeledError>> + Send>>>;
pub type DnsQueryPluginClient = Arc<tokio::sync::RwLock<Option<(DnsClient, BgHandle)>>>;

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

                let values = Self::query(config, val, client.clone())
                    .await
                    .try_collect::<Vec<_>>()
                    .await?;

                let val = PipelineData::Value(Value::list(values, Span::unknown()), None);

                tracing::trace!(phase = "return", ?val);

                Ok(val)
            }
            PipelineData::ListStream(stream, _) => {
                tracing::debug!(phase = "input", data.kind = "stream");

                let span = stream.span();
                let ctrlc = Signals::new(Arc::new(AtomicBool::new(false)));
                let (request_tx, request_rx) = mpsc::channel(config.tasks.item);
                let (resp_tx, mut resp_rx) = mpsc::channel(config.tasks.item);

                plugin.spawn(watch_sigterm(
                    ctrlc.clone(),
                    plugin.cancel.clone(),
                    plugin.client.clone(),
                ));

                plugin.spawn(coordinate_queries(
                    config,
                    client,
                    request_rx,
                    resp_tx,
                    plugin.cancel.clone(),
                ));

                plugin
                    .spawn_blocking({
                        let cancel = plugin.cancel.clone();
                        move || stream_requests(stream, cancel, request_tx)
                    })
                    .await;

                Ok(PipelineData::ListStream(
                    ListStream::new(
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
                        span,
                        ctrlc,
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
                return vec![
                    Box::pin(std::future::ready(Ok(Value::error(err.into(), in_span))))
                        as Pin<Box<dyn Future<Output = _> + Send>>,
                ]
                .into_iter()
                .collect()
            }
        };

        tracing::debug!(request.queries = ?queries);

        let mut responses = FuturesOrdered::new();

        for query in queries {
            let mut client = client.clone();
            let config = config.clone();

            let resp = async move {
                let parts = query.0;

                tracing::info!(query.phase = "start", query.parts = ?parts);

                let request = tokio::time::timeout(
                    config.timeout.item,
                    client.query(parts.name.clone(), parts.query_class, parts.query_type),
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
                        let resp = serde::Response::new(resp);

                        if tracing::enabled!(tracing::Level::DEBUG) {
                            tracing::debug!(query.phase = "finish", query.parts = ?parts, query.resp = ?resp);
                        } else {
                            tracing::info!(query.phase = "finish", query.parts = ?parts);
                        }

                        resp.into_value(config.code.item)
                    })
                    .inspect_err(
                        |err| tracing::debug!(query.phase = "finish", query.error = ?err),
                    )
                    .inspect(|resp| {
                        log_response_val(resp, "finish");
                    })
            };

            // apparently you cannot just collect this into a `FuturesOrdered`
            // because doing so causes each future to be polled in serial,
            // completely defeating the point
            responses.push_back(Box::pin(resp) as Pin<Box<dyn Future<Output = _> + Send>>);
        }

        responses
    }
}

async fn watch_sigterm(
    ctrlc: Signals,
    cancel: CancellationToken,
    client: DnsQueryPluginClient,
) -> Result<(), LabeledError> {
    while !ctrlc.interrupted()
        && client
            .write()
            .await
            .as_mut()
            .is_some_and(|bg| (&mut bg.1).now_or_never().is_none())
    {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    cancel.cancel();
    Ok(())
}

fn stream_requests(
    stream: ListStream,
    cancel: CancellationToken,
    request_tx: mpsc::Sender<Value>,
) -> Result<(), LabeledError> {
    tracing::trace!(task.sender.phase = "start");

    let result = stream.into_iter().try_for_each(|val| {
        tracing::trace!(query = ?val, query.phase = "send");

        if cancel.is_cancelled() {
            return Err(LabeledError::new("canceled"));
        }

        request_tx.blocking_send(val).map_err(|send_err| {
            LabeledError::new("internal error").with_label(
                format!("failed to send dns query result: {}", send_err),
                Span::unknown(),
            )
        })
    });

    tracing::trace!(task.sender.phase = "exit", task.sender.result = ?result);

    result
}

async fn coordinate_queries(
    config: Arc<Config>,
    client: DnsClient,
    mut request_rx: mpsc::Receiver<Value>,
    resp_tx: mpsc::Sender<Result<Value, LabeledError>>,
    cancel: CancellationToken,
) -> Result<(), LabeledError> {
    tracing::trace!(task.query_coordinator.phase = "start");
    let mut buf = Vec::with_capacity(config.tasks.item);

    while request_rx.recv_many(&mut buf, config.tasks.item).await > 0 {
        tracing::trace!(query.phase = "batch received", query.batchsize = buf.len());

        let config = config.clone();
        let client = client.clone();
        let cancel = cancel.clone();

        let val = std::mem::replace(&mut buf, Vec::with_capacity(config.tasks.item))
            .into_value(Span::unknown());

        tracing::trace!(task.query_exec.phase = "start");

        let mut result = tokio::select! {
            _ = cancel.cancelled() => vec![Box::pin(std::future::ready(Err(LabeledError::new("canceled")))) as Pin<Box<dyn Future<Output = _> + Send>>].into_iter().collect(),
            resp = DnsQuery::query(config, val, client) => resp,
        };

        tracing::trace!(
            task.query_exec.phase = "end",
            task.query_exec.result = ?result
        );

        while let Some(resp) = StreamExt::next(&mut result).await {
            resp_tx.send(resp).await.map_err(|send_err| {
                LabeledError::new("internal error").with_label(
                    format!("failed to send dns query result: {}", send_err),
                    Span::unknown(),
                )
            })?;
        }
    }

    tracing::trace!(task.query_coordinator.phase = "exit");

    Ok(())
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
            .main_runtime
            .block_on(self.run_impl(plugin, engine, call, input))
    }

    fn name(&self) -> &str {
        constants::commands::QUERY
    }

    fn description(&self) -> &str {
        "Perform a DNS query"
    }

    fn signature(&self) -> nu_protocol::Signature {
        Signature::build(self.name())
            .rest(
                constants::flags::NAME,

                // [NOTE] this does not work
                // SyntaxShape::OneOf(vec![
                //     SyntaxShape::String,
                //     SyntaxShape::List(Box::new(SyntaxShape::OneOf(vec![
                //         SyntaxShape::String,
                //         SyntaxShape::Binary,
                //         SyntaxShape::Int,
                //         SyntaxShape::Boolean,
                //     ]))),
                // ]),
                SyntaxShape::Any,

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
                "Perform DNSSEC validation on records. Choices are: \"none\", \"opportunistic\" (validate if RRSIGs present, otherwise no validation; default)",
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
                format!("Number of concurrent tasks to execute queries. Please be mindful not to overwhelm your nameserver! Default: {}", constants::config::default::TASKS),
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
                example: "[ $\"ding(char -u '07')-ds\", \"metric\", \"gstatic\", \"com\" ] | each { into binary } | collect { $in } | dns query",
                description: "query record name that has labels with non-renderable bytes",
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
