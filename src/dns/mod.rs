use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use nu_plugin::{EvaluatedCall, LabeledError};
use nu_protocol::{Span, Value};

use trust_dns_client::client::ClientHandle;
use trust_dns_resolver::config::{Protocol, ResolverConfig};

use self::{client::DnsClient, constants::flags, serde::Query};

mod client;
mod constants;
mod nu;
mod serde;

pub struct Dns {}

impl Dns {
    async fn run_impl(
        &mut self,
        name: &str,
        call: &EvaluatedCall,
        input: &Value,
    ) -> Result<Value, LabeledError> {
        match name {
            constants::commands::QUERY => self.query(call, input).await,
            _ => Err(LabeledError {
                label: "NoSuchCommandError".into(),
                msg: "No such command".into(),
                span: Some(call.head),
            }),
        }
    }

    fn get_queries(vals: &[&Value], call: &EvaluatedCall) -> Result<Vec<Query>, LabeledError> {
        vals.iter()
            .map(|input_val| match input_val {
                Value::List { vals, .. } => {
                    if vals.iter().all(|val| matches!(val, Value::Binary { .. })) {
                        return Query::try_from_value(input_val, call);
                    }

                    Dns::get_queries(&vals.iter().collect::<Vec<_>>(), call)
                }
                _ => Query::try_from_value(input_val, call),
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|res| res.into_iter().flatten().collect())
    }

    async fn query(&self, call: &EvaluatedCall, input: &Value) -> Result<Value, LabeledError> {
        let arg_inputs: Vec<Value> = call.rest(0)?;
        let input: Vec<&Value> = match input {
            Value::Nothing { .. } => arg_inputs.iter().collect(),
            val => {
                if !arg_inputs.is_empty() {
                    return Err(LabeledError {
                        label: "AmbiguousInputError".into(),
                        msg: "Input should either be positional args or piped, but not both".into(),
                        span: Some(val.span()?),
                    });
                }

                vec![val]
            }
        };

        let protocol = match call.get_flag_value(flags::PROTOCOL) {
            None => None,
            Some(val) => Some(serde::Protocol::try_from(val).map(|serde::Protocol(proto)| proto)?),
        };

        let (addr, addr_span, protocol) = match call.get_flag_value(flags::SERVER) {
            Some(Value::String { val, span }) => {
                let addr = SocketAddr::from_str(&val)
                    .or_else(|_| {
                        IpAddr::from_str(&val)
                            .map(|ip| SocketAddr::new(ip, constants::config::SERVER_PORT))
                    })
                    .map_err(|err| LabeledError {
                        label: "InvalidServerAddress".into(),
                        msg: format!("Invalid server: {}", err),
                        span: Some(span),
                    })?;

                (addr, Some(span), protocol.unwrap_or(Protocol::Udp))
            }
            None => {
                let (config, _) =
                    trust_dns_resolver::system_conf::read_system_conf().unwrap_or_default();
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
                return Err(LabeledError {
                    label: "InvalidServerAddressInputError".into(),
                    msg: "invalid input type for server address".into(),
                    span: Some(val.span()?),
                })
            }
        };

        let queries: Vec<Query> = Dns::get_queries(&input, call)?;

        let dnssec_mode = match call.get_flag_value(flags::DNSSEC) {
            Some(val) => serde::DnssecMode::try_from(val)?,
            None => serde::DnssecMode::Opportunistic,
        };

        let (mut client, _bg) = DnsClient::new(addr, addr_span, protocol, dnssec_mode).await?;

        let mut total_size = 0;

        let messages: Vec<_> = futures_util::future::join_all(queries.into_iter().map(|query| {
            let parts = query.0.into_parts();
            client.query(parts.name, parts.query_class, parts.query_type)
        }))
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| LabeledError {
            label: "DNSResponseError".into(),
            msg: format!("Error in DNS response: {:?}", err),
            span: None,
        })?
        .into_iter()
        .map(|resp: trust_dns_proto::xfer::DnsResponse| {
            let msg = serde::Message::new(resp.into_inner());
            total_size += msg.size();
            msg.into_value(call)
        })
        .collect();

        let result = Value::record(
            Vec::from_iter(constants::columns::TOP_COLS.iter().map(|s| (*s).into())),
            vec![
                Value::record(
                    vec![
                        constants::columns::ADDRESS.into(),
                        constants::columns::PROTOCOL.into(),
                    ],
                    vec![
                        Value::string(addr.to_string(), Span::unknown()),
                        Value::string(protocol.to_string(), Span::unknown()),
                    ],
                    Span::unknown(),
                ),
                Value::filesize(total_size as i64, Span::unknown()),
                Value::list(messages, Span::unknown()),
            ],
            Span::unknown(),
        );

        Ok(result)
    }
}
