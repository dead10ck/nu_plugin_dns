use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use nu_plugin::{EvaluatedCall, LabeledError};
use nu_protocol::{Span, Value};
use trust_dns_client::client::ClientHandle;
use trust_dns_proto::rr::{DNSClass, RecordType};
use trust_dns_resolver::{
    config::{Protocol, ResolverConfig},
    proto::error::ProtoError,
    Name,
};

use self::{client::DnsClient, serde::RType};

mod client;
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
            "dns query" => self.query(call, input).await,
            _ => Err(LabeledError {
                label: "No such command".into(),
                msg: "No such command".into(),
                span: Some(call.head),
            }),
        }
    }

    async fn query(&self, call: &EvaluatedCall, _input: &Value) -> Result<Value, LabeledError> {
        let (name, name_span) = match call.req(0)? {
            Value::String { val, span } => (Name::from_utf8(val), span),
            Value::List { vals, span } => (
                Name::from_labels(
                    vals.into_iter()
                        .map(|val| {
                            if let Value::Binary { val: bin_val, .. } = val {
                                Ok(bin_val)
                            } else {
                                Err(LabeledError {
                                    label: "InvalidNameError".into(),
                                    msg: "Invalid input type for name".into(),
                                    span: Some(val.span()?),
                                })
                            }
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                span,
            ),
            val => {
                return Err(LabeledError {
                    label: "InvalidInputTypeError".into(),
                    msg: "Invalid input type".into(),
                    span: Some(val.span()?),
                })
            }
        };

        let name = name.map_err(|err| parse_name_err(err, name_span))?;

        let protocol = match call.get_flag_value("protocol") {
            None => None,
            Some(val) => Some(serde::Protocol::try_from(val).map(|serde::Protocol(proto)| proto)?),
        };

        let (addr, addr_span, protocol) = match call.get_flag_value("server") {
            Some(Value::String { val, span }) => {
                let addr = SocketAddr::from_str(&val)
                    .or_else(|_| IpAddr::from_str(&val).map(|ip| SocketAddr::new(ip, 53)))
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

        let qtypes: Vec<RecordType> = match call.get_flag_value("type") {
            Some(Value::List { vals, .. }) => vals
                .into_iter()
                .map(RType::try_from)
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .map(|RType(rtype)| rtype)
                .collect(),
            Some(val) => vec![RType::try_from(val)?.0],
            None => vec![RecordType::AAAA, RecordType::A],
        };

        let dns_class: DNSClass = match call.get_flag_value("class") {
            Some(val) => serde::DNSClass::try_from(val)?.0,
            None => DNSClass::IN,
        };

        let dnssec_mode = match call.get_flag_value("dnssec") {
            Some(val) => serde::DnssecMode::try_from(val)?,
            None => serde::DnssecMode::Opportunistic,
        };

        let (mut client, _bg) = DnsClient::new(addr, addr_span, protocol, dnssec_mode).await?;

        let mut messages: Vec<_> = futures_util::future::join_all(
            qtypes
                .into_iter()
                .map(|qtype| client.query(name.clone(), dns_class, qtype)),
        )
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| LabeledError {
            label: "DNSResponseError".into(),
            msg: format!("Error in DNS response: {:?}", err),
            span: None,
        })?
        .into_iter()
        .map(|resp| serde::Message(&resp.into_inner()).into_value(call))
        .collect();

        let result = Value::record(
            vec!["name_server".into(), "message".into()],
            vec![
                Value::record(
                    vec!["address".into(), "protocol".into()],
                    vec![
                        Value::string(addr.to_string(), Span::unknown()),
                        Value::string(protocol.to_string(), Span::unknown()),
                    ],
                    Span::unknown(),
                ),
                match messages.len() {
                    0 => Value::Nothing {
                        span: Span::unknown(),
                    },
                    1 => messages.pop().unwrap(),
                    _ => Value::list(messages, Span::unknown()),
                }, // serde::Message(&message).into_value(call),
            ],
            Span::unknown(),
        );

        Ok(result)
    }
}

fn parse_name_err(err: ProtoError, span: Span) -> LabeledError {
    LabeledError {
        label: "DnsNameParseError".into(),
        msg: format!("Error parsing as DNS name: {}", err),
        span: Some(span),
    }
}
