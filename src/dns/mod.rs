use std::str::FromStr;

use nu_plugin::{EvaluatedCall, LabeledError};
use nu_protocol::{Span, Value};
use tokio::net::UdpSocket;
use trust_dns_client::client::{AsyncClient, ClientHandle};
use trust_dns_proto::{
    rr::{DNSClass, RecordType},
    udp::UdpClientStream,
};
use trust_dns_resolver::{
    config::{Protocol, ResolverConfig},
    proto::error::ProtoError,
    Name,
};

use self::serde::RType;

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
                Name::from_labels(vals.into_iter().map(|val| {
                    if let Value::Binary { val: bin_val, .. } = val {
                        bin_val
                    } else {
                        unreachable!("Invalid input type");
                    }
                })),
                span,
            ),
            _ => unreachable!("Invalid input type"),
        };

        let name = name.map_err(|err| parse_name_err(err, name_span))?;
        let (config, _) = trust_dns_resolver::system_conf::read_system_conf().unwrap_or_default();
        let (addr, protocol) = match config.name_servers() {
            [ns, ..] => (ns.socket_addr, ns.protocol),
            [] => {
                let config = ResolverConfig::default();
                let ns = config.name_servers().first().unwrap();
                (ns.socket_addr, ns.protocol)
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

        let class_err = |err: ProtoError, span: Span| LabeledError {
            label: "InvalidDNSClass".into(),
            msg: format!("Error parsing DNS class: {}", err),
            span: Some(span),
        };

        let dns_class: DNSClass = match call.get_flag_value("class") {
            Some(Value::String { val, span }) => {
                DNSClass::from_str(&val.to_uppercase()).map_err(|err| class_err(err, span))?
            }
            Some(Value::Int { val, span }) => {
                DNSClass::from_u16(val as u16).map_err(|err| class_err(err, span))?
            }
            None => DNSClass::IN,
            Some(value) => {
                return Err(LabeledError {
                    label: "InvalidClassType".into(),
                    msg: "Invalid type for class type argument. Must be either string or int."
                        .into(),
                    span: Some(value.span()?),
                });
            }
        };

        let (mut client, bg) = match protocol {
            Protocol::Udp => {
                let conn = UdpClientStream::<UdpSocket>::new(addr);
                AsyncClient::connect(conn)
                    .await
                    .map_err(|err| LabeledError {
                        label: "UdpConnectError".into(),
                        msg: format!("Error creating UDP client connection: {}", err),
                        span: None,
                    })?
            }
            Protocol::Tcp => todo!(),
            _ => todo!(),
        };

        let _bg_handle = tokio::spawn(bg);
        let mut messages = Vec::new();

        for qtype in qtypes {
            let resp = client
                .query(name.clone(), dns_class, qtype)
                .await
                .map_err(|err| LabeledError {
                    label: "DNSResponseError".into(),
                    msg: format!("Error in DNS response: {}", err),
                    span: None,
                })?;

            messages.push(serde::Message(&resp.into_inner()).into_value(call));
        }

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
