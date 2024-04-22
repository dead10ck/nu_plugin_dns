use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use hickory_proto::rr::{DNSClass, RecordType};
use hickory_resolver::config::{Protocol, ResolverConfig};
use nu_plugin::EvaluatedCall;
use nu_protocol::{record, LabeledError, Span, Spanned, Value};

use crate::spanned;

use super::{
    constants::{self, flags},
    serde::{self, DnssecMode, RType},
};

#[derive(Debug)]
pub struct Config {
    pub protocol: Spanned<Protocol>,
    pub server: Spanned<SocketAddr>,

    pub qtypes: Spanned<Vec<Spanned<RecordType>>>,
    pub class: Spanned<DNSClass>,

    pub code: Spanned<bool>,
    pub dnssec_mode: Spanned<DnssecMode>,
    pub dns_name: Option<Spanned<String>>,

    pub tasks: Spanned<usize>,
    pub timeout: Spanned<Duration>,
}

impl TryFrom<Value> for Config {
    type Error = LabeledError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let mut record = value.into_record()?;
        Config::from_values(|name| record.remove(name))
    }
}

impl TryFrom<&EvaluatedCall> for Config {
    type Error = LabeledError;

    fn try_from(call: &EvaluatedCall) -> Result<Self, Self::Error> {
        Config::from_values(|name| call.get_flag_value(name))
    }
}

impl Config {
    pub fn from_nu(
        plugin_config: Option<Value>,
        call: &EvaluatedCall,
    ) -> Result<Self, LabeledError> {
        tracing::debug!(?plugin_config, ?call);

        let plugin_config = match plugin_config {
            None => Value::record(record!(), Span::unknown()),
            Some(cfg) => cfg,
        };

        Config::from_values(|name| {
            let cfg_val = plugin_config.get_data_by_key(name);
            let call_val = match (call.has_flag(name), call.get_flag_value(name)) {
                (Ok(true), None) => Some(Value::bool(true, Span::unknown())),
                (_, val) => val,
            };

            match (cfg_val, call_val) {
                (None, None) => None,
                (None, val @ Some(_)) => val,
                (val @ Some(_), None) => val,

                // CLI flags take precedence over config
                (Some(_), callv @ Some(_)) => callv,
            }
        })
    }

    pub fn from_values<F>(mut get_value: F) -> Result<Self, LabeledError>
    where
        F: FnMut(&str) -> Option<Value>,
    {
        let protocol = match get_value(flags::PROTOCOL) {
            None => None,
            Some(val) => {
                let span = val.span();
                Some(
                    serde::Protocol::try_from(val)
                        .map(|serde::Protocol(proto)| spanned!(proto, span))?,
                )
            }
        };

        let needs_dns_name = matches!(
            protocol,
            Some(Spanned {
                item: Protocol::Tls | Protocol::Https | Protocol::Quic,
                ..
            })
        );

        let dns_name = match get_value(constants::flags::DNS_NAME) {
            None => None,
            Some(val) => {
                let span = val.span();

                if !needs_dns_name {
                    return Err(LabeledError::new("invalid config combination").with_label(
                        "DNS name only makes sense for TLS, HTTPS, or QUIC",
                        val.span(),
                    ));
                }

                Some(spanned!(val.into_string()?, span))
            }
        };

        let (addr, protocol) = match get_value(flags::SERVER) {
            Some(ref value @ Value::String { .. }) => {
                let protocol = protocol.unwrap_or(spanned!(Protocol::Udp, Span::unknown()));

                let addr = SocketAddr::from_str(value.as_str().unwrap())
                    .or_else(|_| {
                        IpAddr::from_str(value.as_str().unwrap()).map(|ip| {
                            SocketAddr::new(ip, constants::config::default_port(protocol.item))
                        })
                    })
                    .map_err(|err| {
                        LabeledError::new("invalid server")
                            .with_label(err.to_string(), value.clone().span())
                    })?;

                let addr = spanned!(addr, value.span());

                (addr, protocol)
            }
            None => {
                let (config, _) =
                    hickory_resolver::system_conf::read_system_conf().unwrap_or_default();
                tracing::debug!(?config);
                match config.name_servers() {
                    [ns, ..] => (
                        spanned!(ns.socket_addr, Span::unknown()),
                        spanned!(ns.protocol, Span::unknown()),
                    ),
                    [] => {
                        let config = ResolverConfig::default();
                        let ns = config.name_servers().first().unwrap();

                        // if protocol is explicitly configured, it should take
                        // precedence over the system config
                        (
                            spanned!(ns.socket_addr, Span::unknown()),
                            protocol.unwrap_or(spanned!(ns.protocol, Span::unknown())),
                        )
                    }
                }
            }
            Some(val) => {
                return Err(LabeledError::new("invalid server address")
                    .with_label("server address should be a string", val.span()));
            }
        };

        if needs_dns_name && dns_name.is_none() {
            return Err(LabeledError::new("need DNS name").with_label(
                "protocol needs to be accompanied by --dns-name",
                protocol.span,
            ));
        }

        let qtypes: Spanned<Vec<Spanned<RecordType>>> = match get_value(constants::flags::TYPE) {
            Some(list @ Value::List { .. }) => {
                let span = list.span();
                let vals = list.as_list()?;

                spanned!(
                    vals.iter()
                        .map(|val| {
                            let span = val.span();
                            Result::<_, LabeledError>::Ok(spanned!(RType::try_from(val)?.0, span))
                        })
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .collect(),
                    span
                )
            }
            Some(ref val) => spanned!(
                vec![spanned!(RType::try_from(val)?.0, val.span())],
                val.span()
            ),
            None => spanned!(
                vec![
                    spanned!(RecordType::AAAA, Span::unknown()),
                    spanned!(RecordType::A, Span::unknown()),
                ],
                Span::unknown()
            ),
        };

        let class = match get_value(constants::flags::CLASS) {
            Some(val) => {
                let span = val.span();
                spanned!(crate::dns::serde::DNSClass::try_from(val)?.0, span)
            }
            None => spanned!(hickory_proto::rr::DNSClass::IN, Span::unknown()),
        };

        let code = match get_value(constants::flags::CODE) {
            Some(val @ Value::Bool { .. }) => {
                spanned!(val.as_bool().unwrap(), val.span())
            }
            _ => spanned!(false, Span::unknown()),
        };

        let dnssec_mode = match get_value(constants::flags::DNSSEC) {
            Some(val) => {
                let span = val.span();
                spanned!(serde::DnssecMode::try_from(val)?, span)
            }
            None => spanned!(serde::DnssecMode::Opportunistic, Span::unknown()),
        };

        let tasks = match get_value(constants::flags::TASKS) {
            Some(val @ Value::Int { .. }) => {
                let span = val.span();
                spanned!(
                    val.as_int()?
                        .try_into()
                        .map_err(|err| LabeledError::new("invalid input")
                            .with_label(format!("should be positive int: {err}"), val.span()))?,
                    span
                )
            }
            None => spanned!(constants::config::default::TASKS, Span::unknown()),

            Some(val) => {
                return Err(LabeledError::new("should be int")
                    .with_label("number of tasks should be an int", val.span()))
            }
        };

        let timeout = match get_value(constants::flags::TIMEOUT) {
            Some(val @ Value::Duration { .. }) => {
                let span = val.span();
                spanned!(
                    Duration::from_nanos(val.as_duration()?.try_into().map_err(|err| {
                        LabeledError::new("invalid duration")
                            .with_label(format!("should be positive duration: {err}"), val.span())
                    })?),
                    span
                )
            }
            None => spanned!(constants::config::default::TIMEOUT, Span::unknown()),

            Some(val) => {
                return Err(LabeledError::new("should be duration")
                    .with_label("timeout should be a positive duration", val.span()))
            }
        };

        Ok(Self {
            protocol,
            server: addr,
            qtypes,
            code,
            class,
            dnssec_mode,
            dns_name,
            tasks,
            timeout,
        })
    }
}
