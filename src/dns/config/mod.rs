use std::time::Duration;

use hickory_proto::rr::{DNSClass, RecordType};
use nu_plugin::EvaluatedCall;
use nu_protocol::{FromValue, LabeledError, Parameter, Span, Spanned, Value, record};

use crate::{dns::config::resolver::ResolverConfig, spanned};

use super::{
    constants::{self, params},
    serde::RType,
};

pub use resolver::{Protocol, ProtocolConfig};

mod resolver;

#[derive(Debug)]
pub struct Config {
    pub resolver_config: Spanned<ResolverConfig>,

    pub qtypes: Spanned<Vec<Spanned<RecordType>>>,
    pub class: Spanned<DNSClass>,

    pub code: Spanned<bool>,

    pub tasks: Spanned<usize>,
    pub timeout: Spanned<Duration>,
}

pub fn get_param_name(param: &Parameter) -> &str {
    match param {
        Parameter::Required(positional_arg)
        | Parameter::Optional(positional_arg)
        | Parameter::Rest(positional_arg) => positional_arg.name.as_ref(),
        Parameter::Flag(flag) => flag.long.as_ref(),
    }
}

impl TryFrom<Value> for Config {
    type Error = LabeledError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let mut record = value.into_record()?;
        Config::from_values(|param| record.remove(get_param_name(param)))
    }
}

impl TryFrom<&EvaluatedCall> for Config {
    type Error = LabeledError;

    fn try_from(call: &EvaluatedCall) -> Result<Self, Self::Error> {
        Config::from_values(|param| call.get_flag_value(get_param_name(param)))
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

        Config::from_values(|param| {
            let name = get_param_name(param);

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
        F: FnMut(&Parameter) -> Option<Value>,
    {
        let resolver_config = match get_value(&params::CONFIG) {
            None => {
                let (conf, opts) =
                    hickory_resolver::system_conf::read_system_conf().map_err(|err| {
                        LabeledError::new("could not read system config")
                            .with_label(err.to_string(), Span::unknown())
                    })?;

                spanned!(
                    ResolverConfig {
                        resolver_config: conf,
                        resolver_opts: opts,
                    },
                    Span::unknown()
                )
            }
            Some(val) => {
                let span = val.span();
                let conf = ResolverConfig::from_value(val)?;

                spanned!(conf, span)
            }
        };

        let qtypes: Spanned<Vec<Spanned<RecordType>>> = match get_value(&params::TYPE) {
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

        let class = match get_value(&params::CLASS) {
            Some(val) => {
                let span = val.span();
                spanned!(crate::dns::serde::DNSClass::try_from(val)?.0, span)
            }
            None => spanned!(hickory_proto::rr::DNSClass::IN, Span::unknown()),
        };

        let code = match get_value(&params::CODE) {
            Some(val @ Value::Bool { .. }) => {
                spanned!(val.as_bool().unwrap(), val.span())
            }
            _ => spanned!(false, Span::unknown()),
        };

        let tasks = match get_value(&params::TASKS) {
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
                    .with_label("number of tasks should be an int", val.span()));
            }
        };

        let timeout = match get_value(&params::TIMEOUT) {
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
                    .with_label("timeout should be a positive duration", val.span()));
            }
        };

        Ok(Self {
            resolver_config,
            qtypes,
            code,
            class,
            tasks,
            timeout,
        })
    }
}
