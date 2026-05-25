use std::sync::Arc;

use nu_protocol::{FromValue, LabeledError, ShellError, Spanned, Value};
use serde::Serialize;

type HickoryProtocolConfig = hickory_resolver::config::ProtocolConfig;

#[derive(FromValue)]
pub enum Protocol {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
    H3,
}

#[derive(FromValue)]
pub struct ProtocolConfig {
    pub protocol: Spanned<Protocol>,

    pub server_name: Option<Spanned<String>>,
    pub path: Option<Spanned<String>>,
    pub disable_grease: Option<Spanned<bool>>,
}

impl<'c> TryFrom<&'c ProtocolConfig> for HickoryProtocolConfig {
    type Error = LabeledError;

    fn try_from(protocol_config: &'c ProtocolConfig) -> Result<Self, Self::Error> {
        let Spanned {
            item: proto,
            span: proto_span,
        } = &protocol_config.protocol;
        let get_server_name = || -> Result<Arc<str>, _> {
            protocol_config
                .server_name
                .clone()
                .ok_or_else(|| {
                    LabeledError::new("invalid config")
                        .with_label("server_name is required for this protocol", *proto_span)
                })
                .map(|server_name| server_name.item.into())
        };
        let get_path = || -> Result<Arc<str>, _> {
            protocol_config
                .path
                .clone()
                .ok_or_else(|| {
                    LabeledError::new("invalid config")
                        .with_label("path is required for this protocol", *proto_span)
                })
                .map(|path| path.item.into())
        };

        let config = match proto {
            Protocol::Udp => HickoryProtocolConfig::Udp,
            Protocol::Tcp => HickoryProtocolConfig::Tcp,
            Protocol::Tls => {
                let server_name = get_server_name()?;
                HickoryProtocolConfig::Tls { server_name }
            }
            Protocol::Https => {
                let server_name = get_server_name()?;
                let path = get_path()?;
                HickoryProtocolConfig::Https { server_name, path }
            }
            Protocol::Quic => {
                let server_name = get_server_name()?;
                HickoryProtocolConfig::Quic { server_name }
            }
            Protocol::H3 => {
                let server_name = get_server_name()?;
                let path = get_path()?;
                let disable_grease = protocol_config
                    .disable_grease
                    .map(|val| val.item)
                    .unwrap_or(false);

                HickoryProtocolConfig::H3 {
                    server_name,
                    path,
                    disable_grease,
                }
            }
        };

        Ok(config)
    }
}

pub type HickoryResolverConfig = hickory_resolver::config::ResolverConfig;

#[derive(Debug, serde::Deserialize)]
pub struct ResolverConfig(pub hickory_resolver::config::ResolverConfig);

impl FromValue for ResolverConfig {
    fn from_value(val: Value) -> Result<Self, ShellError> {
        let span = val.span();
        let mut buf = Vec::new();
        val.serialize(&mut rmp_serde::Serializer::new(&mut buf))
            .map_err(|err| {
                LabeledError::new("failed to serialize resolver config")
                    .with_label(err.to_string(), span)
            })?;

        rmp_serde::from_slice(&buf).map_err(|err| {
            ShellError::LabeledError(
                LabeledError::new("error converting config")
                    .with_label(err.to_string(), span)
                    .into(),
            )
        })
    }
}

pub type HickoryResolverOpts = hickory_resolver::config::ResolverOpts;

#[derive(Debug, serde::Deserialize)]
pub struct ResolverOpts(pub hickory_resolver::config::ResolverOpts);

impl FromValue for ResolverOpts {
    fn from_value(val: Value) -> Result<Self, ShellError> {
        let span = val.span();
        let mut buf = Vec::new();
        val.serialize(&mut rmp_serde::Serializer::new(&mut buf))
            .map_err(|err| {
                LabeledError::new("failed to serialize resolver opts")
                    .with_label(err.to_string(), span)
            })?;

        rmp_serde::from_slice(&buf).map_err(|err| {
            ShellError::LabeledError(
                LabeledError::new("error converting config")
                    .with_label(err.to_string(), span)
                    .into(),
            )
        })
    }
}
