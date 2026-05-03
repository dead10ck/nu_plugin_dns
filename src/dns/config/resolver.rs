use std::sync::Arc;

use nu_protocol::{FromValue, LabeledError, Spanned};

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
        } = protocol_config.protocol;

        let config = match proto {
            Protocol::Udp => HickoryProtocolConfig::Udp,
            Protocol::Tcp => HickoryProtocolConfig::Tcp,
            Protocol::Tls => {
                let server_name = protocol_config.server_name.ok_or_else(|| {
                    LabeledError::new("invalid config")
                        .with_label("tls requires server_name", proto_span)
                })?;

                HickoryProtocolConfig::Tls {
                    server_name: Arc::new(&*server_name.item),
                }
            }
            Protocol::Https => todo!(),
            Protocol::Quic => todo!(),
            Protocol::H3 => todo!(),
        };

        Ok(config)
    }
}
