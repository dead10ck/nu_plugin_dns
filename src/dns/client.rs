use std::{net::SocketAddr, pin::Pin, sync::Arc};

use futures_util::{future, Stream, StreamExt};
use nu_plugin::{EvaluatedCall, LabeledError};
use nu_protocol::Span;
use rustls::{OwnedTrustAnchor, RootCertStore};
use tokio::{net::UdpSocket, task::JoinSet};
use trust_dns_client::client::{AsyncClient, AsyncDnssecClient};
use trust_dns_proto::{
    error::{ProtoError, ProtoErrorKind},
    https::HttpsClientStreamBuilder,
    iocompat::AsyncIoTokioAsStd,
    op::NoopMessageFinalizer,
    quic::QuicClientStream,
    tcp::TcpClientStream,
    udp::UdpClientStream,
    xfer::DnsResponse,
    DnsHandle, DnsMultiplexer,
};
use trust_dns_resolver::config::Protocol;

use crate::dns::{constants, serde};

use super::serde::DnssecMode;

type DnsHandleResponse =
    Pin<Box<(dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send + 'static)>>;

/// Client struct that wraps both a secure and non-secure client. This is a hack
/// to allow falling back to unverified responses when the record is not signed.
///
/// See:
///
/// * https://github.com/bluejekyll/trust-dns/issues/1443
/// * https://github.com/bluejekyll/trust-dns/issues/1708
#[derive(Clone)]
pub struct DnsClient {
    async_client: Option<AsyncClient>,
    dnssec_client: Option<AsyncDnssecClient>,
}

type TokioTcpConnect = AsyncIoTokioAsStd<tokio::net::TcpStream>;

impl DnsClient {
    pub async fn new(
        addr: SocketAddr,
        addr_span: Option<Span>,
        protocol: Protocol,
        call: &EvaluatedCall,
    ) -> Result<(Self, JoinSet<Result<(), ProtoError>>), LabeledError> {
        let connect_err = |err| LabeledError {
            label: "ConnectError".into(),
            msg: format!("Error creating client connection: {}", err),
            span: addr_span,
        };

        let dnssec_mode = match call.get_flag_value(constants::flags::DNSSEC) {
            Some(val) => serde::DnssecMode::try_from(val)?,
            None => serde::DnssecMode::Opportunistic,
        };

        let mut join_set = JoinSet::new();

        macro_rules! make_clients {
            ($conn:expr) => {{
                let async_client = if dnssec_mode != DnssecMode::Strict {
                    let (async_client, bg) =
                        AsyncClient::connect($conn).await.map_err(connect_err)?;
                    join_set.spawn(bg);
                    Some(async_client)
                } else {
                    None
                };

                let dnssec_client = if dnssec_mode != DnssecMode::None {
                    let (dnssec_client, bg) = AsyncDnssecClient::connect($conn)
                        .await
                        .map_err(connect_err)?;
                    join_set.spawn(bg);
                    Some(dnssec_client)
                } else {
                    None
                };
                (async_client, dnssec_client)
            }};
        }

        let (async_client, dnssec_client) = match protocol {
            Protocol::Udp => {
                make_clients!(UdpClientStream::<UdpSocket>::new(addr))
            }
            Protocol::Tcp => {
                make_clients!({
                    let (stream, sender) = TcpClientStream::<TokioTcpConnect>::new(addr);
                    DnsMultiplexer::<_, NoopMessageFinalizer>::new(stream, sender, None)
                })
            }
            proto @ (Protocol::Https | Protocol::Tls | Protocol::Quic) => {
                let mut root_store = RootCertStore::empty();
                root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(
                    |ta| {
                        OwnedTrustAnchor::from_subject_spki_name_constraints(
                            ta.subject,
                            ta.spki,
                            ta.name_constraints,
                        )
                    },
                ));

                let client_config = rustls::ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(root_store)
                    .with_no_client_auth();

                let dns_name = call
                    .get_flag_value(constants::flags::DNS_NAME)
                    .ok_or_else(|| LabeledError {
                        label: "MissingRequiredArgError".into(),
                        msg: "HTTPS requires a DNS name".into(),
                        span: None,
                    })?
                    .as_string()?;

                match proto {
                    Protocol::Tls => {
                        let client_config = Arc::new(client_config);
                        make_clients!({
                            let (stream, sender) = trust_dns_proto::rustls::tls_client_connect::<
                                TokioTcpConnect,
                            >(
                                addr, dns_name.clone(), client_config.clone()
                            );
                            DnsMultiplexer::<_, NoopMessageFinalizer>::new(stream, sender, None)
                        })
                    }
                    Protocol::Https => {
                        let client_config = Arc::new(client_config);
                        make_clients!({
                            HttpsClientStreamBuilder::with_client_config(client_config.clone())
                                .build::<TokioTcpConnect>(addr, dns_name.clone())
                        })
                    }
                    Protocol::Quic => make_clients!({
                        let mut builder = QuicClientStream::builder();
                        builder.crypto_config(client_config.clone());
                        builder.build(addr, dns_name.clone())
                    }),
                    _ => unreachable!(),
                }
            }
            proto => {
                return Err(LabeledError {
                    label: "UnknownProtocolError".into(),
                    msg: format!("Unknown protocol: {}", proto),
                    span: Some(call.head),
                })
            }
        };

        Ok((
            Self {
                async_client,
                dnssec_client,
            },
            join_set,
        ))
    }
}

impl DnsHandle for DnsClient {
    type Response = DnsHandleResponse;
    type Error = ProtoError;

    fn send<R>(&mut self, request: R) -> Self::Response
    where
        R: Into<trust_dns_proto::xfer::DnsRequest> + Unpin + Send + 'static,
    {
        let request = request.into();

        match (&mut self.async_client, &mut self.dnssec_client) {
            (None, None) => unreachable!(),
            (Some(async_client), None) => Box::pin(async_client.send(request)),
            (None, Some(dnssec_client)) => Box::pin(dnssec_client.send(request)),
            (Some(async_client), Some(dnssec_client)) => {
                let dnssec_resp = Box::pin(dnssec_client.send(request.clone()));
                let async_resp = Box::pin(async_client.send(request));

                Box::pin(
                    dnssec_resp
                        .chain(async_resp)
                        .filter(|resp| {
                            future::ready(!matches!(
                                resp,
                                Err(ProtoError {
                                    kind,
                                    ..
                                }) if matches!(**kind,
                                    ProtoErrorKind::RrsigsNotPresent{..} |
                                    ProtoErrorKind::Message("no results to verify"))
                            ))
                        })
                        .take(1),
                )
            }
        }
    }
}
