use std::{pin::Pin, sync::Arc};

use futures_util::{future, Stream, StreamExt};
use hickory_client::client::{AsyncClient, AsyncDnssecClient};
use hickory_proto::{
    error::{ProtoError, ProtoErrorKind},
    h2::HttpsClientStreamBuilder,
    iocompat::AsyncIoTokioAsStd,
    op::NoopMessageFinalizer,
    quic::QuicClientStream,
    tcp::TcpClientStream,
    udp::UdpClientStream,
    xfer::DnsResponse,
    DnsHandle, DnsMultiplexer,
};
use hickory_resolver::config::Protocol;
use nu_protocol::{LabeledError, Span};
use rustls::{OwnedTrustAnchor, RootCertStore};
use tokio::{net::UdpSocket, task::JoinSet};

use super::{config::Config, serde::DnssecMode};

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
        config: &Config,
    ) -> Result<(Self, JoinSet<Result<(), ProtoError>>), LabeledError> {
        let connect_err = |err| {
            LabeledError::new("connection error").with_label(
                format!("Error creating client connection: {}", err),
                Span::unknown(),
            )
        };

        let mut join_set = JoinSet::new();

        macro_rules! make_clients {
            ($conn:expr) => {{
                let async_client = if config.dnssec_mode.item != DnssecMode::Strict {
                    let (async_client, bg) =
                        AsyncClient::connect($conn).await.map_err(connect_err)?;
                    join_set.spawn(bg);
                    Some(async_client)
                } else {
                    None
                };

                let dnssec_client = if config.dnssec_mode.item != DnssecMode::None {
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

        let (async_client, dnssec_client) = match config.protocol.item {
            Protocol::Udp => {
                make_clients!(UdpClientStream::<UdpSocket>::new(config.server.item))
            }
            Protocol::Tcp => {
                make_clients!({
                    let (stream, sender) =
                        TcpClientStream::<TokioTcpConnect>::new(config.server.item);
                    DnsMultiplexer::<_, NoopMessageFinalizer>::new(stream, sender, None)
                })
            }
            proto @ (Protocol::Https | Protocol::Tls | Protocol::Quic) => {
                let mut root_store = RootCertStore::empty();
                root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                    OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                }));

                let client_config = rustls::ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(root_store)
                    .with_no_client_auth();

                match proto {
                    Protocol::Tls => {
                        let client_config = Arc::new(client_config);
                        make_clients!({
                            let (stream, sender) =
                                hickory_proto::rustls::tls_client_connect::<TokioTcpConnect>(
                                    config.server.item,
                                    // safe to unwrap because having a DNS name
                                    // is enforced when constructing the config
                                    config.dns_name.as_ref().unwrap().clone().item,
                                    client_config.clone(),
                                );
                            DnsMultiplexer::<_, NoopMessageFinalizer>::new(stream, sender, None)
                        })
                    }
                    Protocol::Https => {
                        let client_config = Arc::new(client_config);
                        make_clients!({
                            HttpsClientStreamBuilder::with_client_config(client_config.clone())
                                .build::<TokioTcpConnect>(
                                config.server.item,
                                config.dns_name.as_ref().unwrap().clone().item,
                            )
                        })
                    }
                    Protocol::Quic => make_clients!({
                        let mut builder = QuicClientStream::builder();
                        builder.crypto_config(client_config.clone());
                        builder.build(
                            config.server.item,
                            config.dns_name.as_ref().unwrap().clone().item,
                        )
                    }),
                    _ => unreachable!(),
                }
            }
            proto => {
                return Err(LabeledError::new("unknown protocol")
                    .with_label(format!("Unknown protocol: {}", proto), config.protocol.span))
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

    fn send<R>(&self, request: R) -> Self::Response
    where
        R: Into<hickory_proto::xfer::DnsRequest> + Unpin + Send + 'static,
    {
        let request = request.into();

        match (&self.async_client, &self.dnssec_client) {
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
