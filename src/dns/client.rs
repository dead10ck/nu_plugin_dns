use std::{net::SocketAddr, pin::Pin};

use futures_util::{future, Stream, StreamExt};
use nu_plugin::LabeledError;
use nu_protocol::Span;
use tokio::{net::UdpSocket, task::JoinSet};
use trust_dns_client::client::{AsyncClient, AsyncDnssecClient};
use trust_dns_proto::{
    error::{ProtoError, ProtoErrorKind},
    iocompat::AsyncIoTokioAsStd,
    op::NoopMessageFinalizer,
    tcp::TcpClientStream,
    udp::UdpClientStream,
    xfer::DnsResponse,
    DnsHandle, DnsMultiplexer,
};
use trust_dns_resolver::config::Protocol;

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

impl DnsClient {
    pub async fn new(
        addr: SocketAddr,
        addr_span: Option<Span>,
        protocol: Protocol,
        dnssec_mode: DnssecMode,
    ) -> Result<(Self, JoinSet<Result<(), ProtoError>>), LabeledError> {
        let connect_err = |err| LabeledError {
            label: "ConnectError".into(),
            msg: format!("Error creating client connection: {}", err),
            span: addr_span,
        };

        let mut join_set = JoinSet::new();

        let (async_client, dnssec_client) = match protocol {
            Protocol::Udp => {
                let async_client = if dnssec_mode != DnssecMode::Strict {
                    let conn = UdpClientStream::<UdpSocket>::new(addr);
                    let (async_client, bg) =
                        AsyncClient::connect(conn).await.map_err(connect_err)?;
                    join_set.spawn(bg);
                    Some(async_client)
                } else {
                    None
                };

                let dnssec_client = if dnssec_mode != DnssecMode::None {
                    let conn = UdpClientStream::<UdpSocket>::new(addr);
                    let (dnssec_client, bg) = AsyncDnssecClient::connect(conn)
                        .await
                        .map_err(connect_err)?;
                    join_set.spawn(bg);
                    Some(dnssec_client)
                } else {
                    None
                };

                (async_client, dnssec_client)
            }
            Protocol::Tcp => {
                let async_client = if dnssec_mode != DnssecMode::Strict {
                    let (stream, sender) =
                        TcpClientStream::<AsyncIoTokioAsStd<tokio::net::TcpStream>>::new(addr);
                    let conn = DnsMultiplexer::<_, NoopMessageFinalizer>::new(stream, sender, None);
                    let (async_client, bg) =
                        AsyncClient::connect(conn).await.map_err(connect_err)?;
                    join_set.spawn(bg);
                    Some(async_client)
                } else {
                    None
                };

                let dnssec_client = if dnssec_mode != DnssecMode::None {
                    let (stream, sender) =
                        TcpClientStream::<AsyncIoTokioAsStd<tokio::net::TcpStream>>::new(addr);
                    let conn = DnsMultiplexer::<_, NoopMessageFinalizer>::new(stream, sender, None);
                    let (dnssec_client, bg) = AsyncDnssecClient::connect(conn)
                        .await
                        .map_err(connect_err)?;
                    join_set.spawn(bg);
                    Some(dnssec_client)
                } else {
                    None
                };

                (async_client, dnssec_client)
            }
            _ => todo!(),
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
