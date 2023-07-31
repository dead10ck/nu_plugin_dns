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
    async_client: AsyncClient,
    dnssec_client: AsyncDnssecClient,
}

impl DnsClient {
    pub async fn new(
        addr: SocketAddr,
        addr_span: Option<Span>,
        protocol: Protocol,
    ) -> Result<(Self, JoinSet<Result<(), ProtoError>>), LabeledError> {
        let connect_err = |err| LabeledError {
            label: "ConnectError".into(),
            msg: format!("Error creating client connection: {}", err),
            span: addr_span,
        };

        let mut join_set = JoinSet::new();

        let (async_client, dnssec_client) = match protocol {
            Protocol::Udp => {
                let conn = UdpClientStream::<UdpSocket>::new(addr);
                let (async_client, bg) = AsyncClient::connect(conn).await.map_err(connect_err)?;
                join_set.spawn(bg);

                let conn = UdpClientStream::<UdpSocket>::new(addr);
                let (dnssec_client, bg) = AsyncDnssecClient::connect(conn)
                    .await
                    .map_err(connect_err)?;
                join_set.spawn(bg);

                (async_client, dnssec_client)
            }
            Protocol::Tcp => {
                let (stream, sender) =
                    TcpClientStream::<AsyncIoTokioAsStd<tokio::net::TcpStream>>::new(addr);
                let conn = DnsMultiplexer::<_, NoopMessageFinalizer>::new(stream, sender, None);
                let (async_client, bg) = AsyncClient::connect(conn).await.map_err(connect_err)?;
                join_set.spawn(bg);

                let (stream, sender) =
                    TcpClientStream::<AsyncIoTokioAsStd<tokio::net::TcpStream>>::new(addr);
                let conn = DnsMultiplexer::<_, NoopMessageFinalizer>::new(stream, sender, None);
                let (dnssec_client, bg) = AsyncDnssecClient::connect(conn)
                    .await
                    .map_err(connect_err)?;
                join_set.spawn(bg);

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
        let dnssec_resp = Box::pin(self.dnssec_client.send(request.clone()));
        let async_resp = Box::pin(self.async_client.send(request));

        Box::pin(
            dnssec_resp
                .chain(async_resp)
                .filter(|resp| {
                    future::ready(!matches!(
                        resp,
                        Err(ProtoError {
                            kind,
                            ..
                        }) if matches!(**kind, ProtoErrorKind::RrsigsNotPresent{..})
                    ))
                })
                .take(1),
        )
    }
}
