use std::{pin::Pin, sync::Arc, time::Duration};

use futures_util::{Stream, StreamExt};
use hickory_client::client::{Client, DnssecClient};
use hickory_proto::xfer::Protocol;
use hickory_proto::{
    h2::HttpsClientStreamBuilder, quic::QuicClientStream, runtime::RuntimeProvider,
    tcp::TcpClientStream, udp::UdpClientStream, xfer::DnsResponse, DnsHandle, DnsMultiplexer,
    ProtoError,
};
use nu_protocol::{LabeledError, Span};
use rustls::{pki_types::TrustAnchor, RootCertStore};
use tokio::task::JoinSet;

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
//
// FIXME: we no longer need this double client nonsense, they fixed negative validation
#[derive(Clone)]
pub struct DnsClient {
    async_client: Option<Client>,
    dnssec_client: Option<DnssecClient>,
}

impl DnsClient {
    pub async fn new(
        config: &Config,
        provider: impl RuntimeProvider,
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
                    let (async_client, bg) = Client::connect($conn).await.map_err(connect_err)?;
                    join_set.spawn(bg);
                    Some(async_client)
                } else {
                    None
                };

                let dnssec_client = if config.dnssec_mode.item != DnssecMode::None {
                    let (dnssec_client, bg) =
                        DnssecClient::connect($conn).await.map_err(connect_err)?;
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
                make_clients!(
                    UdpClientStream::builder(config.server.item, provider.clone())
                        .with_timeout(
                            // can't set a timeout on HTTPS client, so work
                            // around by setting the client internal timeout
                            // very long for all the others so we can set
                            // our own instead
                            Some(Duration::from_secs(60 * 60 * 24 * 365))
                        )
                        .build()
                )
            }
            Protocol::Tcp => {
                make_clients!({
                    let (stream, sender) = TcpClientStream::new(
                        config.server.item,
                        None,
                        // can't set a timeout on HTTPS client, so work around
                        // by setting the client internal timeout very long for
                        // all the others so we can set our own instead
                        Some(Duration::from_secs(60 * 60 * 24 * 365)),
                        provider.clone(),
                    );

                    DnsMultiplexer::<_>::new(stream, sender, None)
                })
            }
            proto @ (Protocol::Https | Protocol::Tls | Protocol::Quic) => {
                let root_store = RootCertStore::from_iter(
                    webpki_roots::TLS_SERVER_ROOTS
                        .iter()
                        .map(TrustAnchor::to_owned),
                );

                let client_config = rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth();

                match proto {
                    Protocol::Tls => {
                        let client_config = Arc::new(client_config);
                        make_clients!({
                            let (stream, sender) = hickory_proto::rustls::tls_client_connect(
                                config.server.item,
                                // safe to unwrap because having a DNS name
                                // is enforced when constructing the config
                                config.dns_name.as_ref().unwrap().clone().item,
                                client_config.clone(),
                                provider.clone(),
                            );
                            DnsMultiplexer::<_>::with_timeout(
                                stream,
                                sender,
                                // can't set a timeout on HTTPS client, so work
                                // around by setting the client internal timeout
                                // very long for all the others so we can set
                                // our own instead
                                Duration::from_secs(60 * 60 * 24 * 365),
                                None,
                            )
                        })
                    }
                    Protocol::Https => {
                        let client_config = Arc::new(client_config);
                        make_clients!({
                            HttpsClientStreamBuilder::with_client_config(
                                client_config.clone(),
                                provider.clone(),
                            )
                            .build(
                                config.server.item,
                                config.dns_name.as_ref().unwrap().clone().item,
                                // FIXME: Add a config option
                                String::from("/dns-query"),
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
                        // FIXME: we no longer need this double client nonsense, they fixed negative validation
                        // .filter(|resp| {
                        //     future::ready(!matches!(
                        //         resp,
                        //         Err(ProtoError {
                        //             kind,
                        //             ..
                        //         }) if matches!(**kind,
                        //             ProtoErrorKind::RrsigsNotPresent{..} |
                        //             ProtoErrorKind::Message("no results to verify"))
                        //     ))
                        // })
                        .take(1),
                )
            }
        }
    }
}
