use std::future::Future;
use std::{pin::Pin, sync::Arc, time::Duration};

use futures_util::Stream;
use hickory_client::client::{Client, DnssecClient};
use hickory_proto::xfer::{DnsRequestSender, Protocol};
use hickory_proto::{
    h2::HttpsClientStreamBuilder, quic::QuicClientStream, runtime::RuntimeProvider,
    tcp::TcpClientStream, udp::UdpClientStream, xfer::DnsResponse, DnsHandle, DnsMultiplexer,
    ProtoError,
};
use nu_protocol::{LabeledError, Span};
use rustls::{pki_types::TrustAnchor, RootCertStore};
use tokio::task::JoinHandle;

use super::{config::Config, serde::DnssecMode};

type DnsHandleResponse =
    Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send + 'static>>;
pub(crate) type BgHandle = JoinHandle<Result<(), ProtoError>>;

#[derive(Clone)]
pub struct DnsClient {
    client: HickoryDnsClient,
}

#[derive(Clone)]
pub enum HickoryDnsClient {
    Standard(Client),
    Dnssec(DnssecClient),
}

impl DnsClient {
    pub async fn connect<F, S>(config: &Config, conn: F) -> Result<(Self, BgHandle), LabeledError>
    where
        S: DnsRequestSender,
        F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    {
        let connect_err = |err| {
            LabeledError::new("connection error").with_label(
                format!("Error creating client connection: {}", err),
                Span::unknown(),
            )
        };

        let (client, bg) = match config.dnssec_mode.item {
            DnssecMode::None => {
                let (client, bg) = Client::connect(conn).await.map_err(connect_err)?;
                (HickoryDnsClient::Standard(client), bg)
            }
            DnssecMode::Opportunistic => {
                let (client, bg) = DnssecClient::connect(conn).await.map_err(connect_err)?;
                (HickoryDnsClient::Dnssec(client), bg)
            }
        };

        Ok((DnsClient { client }, tokio::spawn(bg)))
    }

    pub async fn new(
        config: &Config,
        provider: impl RuntimeProvider,
    ) -> Result<(Self, BgHandle), LabeledError> {
        let (client, bg) = match config.protocol.item {
            Protocol::Udp => {
                DnsClient::connect(
                    config,
                    UdpClientStream::builder(config.server.item, provider.clone())
                        .with_timeout(
                            // can't set a timeout on HTTPS client, so work
                            // around by setting the client internal timeout
                            // very long for all the others so we can set
                            // our own instead
                            Some(Duration::from_secs(60 * 60 * 24 * 365)),
                        )
                        .build(),
                )
                .await?
            }
            Protocol::Tcp => {
                DnsClient::connect(config, {
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
                .await?
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
                        DnsClient::connect(config, {
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
                        .await?
                    }
                    Protocol::Https => {
                        let client_config = Arc::new(client_config);
                        DnsClient::connect(config, {
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
                        .await?
                    }
                    Protocol::Quic => {
                        DnsClient::connect(config, {
                            let mut builder = QuicClientStream::builder();
                            builder.crypto_config(client_config.clone());
                            builder.build(
                                config.server.item,
                                config.dns_name.as_ref().unwrap().clone().item,
                            )
                        })
                        .await?
                    }
                    _ => unreachable!(),
                }
            }
            proto => {
                return Err(LabeledError::new("unknown protocol")
                    .with_label(format!("Unknown protocol: {}", proto), config.protocol.span))
            }
        };

        Ok((client, bg))
    }
}

impl DnsHandle for DnsClient {
    type Response = DnsHandleResponse;

    fn send<R>(&self, request: R) -> Self::Response
    where
        R: Into<hickory_proto::xfer::DnsRequest> + Unpin + Send + 'static,
    {
        let request = request.into();

        match &self.client {
            HickoryDnsClient::Standard(client) => Box::pin(client.send(request)),
            HickoryDnsClient::Dnssec(client) => Box::pin(client.send(request)),
        }
    }
}
