// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//! Optional mutual TLS for every Ballista connection.
//!
//! A process installs one [`TlsConfig`] at startup with [`install`], before it
//! opens any connection. From then on every scheduler and executor server
//! accepts only TLS connections whose client certificate the server
//! configuration verifies, every client connects over TLS, and a
//! [`PeerAuthorizer`] decides which peer may call which RPC. Without an
//! installed configuration nothing changes.
//!
//! The rustls configurations are supplied whole, so the embedding application
//! chooses its certificate verification (for example SPIFFE identities rather
//! than host names) and how certificates are reloaded.

use std::{
    fmt,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::Duration,
};

use futures::{Stream, StreamExt};
use log::debug;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::mpsc,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, server::TlsStream};
use tonic::{
    codegen::http,
    transport::{Channel, Endpoint, Uri, server::Connected},
};

/// The TLS configuration of one process.
pub struct TlsConfig {
    /// Server configuration for every listener. It should require and verify
    /// client certificates.
    pub server: Arc<rustls::ServerConfig>,
    /// Client configuration for every outgoing connection, with a client
    /// certificate. ALPN must offer `h2`.
    pub client: Arc<rustls::ClientConfig>,
    /// Decides which peer may call which path.
    pub authorizer: Arc<dyn PeerAuthorizer>,
    /// How long a TLS handshake may take before the connection is dropped.
    pub handshake_timeout: Duration,
    /// Where the scheduler serves `/healthz` and `/readyz` without TLS, for
    /// probes that cannot present a client certificate. Nothing else is
    /// served there. Executors have their own health port.
    pub plain_health: Option<SocketAddr>,
}

impl fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfig")
            .field("handshake_timeout", &self.handshake_timeout)
            .finish_non_exhaustive()
    }
}

/// A verified TLS peer: its address and certificate chain, leaf first.
#[derive(Clone, Debug)]
pub struct PeerIdentity {
    /// The address the peer connected from.
    pub addr: SocketAddr,
    /// The peer's verified certificate chain, leaf first.
    pub certs: Arc<Vec<CertificateDer<'static>>>,
}

/// Authorization of TLS peers, called after the handshake has verified the
/// peer's certificate.
pub trait PeerAuthorizer: Send + Sync + 'static {
    /// May `peer` call `path`? `path` is a gRPC method path such as
    /// `/ballista.protobuf.SchedulerGrpc/RegisterExecutor`, or an HTTP path
    /// such as `/api/jobs`.
    fn authorize(&self, peer: &PeerIdentity, path: &str) -> Result<(), String>;
    /// May `peer` act as executor `executor_id`? The scheduler also requires
    /// that an executor's advertised host is the address it connected from.
    fn authorize_executor(
        &self,
        peer: &PeerIdentity,
        executor_id: &str,
    ) -> Result<(), String>;
}

static TLS: OnceLock<Arc<TlsConfig>> = OnceLock::new();

/// Install this process's TLS configuration. Call once, at startup.
pub fn install(config: TlsConfig) -> Result<(), String> {
    TLS.set(Arc::new(config))
        .map_err(|_| "Ballista TLS is already configured".to_string())
}

/// The installed configuration, if any.
pub fn config() -> Option<&'static Arc<TlsConfig>> {
    TLS.get()
}

/// Connect a gRPC endpoint: over TLS when configured, otherwise as
/// `endpoint.connect()`. The endpoint's `http://` scheme is kept; TLS is done
/// by the connector, with the URI host as the server name.
pub async fn connect(endpoint: Endpoint) -> Result<Channel, tonic::transport::Error> {
    let Some(tls) = config() else {
        return endpoint.connect().await;
    };
    let connector = TlsConnector::from(tls.client.clone());
    endpoint
        .connect_with_connector(tower::service_fn(move |uri: Uri| {
            let connector = connector.clone();
            async move {
                let host = uri
                    .host()
                    .ok_or_else(|| io::Error::other("URI without host"))?
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned();
                let port = uri.port_u16().unwrap_or(80);
                let tcp = TcpStream::connect((host.as_str(), port)).await?;
                tcp.set_nodelay(true)?;
                let name = ServerName::try_from(host)
                    .map_err(|_| io::Error::other("invalid TLS server name"))?;
                let stream = connector.connect(name, tcp).await?;
                Ok::<_, io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
}

/// A server-side TLS connection and the verified peer behind it.
pub struct TlsConn {
    inner: TlsStream<TcpStream>,
    peer: PeerIdentity,
}

impl TlsConn {
    /// The verified peer of this connection.
    pub fn peer(&self) -> &PeerIdentity {
        &self.peer
    }
}

impl AsyncRead for TlsConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// tonic inserts this into each request's extensions, so handlers and
/// layers find the [`PeerIdentity`] there.
impl Connected for TlsConn {
    type ConnectInfo = PeerIdentity;
    fn connect_info(&self) -> PeerIdentity {
        self.peer.clone()
    }
}

/// TLS connections accepted from a stream of TCP connections. Each handshake
/// runs in its own task under the configured timeout, so a slow or silent
/// client cannot hold up others. Failed handshakes and accept errors are
/// dropped.
pub fn accept<S>(
    tcp: S,
    tls: &TlsConfig,
) -> impl Stream<Item = io::Result<TlsConn>> + Send + 'static
where
    S: Stream<Item = io::Result<TcpStream>> + Send + 'static,
{
    let acceptor = TlsAcceptor::from(tls.server.clone());
    let timeout = tls.handshake_timeout;
    let (sender, receiver) = mpsc::channel::<TlsConn>(256);
    tokio::spawn(async move {
        let mut tcp = Box::pin(tcp);
        loop {
            // Stop accepting, and release the socket, once the server is gone.
            let next = tokio::select! {
                next = tcp.next() => next,
                _ = sender.closed() => break,
            };
            let Some(next) = next else { break };
            let stream = match next {
                Ok(stream) => stream,
                Err(e) => {
                    debug!("TCP accept failed: {e}");
                    continue;
                }
            };
            let (acceptor, sender) = (acceptor.clone(), sender.clone());
            tokio::spawn(async move {
                let Ok(addr) = stream.peer_addr() else { return };
                match tokio::time::timeout(timeout, acceptor.accept(stream)).await {
                    Ok(Ok(inner)) => {
                        let certs = inner
                            .get_ref()
                            .1
                            .peer_certificates()
                            .map(|c| c.iter().map(|c| c.clone().into_owned()).collect())
                            .unwrap_or_default();
                        let peer = PeerIdentity {
                            addr,
                            certs: Arc::new(certs),
                        };
                        let _ = sender.send(TlsConn { inner, peer }).await;
                    }
                    Ok(Err(e)) => debug!("TLS handshake from {addr} failed: {e}"),
                    Err(_) => debug!("TLS handshake from {addr} timed out"),
                }
            });
        }
    });
    tokio_stream::wrappers::ReceiverStream::new(receiver).map(Ok)
}

/// Authorizes every request with the installed [`PeerAuthorizer`], from the
/// [`PeerIdentity`] in its extensions. A request without one is refused.
/// Without an installed configuration, every request passes.
#[derive(Clone, Debug, Default)]
pub struct AuthorizeLayer;

impl<S> tower::Layer<S> for AuthorizeLayer {
    type Service = Authorize<S>;
    fn layer(&self, inner: S) -> Authorize<S> {
        Authorize { inner }
    }
}

/// The service built by [`AuthorizeLayer`].
#[derive(Clone, Debug)]
pub struct Authorize<S> {
    inner: S,
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

impl<S, B, R> tower::Service<http::Request<B>> for Authorize<S>
where
    S: tower::Service<http::Request<B>, Response = http::Response<R>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    R: Default + Send + 'static,
{
    type Response = http::Response<R>;
    type Error = S::Error;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let decision = match config() {
            None => Ok(()),
            Some(tls) => match request.extensions().get::<PeerIdentity>() {
                Some(peer) => tls.authorizer.authorize(peer, request.uri().path()),
                None => Err("no verified TLS peer".to_string()),
            },
        };
        match decision {
            Ok(()) => Box::pin(self.inner.call(request)),
            Err(reason) => {
                debug!("refused {}: {reason}", request.uri().path());
                let grpc = request
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.starts_with("application/grpc"));
                let response = if grpc {
                    tonic::Status::permission_denied("peer not authorized").into_http()
                } else {
                    let mut response = http::Response::new(R::default());
                    *response.status_mut() = http::StatusCode::FORBIDDEN;
                    response
                };
                Box::pin(std::future::ready(Ok(response)))
            }
        }
    }
}

/// The verified peer of a request, when TLS is configured.
pub fn peer_of<T>(request: &tonic::Request<T>) -> Option<&PeerIdentity> {
    request.extensions().get::<PeerIdentity>()
}

/// Check that `executor_id`, advertising `host`, is the TLS peer of this
/// request: the authorizer accepts the peer as that executor, and the host is
/// the address the peer connected from. Passes when TLS is not configured.
pub fn check_executor<T>(
    request: &tonic::Request<T>,
    executor_id: &str,
    host: Option<&str>,
) -> Result<(), tonic::Status> {
    let Some(tls) = config() else { return Ok(()) };
    let peer = peer_of(request)
        .ok_or_else(|| tonic::Status::unauthenticated("no verified TLS peer"))?;
    tls.authorizer
        .authorize_executor(peer, executor_id)
        .map_err(|_| tonic::Status::permission_denied("peer is not this executor"))?;
    if let Some(host) = host {
        let ip = peer.addr.ip().to_canonical();
        let claimed: Option<std::net::IpAddr> = host.parse().ok();
        if claimed.map(|c| c.to_canonical()) != Some(ip) {
            return Err(tonic::Status::permission_denied(
                "executor host is not the connecting address",
            ));
        }
    }
    Ok(())
}
