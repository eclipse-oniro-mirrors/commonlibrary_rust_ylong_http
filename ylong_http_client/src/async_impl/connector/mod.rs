// Copyright (c) 2023 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Asynchronous `Connector` trait and `HttpConnector` implementation.

mod stream;

use core::future::Future;
use std::io::{Error, ErrorKind};
use std::sync::Arc;

/// Information of an IO.
pub use stream::ConnInfo;
use ylong_http::request::uri::Uri;
#[cfg(feature = "http3")]
use ylong_runtime::net::{ConnectedUdpSocket, UdpSocket};

use crate::async_impl::dns::{DefaultDnsResolver, EyeBallConfig, HappyEyeballs, Resolver};
use crate::runtime::{AsyncRead, AsyncWrite, TcpStream};
use crate::util::config::{ConnectorConfig, HttpVersion};
use crate::{HttpClientError, Timeout};

/// `Connector` trait used by `async_impl::Client`. `Connector` provides
/// asynchronous connection establishment interfaces.
pub trait Connector {
    /// Streams that this connector produces.
    type Stream: AsyncRead + AsyncWrite + ConnInfo + Unpin + Sync + Send + 'static;

    /// Futures generated by this connector when attempting to create a stream.
    type Future: Future<Output = Result<Self::Stream, HttpClientError>>
        + Unpin
        + Sync
        + Send
        + 'static;

    /// Attempts to establish a connection.
    fn connect(&self, uri: &Uri, http_version: HttpVersion) -> Self::Future;
}

/// Connector for creating HTTP or HTTPS connections asynchronously.
///
/// `HttpConnector` implements `async_impl::Connector` trait.
pub struct HttpConnector {
    config: ConnectorConfig,
    resolver: Arc<dyn Resolver>,
}

impl HttpConnector {
    /// Creates a new `HttpConnector` with a `ConnectorConfig`.
    pub(crate) fn new(config: ConnectorConfig, resolver: Arc<dyn Resolver>) -> Self {
        Self { config, resolver }
    }

    /// Creates a new `HttpConnector` with a given dns `Resolver`.
    pub(crate) fn with_dns_resolver<R>(resolver: R) -> Self
    where
        R: Resolver,
    {
        let resolver = Arc::new(resolver) as Arc<dyn Resolver>;
        Self {
            config: Default::default(),
            resolver,
        }
    }
}

impl Default for HttpConnector {
    fn default() -> Self {
        Self {
            config: Default::default(),
            resolver: Arc::new(DefaultDnsResolver::default()),
        }
    }
}

async fn tcp_stream(eyeballs: HappyEyeballs) -> Result<TcpStream, HttpClientError> {
    eyeballs
        .connect()
        .await
        .map_err(|e| {
            #[cfg(target_os = "linux")]
            if format!("{}", e).contains("failed to lookup address information") {
                return HttpClientError::from_dns_error(crate::ErrorKind::Connect, e);
            }
            #[cfg(target_os = "windows")]
            if let Some(code) = e.raw_os_error() {
                if (0x2329..=0x26B2).contains(&code) || code == 0x2AF9 {
                    return HttpClientError::from_dns_error(crate::ErrorKind::Connect, e);
                }
            }
            HttpClientError::from_io_error(crate::ErrorKind::Connect, e)
        })
        .and_then(|stream| match stream.set_nodelay(true) {
            Ok(()) => Ok(stream),
            Err(e) => err_from_io!(Connect, e),
        })
}

async fn eyeballs_connect(
    resolver: Arc<dyn Resolver>,
    addr: &str,
    timeout: Timeout,
) -> Result<TcpStream, HttpClientError> {
    let addr_fut = resolver.resolve(addr);
    let socket_addr = addr_fut.await.map_err(|e| {
        HttpClientError::from_dns_error(
            crate::ErrorKind::Connect,
            Error::new(ErrorKind::Interrupted, e),
        )
    })?;

    let addrs = socket_addr.collect::<Vec<_>>();
    let eyeball_config = EyeBallConfig::new(timeout.inner(), None);
    let happy_eyeballs = HappyEyeballs::new(addrs, eyeball_config);
    tcp_stream(happy_eyeballs).await
}

#[cfg(feature = "http3")]
pub(crate) async fn udp_stream(
    addr: &std::net::SocketAddr,
) -> Result<ConnectedUdpSocket, HttpClientError> {
    let local_addr = match addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };
    let sock = UdpSocket::bind(local_addr)
        .await
        .map_err(|e| HttpClientError::from_io_error(crate::ErrorKind::Connect, e))?;
    sock.connect(addr)
        .await
        .map_err(|e| HttpClientError::from_io_error(crate::ErrorKind::Connect, e))
}

#[cfg(not(feature = "__tls"))]
mod no_tls {
    use core::future::Future;
    use core::pin::Pin;

    use ylong_http::request::uri::Uri;

    use super::{eyeballs_connect, Connector, HttpConnector};
    use crate::async_impl::connector::stream::HttpStream;
    use crate::async_impl::interceptor::{ConnDetail, ConnProtocol};
    use crate::runtime::TcpStream;
    use crate::util::config::HttpVersion;
    use crate::HttpClientError;

    impl Connector for HttpConnector {
        type Stream = HttpStream<TcpStream>;
        type Future =
            Pin<Box<dyn Future<Output = Result<Self::Stream, HttpClientError>> + Sync + Send>>;

        fn connect(&self, uri: &Uri, _http_version: HttpVersion) -> Self::Future {
            // Checks if this uri need be proxied.
            let mut is_proxy = false;
            let mut addr = uri.authority().unwrap().to_string();
            if let Some(proxy) = self.config.proxies.match_proxy(uri) {
                addr = proxy.via_proxy(uri).authority().unwrap().to_string();
                is_proxy = true;
            }

            let resolver = self.resolver.clone();
            let timeout = self.config.timeout.clone();
            Box::pin(async move {
                let stream = eyeballs_connect(resolver, addr.as_str(), timeout).await?;
                let local = stream
                    .local_addr()
                    .map_err(|e| HttpClientError::from_io_error(crate::ErrorKind::Connect, e))?;
                let peer = stream
                    .peer_addr()
                    .map_err(|e| HttpClientError::from_io_error(crate::ErrorKind::Connect, e))?;
                let detail = ConnDetail {
                    protocol: ConnProtocol::Tcp,
                    alpn: None,
                    local,
                    peer,
                    addr,
                    proxy: is_proxy,
                };
                Ok(HttpStream::new(stream, detail))
            })
        }
    }
}

#[cfg(feature = "__tls")]
mod tls {
    use core::future::Future;
    use core::pin::Pin;
    use std::error;
    use std::fmt::{Debug, Display, Formatter};
    use std::io::{Error, ErrorKind, Write};

    use ylong_http::request::uri::{Scheme, Uri};

    use super::{eyeballs_connect, Connector, HttpConnector};
    use crate::async_impl::connector::stream::HttpStream;
    use crate::async_impl::interceptor::{ConnDetail, ConnProtocol};
    use crate::async_impl::mix::MixStream;
    #[cfg(feature = "http3")]
    use crate::async_impl::quic::QuicConn;
    use crate::async_impl::ssl_stream::AsyncSslStream;
    #[cfg(all(target_os = "linux", feature = "ylong_base", feature = "__tls"))]
    use crate::config::FchownConfig;
    use crate::runtime::{AsyncReadExt, AsyncWriteExt, TcpStream};
    use crate::util::config::HttpVersion;
    use crate::{HttpClientError, TlsConfig};

    impl Connector for HttpConnector {
        type Stream = HttpStream<MixStream>;
        type Future =
            Pin<Box<dyn Future<Output = Result<Self::Stream, HttpClientError>> + Sync + Send>>;

        fn connect(&self, uri: &Uri, _http_version: HttpVersion) -> Self::Future {
            // Make sure all parts of uri is accurate.
            let mut addr = uri.authority().unwrap().to_string();
            let mut auth = None;
            let mut is_proxy = false;

            if let Some(proxy) = self.config.proxies.match_proxy(uri) {
                addr = proxy.via_proxy(uri).authority().unwrap().to_string();
                auth = proxy
                    .intercept
                    .proxy_info()
                    .basic_auth
                    .as_ref()
                    .and_then(|v| v.to_string().ok());
                is_proxy = true;
            }
            #[cfg(all(target_os = "linux", feature = "ylong_base", feature = "__tls"))]
            let fchown = self.config.fchown.clone();
            let resolver = self.resolver.clone();
            let timeout = self.config.timeout.clone();
            match *uri.scheme().unwrap() {
                Scheme::HTTP => Box::pin(async move {
                    let stream = eyeballs_connect(resolver, addr.as_str(), timeout).await?;

                    #[cfg(all(target_os = "linux", feature = "ylong_base", feature = "__tls"))]
                    if let Some(fchown) = fchown {
                        let _ = stream.fchown(fchown.uid, fchown.gid);
                    }

                    let local = stream.local_addr().map_err(|e| {
                        HttpClientError::from_io_error(crate::ErrorKind::Connect, e)
                    })?;
                    let peer = stream.peer_addr().map_err(|e| {
                        HttpClientError::from_io_error(crate::ErrorKind::Connect, e)
                    })?;
                    let detail = ConnDetail {
                        protocol: ConnProtocol::Tcp,
                        alpn: None,
                        local,
                        peer,
                        addr,
                        proxy: is_proxy,
                    };

                    Ok(HttpStream::new(MixStream::Http(stream), detail))
                }),
                Scheme::HTTPS => {
                    let host = uri.host().unwrap().to_string();
                    let port = uri.port().unwrap().as_u16().unwrap();
                    let config = self.config.tls.clone();
                    #[cfg(feature = "http3")]
                    if _http_version == HttpVersion::Http3 {
                        return Box::pin(async move {
                            let addr_fut = resolver.resolve(&addr);
                            let addrs = addr_fut.await.map_err(|e| {
                                HttpClientError::from_dns_error(
                                    crate::ErrorKind::Connect,
                                    Error::new(ErrorKind::Interrupted, e),
                                )
                            })?;

                            let mut last_e = None;
                            for addr_it in addrs {
                                let udp_socket = match super::udp_stream(&addr_it).await {
                                    Ok(socket) => socket,
                                    Err(e) => {
                                        last_e = Some(e);
                                        continue;
                                    }
                                };
                                let local = udp_socket.local_addr().map_err(|e| {
                                    HttpClientError::from_io_error(crate::ErrorKind::Connect, e)
                                })?;
                                let peer = udp_socket.peer_addr().map_err(|e| {
                                    HttpClientError::from_io_error(crate::ErrorKind::Connect, e)
                                })?;
                                let detail = ConnDetail {
                                    protocol: ConnProtocol::Udp,
                                    alpn: None,
                                    local,
                                    peer,
                                    addr: addr.clone(),
                                    proxy: false,
                                };
                                let mut stream =
                                    HttpStream::new(MixStream::Udp(udp_socket), detail);
                                let Ok(quic_conn) =
                                    QuicConn::connect(&mut stream, &config, &host).await
                                else {
                                    continue;
                                };
                                stream.set_quic_conn(quic_conn);
                                return Ok(stream);
                            }

                            Err(last_e.unwrap_or(HttpClientError::from_str(
                                crate::ErrorKind::Connect,
                                "connect failed",
                            )))
                        });
                    }
                    Box::pin(async move {
                        let stream = eyeballs_connect(resolver, addr.as_str(), timeout).await?;
                        #[cfg(all(target_os = "linux", feature = "ylong_base", feature = "__tls"))]
                        {
                            https_connect(
                                config,
                                addr,
                                stream,
                                is_proxy,
                                auth,
                                (host, port),
                                fchown,
                            )
                            .await
                        }
                        #[cfg(not(all(
                            target_os = "linux",
                            feature = "ylong_base",
                            feature = "__tls"
                        )))]
                        {
                            https_connect(config, addr, stream, is_proxy, auth, (host, port)).await
                        }
                    })
                }
            }
        }
    }

    async fn https_connect(
        config: TlsConfig,
        addr: String,
        tcp_stream: TcpStream,
        is_proxy: bool,
        auth: Option<String>,
        (host, port): (String, u16),
        #[cfg(all(target_os = "linux", feature = "ylong_base", feature = "__tls"))] fchown: Option<
            FchownConfig,
        >,
    ) -> Result<HttpStream<MixStream>, HttpClientError> {
        let mut tcp = tcp_stream;
        #[cfg(all(target_os = "linux", feature = "ylong_base", feature = "__tls"))]
        if let Some(fchown) = fchown {
            let _ = tcp.fchown(fchown.uid, fchown.gid);
        }
        let local = tcp
            .local_addr()
            .map_err(|e| HttpClientError::from_io_error(crate::ErrorKind::Connect, e))?;
        let peer = tcp
            .peer_addr()
            .map_err(|e| HttpClientError::from_io_error(crate::ErrorKind::Connect, e))?;
        if is_proxy {
            tcp = tunnel(tcp, &host, port, auth)
                .await
                .map_err(|e| HttpClientError::from_io_error(crate::ErrorKind::Connect, e))?;
        };

        let pinned_key = config.pinning_host_match(addr.as_str());
        let mut stream = config
            .ssl_new(&host)
            .and_then(|ssl| AsyncSslStream::new(ssl.into_inner(), tcp, pinned_key))
            .map_err(|e| {
                HttpClientError::from_tls_error(
                    crate::ErrorKind::Connect,
                    Error::new(ErrorKind::Other, e),
                )
            })?;

        Pin::new(&mut stream).connect().await.map_err(|e| {
            HttpClientError::from_tls_error(
                crate::ErrorKind::Connect,
                Error::new(ErrorKind::Other, e),
            )
        })?;

        let alpn = stream.negotiated_alpn_protocol().map(Vec::from);
        let detail = ConnDetail {
            protocol: ConnProtocol::Tcp,
            alpn,
            local,
            peer,
            addr,
            proxy: is_proxy,
        };

        Ok(HttpStream::new(MixStream::Https(stream), detail))
    }

    async fn tunnel(
        mut conn: TcpStream,
        host: &str,
        port: u16,
        auth: Option<String>,
    ) -> Result<TcpStream, Error> {
        let mut req = Vec::new();

        write!(
            &mut req,
            "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        )?;

        if let Some(value) = auth {
            write!(&mut req, "Proxy-Authorization: Basic {value}\r\n")?;
        }

        write!(&mut req, "\r\n")?;

        conn.write_all(&req).await?;

        let mut buf = [0; 8192];
        let mut pos = 0;

        loop {
            let n = conn.read(&mut buf[pos..]).await?;

            if n == 0 {
                return Err(other_io_error(CreateTunnelErr::Unsuccessful));
            }

            pos += n;
            let resp = &buf[..pos];
            if resp.starts_with(b"HTTP/1.1 200") || resp.starts_with(b"HTTP/1.0 200") {
                if resp.ends_with(b"\r\n\r\n") {
                    return Ok(conn);
                }
                if pos == buf.len() {
                    return Err(other_io_error(CreateTunnelErr::ProxyHeadersTooLong));
                }
            } else if resp.starts_with(b"HTTP/1.1 407") {
                return Err(other_io_error(CreateTunnelErr::ProxyAuthenticationRequired));
            } else {
                return Err(other_io_error(CreateTunnelErr::Unsuccessful));
            }
        }
    }

    fn other_io_error(err: CreateTunnelErr) -> Error {
        Error::new(ErrorKind::Other, err)
    }

    enum CreateTunnelErr {
        ProxyHeadersTooLong,
        ProxyAuthenticationRequired,
        Unsuccessful,
    }

    impl Debug for CreateTunnelErr {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::ProxyHeadersTooLong => f.write_str("Proxy headers too long for tunnel"),
                Self::ProxyAuthenticationRequired => f.write_str("Proxy authentication required"),
                Self::Unsuccessful => f.write_str("Unsuccessful tunnel"),
            }
        }
    }

    impl Display for CreateTunnelErr {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            Debug::fmt(self, f)
        }
    }

    impl error::Error for CreateTunnelErr {}

    #[cfg(all(test, feature = "__tls"))]
    mod ut_tunnel_error_debug {
        use crate::async_impl::connector::tls::CreateTunnelErr;

        /// UT test cases for debug of`CreateTunnelErr`.
        ///
        /// # Brief
        /// 1. Checks `CreateTunnelErr` debug by calling `CreateTunnelErr::fmt`.
        /// 2. Checks if the result is as expected.
        #[test]
        fn ut_tunnel_error_debug_assert() {
            assert_eq!(
                format!("{:?}", CreateTunnelErr::ProxyHeadersTooLong),
                "Proxy headers too long for tunnel"
            );
            assert_eq!(
                format!("{:?}", CreateTunnelErr::ProxyAuthenticationRequired),
                "Proxy authentication required"
            );
            assert_eq!(
                format!("{:?}", CreateTunnelErr::Unsuccessful),
                "Unsuccessful tunnel"
            );
            assert_eq!(
                format!("{}", CreateTunnelErr::ProxyHeadersTooLong),
                "Proxy headers too long for tunnel"
            );
            assert_eq!(
                format!("{}", CreateTunnelErr::ProxyAuthenticationRequired),
                "Proxy authentication required"
            );
            assert_eq!(
                format!("{}", CreateTunnelErr::Unsuccessful),
                "Unsuccessful tunnel"
            );
        }
    }

    #[cfg(all(test, feature = "__tls", feature = "ylong_base"))]
    mod ut_create_tunnel_err_debug {
        use std::net::SocketAddr;
        use std::str::FromStr;

        use ylong_runtime::io::AsyncWriteExt;

        use crate::async_impl::connector::tcp_stream;
        use crate::async_impl::connector::tls::{other_io_error, tunnel, CreateTunnelErr};
        use crate::async_impl::dns::{EyeBallConfig, HappyEyeballs};
        use crate::start_tcp_server;
        use crate::util::test_utils::{format_header_str, TcpHandle};

        /// UT test cases for `tunnel`.
        ///
        /// # Brief
        /// 1. Creates a `tcp stream` by calling `tcp_stream`.
        /// 2. Sends a `Request` by `tunnel`.
        /// 3. Checks if the result is as expected.
        #[test]
        fn ut_ssl_tunnel_error() {
            let mut handles = vec![];
            start_tcp_server!(
               Handles: handles,
               EndWith: "\r\n\r\n",
               Shutdown: std::net::Shutdown::Both,
            );
            let handle = handles.pop().expect("No more handles !");

            let eyeballs = HappyEyeballs::new(
                vec![SocketAddr::from_str(handle.addr.as_str()).unwrap()],
                EyeBallConfig::new(None, None),
            );

            let handle = ylong_runtime::spawn(async move {
                let tcp = tcp_stream(eyeballs).await.unwrap();
                let res = tunnel(
                    tcp,
                    "ylong_http.com",
                    443,
                    Some(String::from("base64 bytes")),
                )
                .await;
                assert_eq!(
                    format!("{:?}", res.err()),
                    format!("{:?}", Some(other_io_error(CreateTunnelErr::Unsuccessful)))
                );
                handle
                    .server_shutdown
                    .recv()
                    .expect("server send order failed !");
            });
            ylong_runtime::block_on(handle).unwrap();

            start_tcp_server!(
               Handles: handles,
               EndWith: "\r\n\r\n",
               Response: {
                   Status: 407,
                   Version: "HTTP/1.1",
                   Header: "Content-Length", "11",
                   Body: "METHOD GET!",
               },
               Shutdown: std::net::Shutdown::Both,
            );
            let handle = handles.pop().expect("No more handles !");

            let eyeballs = HappyEyeballs::new(
                vec![SocketAddr::from_str(handle.addr.as_str()).unwrap()],
                EyeBallConfig::new(None, None),
            );
            let handle = ylong_runtime::spawn(async move {
                let tcp = tcp_stream(eyeballs).await.unwrap();
                let res = tunnel(
                    tcp,
                    "ylong_http.com",
                    443,
                    Some(String::from("base64 bytes")),
                )
                .await;
                assert_eq!(
                    format!("{:?}", res.err()),
                    format!(
                        "{:?}",
                        Some(other_io_error(CreateTunnelErr::ProxyAuthenticationRequired))
                    )
                );
                handle
                    .server_shutdown
                    .recv()
                    .expect("server send order failed !");
            });
            ylong_runtime::block_on(handle).unwrap();

            start_tcp_server!(
               Handles: handles,
               EndWith: "\r\n\r\n",
               Response: {
                   Status: 402,
                   Version: "HTTP/1.1",
                   Header: "Content-Length", "11",
                   Body: "METHOD GET!",
               },
               Shutdown: std::net::Shutdown::Both,
            );
            let handle = handles.pop().expect("No more handles !");

            let eyeballs = HappyEyeballs::new(
                vec![SocketAddr::from_str(handle.addr.as_str()).unwrap()],
                EyeBallConfig::new(None, None),
            );
            let handle = ylong_runtime::spawn(async move {
                let tcp = tcp_stream(eyeballs).await.unwrap();
                let res = tunnel(
                    tcp,
                    "ylong_http.com",
                    443,
                    Some(String::from("base64 bytes")),
                )
                .await;
                assert_eq!(
                    format!("{:?}", res.err()),
                    format!("{:?}", Some(other_io_error(CreateTunnelErr::Unsuccessful)))
                );
                handle
                    .server_shutdown
                    .recv()
                    .expect("server send order failed !");
            });
            ylong_runtime::block_on(handle).unwrap();
        }

        /// UT test cases for `tunnel`.
        ///
        /// # Brief
        /// 1. Creates a `tcp stream` by calling `tcp_stream`.
        /// 2. Sends a `Request` by `tunnel`.
        /// 3. Checks if the result is as expected.
        #[test]
        fn ut_ssl_tunnel_connect() {
            let mut handles = vec![];

            start_tcp_server!(
               Handles: handles,
               EndWith: "\r\n\r\n",
                Response: {
                   Status: 200,
                   Version: "HTTP/1.1",
                   Body: "",
               },
               Shutdown: std::net::Shutdown::Both,
            );
            let handle = handles.pop().expect("No more handles !");

            let eyeballs = HappyEyeballs::new(
                vec![SocketAddr::from_str(handle.addr.as_str()).unwrap()],
                EyeBallConfig::new(None, None),
            );
            let handle = ylong_runtime::spawn(async move {
                let tcp = tcp_stream(eyeballs).await.unwrap();
                let res = tunnel(
                    tcp,
                    "ylong_http.com",
                    443,
                    Some(String::from("base64 bytes")),
                )
                .await;
                assert!(res.is_ok());
                handle
                    .server_shutdown
                    .recv()
                    .expect("server send order failed !");
            });
            ylong_runtime::block_on(handle).unwrap();
        }

        /// UT test cases for response beyond size of `tunnel`.
        ///
        /// # Brief
        /// 1. Creates a `tcp stream` by calling `tcp_stream`.
        /// 2. Sends a `Request` by `tunnel`.
        /// 3. Checks if the result is as expected.
        #[test]
        fn ut_ssl_tunnel_resp_beyond_size() {
            let mut handles = vec![];

            let buf = vec![b'b'; 8192];
            let body = String::from_utf8(buf).unwrap();

            start_tcp_server!(
               Handles: handles,
               EndWith: "\r\n\r\n",
                Response: {
                   Status: 200,
                   Version: "HTTP/1.1",
                   Header: "Content-Length", "11",
                   Body: body.as_str(),
               },
            );
            let handle = handles.pop().expect("No more handles !");

            let eyeballs = HappyEyeballs::new(
                vec![SocketAddr::from_str(handle.addr.as_str()).unwrap()],
                EyeBallConfig::new(None, None),
            );
            let handle = ylong_runtime::spawn(async move {
                let tcp = tcp_stream(eyeballs).await.unwrap();
                let res = tunnel(
                    tcp,
                    "ylong_http.com",
                    443,
                    Some(String::from("base64 bytes")),
                )
                .await;
                assert_eq!(
                    format!("{:?}", res.err()),
                    format!(
                        "{:?}",
                        Some(other_io_error(CreateTunnelErr::ProxyHeadersTooLong))
                    )
                );
                handle
                    .server_shutdown
                    .recv()
                    .expect("server send order failed !");
            });
            ylong_runtime::block_on(handle).unwrap();
        }
    }
}
