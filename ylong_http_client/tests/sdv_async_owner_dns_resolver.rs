// Copyright (c) 2026 Huawei Device Co., Ltd.
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

#![cfg(all(
    target_os = "linux",
    feature = "async",
    feature = "http1_1",
    feature = "ylong_base",
    feature = "c_openssl_3_0"
))]

//! SDV tests for the owner-aware DNS resolver through the public client
//! API: a `Client` built with `sockets_owner` + `dns_servers` resolves
//! against a local mock DNS server (UDP and TCP on one port) and connects
//! to a local HTTP server on 127.0.0.1, the address the mock's answers
//! point at. The requested name (`owner.vpn.test`) exists neither in
//! `/etc/hosts` nor anywhere else, so every successful request proves the
//! resolution went through the override servers.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ylong_http_client::async_impl::{Body, Client, RequestBuilder};

/// The name the tests resolve: absent from `/etc/hosts`, only known to
/// the mock DNS server.
const TEST_NAME: &str = "owner.vpn.test";

/// How the mock answers a received query.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MockMode {
    /// A query -> 127.0.0.1 (the HTTP server), AAAA -> ::1 (nothing
    /// listens there; the connection attempt is refused instantly and
    /// HappyEyeballs falls to the v4 address).
    Answers,
    /// Every query -> NXDOMAIN.
    NxDomain,
    /// A query -> TC=1 over UDP (forcing the TCP retry), AAAA -> ::1; the
    /// TCP retry returns 127.0.0.1.
    TcOverTcp,
}

/// Builds a DNS response echoing the received query's id and question
/// section (the same well-formed shape the resolver's unit tests use).
fn build_reply(query: &[u8], addrs: &[IpAddr], truncated: bool, rcode: u16) -> Vec<u8> {
    let id = u16::from_be_bytes([query[0], query[1]]);
    let mut flags: u16 = 0x8000 | (rcode & 0x000F); // QR | rcode
    if truncated {
        flags |= 0x0200; // TC
    }
    let qtype = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
    let mut msg = Vec::new();
    msg.extend(id.to_be_bytes());
    msg.extend(flags.to_be_bytes());
    msg.extend(1u16.to_be_bytes()); // qdcount
    msg.extend((addrs.len() as u16).to_be_bytes()); // ancount
    msg.extend([0, 0, 0, 0]); // nscount/arcount
    msg.extend_from_slice(&query[12..]); // question section echo
    if truncated {
        return msg;
    }
    for addr in addrs {
        msg.extend([0xC0, 0x0C]); // owner: pointer to the question name
        msg.extend(qtype.to_be_bytes());
        msg.extend(1u16.to_be_bytes()); // class IN
        msg.extend(60u32.to_be_bytes()); // ttl
        match addr {
            IpAddr::V4(v4) => {
                msg.extend(4u16.to_be_bytes());
                msg.extend(v4.octets());
            }
            IpAddr::V6(v6) => {
                msg.extend(16u16.to_be_bytes());
                msg.extend(v6.octets());
            }
        }
    }
    msg
}

/// Spawns the mock DNS server: UDP and TCP on ONE port, answering
/// `udp_queries` datagrams per `mode` and, for [`MockMode::TcOverTcp`],
/// exactly one TCP retry. Returns the mock's port and the counter of
/// received UDP queries.
fn spawn_dns_mock(mode: MockMode, udp_queries: usize) -> (u16, Arc<AtomicUsize>) {
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    let tcp = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    let received = Arc::new(AtomicUsize::new(0));
    let counter = received.clone();
    std::thread::spawn(move || {
        for _ in 0..udp_queries {
            let mut buf = [0u8; 512];
            let (len, src) = match udp.recv_from(&mut buf) {
                Ok(value) => value,
                Err(_) => return,
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let query = &buf[..len];
            let is_a = len >= 4 && query[len - 4] == 0 && query[len - 3] == 1;
            let reply = match mode {
                MockMode::Answers => {
                    if is_a {
                        build_reply(query, &[IpAddr::from([127, 0, 0, 1])], false, 0)
                    } else {
                        build_reply(
                            query,
                            &[IpAddr::V6(Ipv6Addr::LOCALHOST)],
                            false,
                            0,
                        )
                    }
                }
                MockMode::NxDomain => build_reply(query, &[], false, 3),
                MockMode::TcOverTcp => {
                    if is_a {
                        build_reply(query, &[], true, 0)
                    } else {
                        build_reply(
                            query,
                            &[IpAddr::V6(Ipv6Addr::LOCALHOST)],
                            false,
                            0,
                        )
                    }
                }
            };
            let _ = udp.send_to(&reply, src);
        }
        if mode == MockMode::TcOverTcp {
            // The TCP retry for the truncated A answer: two-byte length
            // prefix, then the query; reply with a usable loopback A.
            let (mut stream, _) = match tcp.accept() {
                Ok(value) => value,
                Err(_) => return,
            };
            let mut length = [0u8; 2];
            if stream.read_exact(&mut length).is_err() {
                return;
            }
            let mut query = vec![0u8; u16::from_be_bytes(length) as usize];
            if stream.read_exact(&mut query).is_err() {
                return;
            }
            let reply = build_reply(&query, &[IpAddr::from([127, 0, 0, 1])], false, 0);
            let mut framed = Vec::with_capacity(reply.len() + 2);
            framed.extend((reply.len() as u16).to_be_bytes());
            framed.extend(reply);
            let _ = stream.write_all(&framed);
        }
    });
    (port, received)
}

/// Spawns a minimal HTTP/1.1 server on 127.0.0.1: every request gets one
/// static 200 response with the body "Hi!".
fn spawn_http_server() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(value) => value,
                Err(_) => return,
            };
            // Read the request head, then answer.
            let mut buf = [0u8; 4096];
            let mut got = 0;
            loop {
                match stream.read(&mut buf[got..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        got += n;
                        if buf[..got].windows(4).any(|w| w == b"\r\n\r\n") || got == buf.len() {
                            break;
                        }
                    }
                }
            }
            let body = "Hi!";
            let response =
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

/// Builds a GET request to the test name behind the given port.
fn build_request(port: u16) -> ylong_http_client::async_impl::Request {
    RequestBuilder::new()
        .method("GET")
        .url(format!("http://{TEST_NAME}:{port}/data").as_str())
        .header("Content-Length", "6")
        .body(Body::slice("Hello!".as_bytes()))
        .unwrap()
}

/// Builds the owner-aware client against the mock DNS port.
fn build_client(dns_port: u16) -> Client {
    // fchown to the process's own uid/gid is always permitted, so the
    // owner-aware sockets bind without privileges.
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    Client::builder()
        .sockets_owner(uid, gid)
        .dns_servers(vec!["127.0.0.1".to_string()])
        .dns_port(dns_port)
        .build()
        .unwrap()
}

/// Sends one request and verifies the response status and body.
async fn request_ok(client: &Client, port: u16) {
    let mut response = client.request(build_request(port)).await.unwrap();
    assert_eq!(response.status().as_u16(), 200, "response status");
    let mut buf = [0u8; 4096];
    let mut size = 0;
    loop {
        let read = response.data(&mut buf[size..]).await.unwrap();
        if read == 0 {
            break;
        }
        size += read;
    }
    assert_eq!(&buf[..size], b"Hi!", "response body");
}

/// SDV case for the basic UDP path through the public API: both family
/// queries hit the override server, the answer addresses are connected,
/// and the HTTP exchange completes.
///
/// # Brief
/// 1. Starts the mock DNS server (A -> 127.0.0.1, AAAA -> ::1) and the
///    HTTP server.
/// 2. Builds a client with `sockets_owner` + `dns_servers` and sends a
///    request to `owner.vpn.test`.
/// 3. Verifies status 200 and the body, and that exactly two queries
///    (A + AAAA) reached the mock.
#[test]
fn sdv_owner_resolver_udp_basic() {
    let (dns_port, received) = spawn_dns_mock(MockMode::Answers, 2);
    let http_port = spawn_http_server();
    let client = build_client(dns_port);

    ylong_runtime::block_on(async move {
        request_ok(&client, http_port).await;
    });
    assert_eq!(received.load(Ordering::SeqCst), 2, "A + AAAA queries");
}

/// SDV case for the authoritative-negative path through the public API:
/// NXDOMAIN from the only configured server kills the candidate, no other
/// source is consulted (no search candidates, no system resolver
/// fallback) and the request fails.
///
/// # Brief
/// 1. Starts the mock in NXDOMAIN mode.
/// 2. Sends a request through the owner-aware client.
/// 3. Verifies the request fails and the mock saw both family queries.
#[test]
fn sdv_owner_resolver_nxdomain_error() {
    let (dns_port, received) = spawn_dns_mock(MockMode::NxDomain, 2);
    let http_port = spawn_http_server();
    let client = build_client(dns_port);

    ylong_runtime::block_on(async move {
        let result = client.request(build_request(http_port)).await;
        assert!(result.is_err(), "NXDOMAIN must fail the request");
    });
    assert_eq!(received.load(Ordering::SeqCst), 2, "A + AAAA queries");
}

/// SDV case for the no-cache posture through the public API: two fresh
/// clients against the same mock each resolve from scratch (four queries
/// in total) — nothing is cached between clients, and the resolution is
/// never served from any shared tier.
///
/// # Brief
/// 1. Starts the mock answering four queries.
/// 2. Two clients each send one request to the same URL.
/// 3. Both requests succeed and the mock saw four queries.
#[test]
fn sdv_owner_resolver_no_shared_cache() {
    let (dns_port, received) = spawn_dns_mock(MockMode::Answers, 4);
    let http_port = spawn_http_server();

    ylong_runtime::block_on(async move {
        {
            let client = build_client(dns_port);
            request_ok(&client, http_port).await;
        }
        {
            let client = build_client(dns_port);
            request_ok(&client, http_port).await;
        }
    });
    assert_eq!(received.load(Ordering::SeqCst), 4, "two resolutions");
}

/// SDV case for the TC-over-TCP retry through the public API: the UDP
/// answer for the A query is truncated (TC=1), the exchange retries over
/// TCP to the same server and the committed answer connects.
///
/// # Brief
/// 1. Starts the mock in TcOverTcp mode (UDP A truncated, AAAA answered;
///    the TCP listener on the same port returns a valid A).
/// 2. Sends a request through the owner-aware client.
/// 3. Verifies status 200 and the body, and that both UDP queries and one
///    TCP retry reached the mock.
#[test]
fn sdv_owner_resolver_tc_over_tcp() {
    let (dns_port, received) = spawn_dns_mock(MockMode::TcOverTcp, 2);
    let http_port = spawn_http_server();
    let client = build_client(dns_port);

    ylong_runtime::block_on(async move {
        request_ok(&client, http_port).await;
    });
    assert_eq!(received.load(Ordering::SeqCst), 2, "A + AAAA UDP queries");
}
