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

//! The res_msend port: both family queries share one owner socket and are
//! broadcast to every configured server under a total time budget,
//! mirroring musl `__res_msend_rc` (`res_msend.c` L237-847) with the musl
//! OHOS musl build rules (v4 fast-exit, invalid-A retry, NXDOMAIN consensus,
//! TC-over-TCP rollback).

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::time::{Duration, Instant};

use super::error::{fail_to_parse, timeout_error};
use super::query::DualQuery;
use super::wire::{
    parse_response, ParseOutcome, FLAG_TC, RCODE_NOERROR, RCODE_NXDOMAIN, RCODE_SERVFAIL,
};
use super::owner_resolver::OwnerAwareResolver;
use crate::async_impl::dns::config::{ResolvConf, MAX_NAMESERVERS};
use crate::runtime::{timeout, AsyncReadExt, AsyncWriteExt, TcpStream, UdpSocket};

/// Receiving buffer of a UDP DNS exchange. DNS over UDP traditionally caps
/// messages at 512 bytes [RFC1035, Section 2.3.4]; longer replies set TC=1
/// and are retried over TCP [RFC1035, Section 4.2.1], so this is a generous
/// upper bound for the UDP path.
///
/// [RFC1035, Section 2.3.4]: https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.4
/// [RFC1035, Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.1
const UDP_RECV_BUF: usize = 4096;

/// The family filter (musl `queryNum`, lookup_name.c L309-330):
/// which families the exchange actually queries. `Both` is the dual
/// `queryNum = 2`; the single-family values are `queryNum = 1` with the
/// one `afrr` table entry. Slots keep the fixed mapping [0] = AAAA,
/// [1] = A; a filtered family's slot is never sent, never matched and
/// stays `None` in the result.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum FamilyMask {
    Both,
    /// Only the A query exists (v6 disabled or an AAAA-nodata cache hit).
    V4Only,
    /// Only the AAAA query exists (v4 disabled).
    V6Only,
}

impl FamilyMask {
    /// Whether family slot `i` ([0] AAAA, [1] A) takes part in the
    /// exchange.
    pub(super) fn is_active(self, slot: usize) -> bool {
        match self {
            FamilyMask::Both => true,
            FamilyMask::V4Only => slot == 1,
            FamilyMask::V6Only => slot == 0,
        }
    }
}

/// musl res_msend: the first valid v4 records end the wait early — within
/// `LARGE_LATENCY` of the round start only `MIN_WAIT_V6` is granted for v6
/// answers, beyond it the exchange returns immediately
/// (`res_msend.c` L19-22, L538-571).
const LARGE_LATENCY: Duration = Duration::from_millis(500);

const MIN_WAIT_V6: Duration = Duration::from_millis(80);

/// Sends both family queries to ALL configured servers through ONE owner
/// socket, mirroring musl `__res_msend_rc` (res_msend.c L237-847): the
/// socket and the per-query state live in [`Exchange`]; this drives the
/// budget loop — the total budget `conf.timeout` is split into
/// `conf.attempts` rounds, each round resends every still-unanswered query
/// to the configured server set, and the exchange ends when
/// [`Exchange::exchange_complete`] fires or the budget runs out.
/// Truncation is detected exactly as musl does: the DNS header TC bit OR
/// the kernel-side `recvmsg` `MSG_TRUNC` flag ([RFC1035, Section 4.2.1],
/// `res_msend.c` L739), observed through `UdpSocket::recv_from_truncated`.
///
/// The loop shape is musl's exactly (L411-457): there is NO pre-loop send —
/// `t1 = t2 - retry_interval` (L415) makes the FIRST pass fire the round
/// boundary, so the first send happens there and consumes attempt #1
/// (`query_round` 0→1, L461); `retry_count` bumps once per pass (L421-422)
/// and selects the first-round server set. `mask` is the family
/// filter: only the active families are built as queries (musl
/// `queryNum`, lookup_name.c L309-330). Returns the accepted raw answer
/// per family; `None` = no answer (or the family was filtered out).
///
/// [RFC1035, Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.1
pub(super) async fn run(
    resolver: &OwnerAwareResolver,
    servers: &[SocketAddr],
    query: &DualQuery,
    conf: &ResolvConf,
    mask: FamilyMask,
) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let start = Instant::now();
    let deadline = start + conf.timeout;
    let Some(mut ex) = Exchange::bind(resolver, servers, query, conf, mask, deadline).await else {
        return (None, None);
    };
    // musl divides by `attempts` unguarded; the config caps keep it
    // positive in practice, the floor here is a Rust division guard.
    let attempts = conf.attempts.max(1);
    let retry_interval = conf.timeout / attempts;
    // musl L415: `t1 = t2 - retry_interval` — the first loop pass sees
    // `t2 - t1 >= retry_interval` and fires the round boundary at once.
    let mut round_start = start.checked_sub(retry_interval).unwrap_or(start);
    'budget: loop {
        let now = Instant::now();
        if now >= deadline || ex.exchange_complete() {
            break;
        }
        ex.retry_count += 1; // musl L421-422: one bump per poll pass
                             // L442-445: when every A reply of this round was invalid, the
                             // next round fires immediately instead of finishing the wait.
        if ex.round_accelerated() {
            round_start = now.checked_sub(retry_interval).unwrap_or(now);
        }
        if now.duration_since(round_start) >= retry_interval {
            if ex.round_boundary_exit(attempts) {
                break;
            }
            ex.query_round += 1; // musl L461
            ex.send_round().await;
            round_start = now;
        }
        let window = ex.poll_window(deadline, round_start, retry_interval);
        if window.is_zero() {
            break;
        }
        match timeout(window, ex.socket.recv_from_truncated(&mut ex.buf)).await {
            Ok(Ok((len, peer, truncated))) => {
                if ex.handle_reply(len, peer, truncated).await {
                    break 'budget; // musl `goto out`: fatal TCP rcode
                                   // (L766-771)
                }
                // musl L577-600 (`while (next < nqueries)`): the poll
                // returned ready; the remaining queued datagrams of
                // this pass are drained nonblocking, one per query
                // slot (`rlen < 4` keeps draining, L601-602); EAGAIN
                // returns to polling (L592-599).
                for _ in 1..ex.query_count() {
                    match ex.socket.try_recv_from_truncated(&mut ex.buf) {
                        Ok((len, peer, truncated)) => {
                            if ex.handle_reply(len, peer, truncated).await {
                                break 'budget;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
            Ok(Err(_)) => continue, // L589-597: back to polling
            Err(_) => continue,     // poll timeout (L574)
        }
    }
    ex.into_answers()
}

/// One `res_msend` exchange: the owner socket shared by both family queries
/// plus the mutable per-query state musl keeps in locals (res_msend.c
/// L397-437). Field names follow musl (`ans`, `retry`, `nres_*`,
/// `servfail_retry`, ...) so the port stays reviewable against the original.
struct Exchange<'a> {
    resolver: &'a OwnerAwareResolver,
    servers: &'a [SocketAddr],
    query: &'a DualQuery,
    socket: UdpSocket,
    /// Whether `socket` is an IPv6 socket; v4 servers are addressed as
    /// v4-mapped on it.
    v6_socket: bool,
    /// Exchange end (musl `t0 + timeout`): the budget shared by the UDP
    /// rounds and the TCP retries.
    deadline: Instant,
    /// Accepted raw answer per family: [0] AAAA, [1] A; None = pending.
    ans: [Option<Vec<u8>>; 2],
    /// The A answer holds records but every one of them is invalid
    /// (127.0.0.0/8 or 0.0.0.0): the query keeps polling for another
    /// server's answer (res_msend.c L724-736).
    no_valid_v4: [bool; 2],
    /// NXDOMAIN votes per family: NXDOMAIN is accepted only from the last
    /// expected server (res_msend.c L657-675).
    retry: [usize; 2],
    /// musl record counters: valid v4, invalid v4 and v6 records seen so
    /// far (L693-723).
    nres_v4: u32,
    nres_invalid_v4: u32,
    nres_v6: u32,
    query_round: u32,
    /// The v4 fast-exit granted its final window (L538-571): without a
    /// reply in it, the exchange ends.
    end_query: bool,
    /// SERVFAIL resend budget, reset to `2 * nqueries` every round (L534).
    servfail_retry: u32,
    /// When the first valid v4 records were seen, for the fast-exit.
    v4_seen_at: Option<Instant>,
    /// Per-round A-query accounting for the invalid-round acceleration
    /// (L442-445): sends, replies and invalid/NXDOMAIN replies.
    v4_sent_this_round: u32,
    v4_recv_this_round: u32,
    v4_invalid_this_round: u32,
    /// The family filter (musl `queryNum`): which slots exist.
    mask: FamilyMask,
    /// musl L262-276: poll-pass counter (`retry_count`), bumped once per
    /// loop pass; `<= 1` selects the first-round server set.
    retry_count: u32,
    /// musl `conf->non_public` (resolvconf.c L165): the first send round
    /// targets only the leading `non_public` servers when positive.
    non_public: usize,
    /// musl L281-334: the server bookkeeping — v4/v6 server index
    /// counts (`nv4`/`nv6`), the multiV4 flag with its first-try /
    /// second-try index sets, and the last server index a slot rotated to
    /// (`last_retry`), which the next multiV4 round resumes from.
    nv4: usize,
    nv6: usize,
    multi_v4: bool,
    first_try: [usize; 3],
    sec_try: [usize; 3],
    last_retry: usize,
    buf: [u8; UDP_RECV_BUF],
}

impl<'a> Exchange<'a> {
    /// Binds the shared exchange socket exactly like musl L338-395: IPv6
    /// when any server is IPv6 (v4 servers become v4-mapped; Linux keeps
    /// `IPV6_V6ONLY` off by default), downgraded to IPv4 when v6 is
    /// unavailable, and failed outright for an all-v6 list without v6
    /// support (DNS_FAIL_REASON_LACK_V6_SUPPORT). The owner is set before
    /// bind so no packet can leave un-owned (AC-1.6).
    async fn bind(
        resolver: &'a OwnerAwareResolver,
        servers: &'a [SocketAddr],
        query: &'a DualQuery,
        conf: &ResolvConf,
        mask: FamilyMask,
        deadline: Instant,
    ) -> Option<Exchange<'a>> {
        // Contract: every entry point (the resolv.conf parse, the
        // `parse_dns_servers` override) truncates the server list to the
        // musl MAXNS bound; the round bookkeeping below is only defined
        // under it (musl relies on the same invariant, `resolvconf.c`
        // L157/L217). A violation is a caller bug: loud in debug builds,
        // unreachable through any configured path.
        debug_assert!(
            servers.len() <= MAX_NAMESERVERS,
            "server list exceeds the musl MAXNS cap"
        );
        let any_v6 = servers.iter().any(|server| server.is_ipv6());
        let all_v6 = servers.iter().all(|server| server.is_ipv6());
        let (socket, v6_socket) = if any_v6 {
            match UdpSocket::bind_with_owner("[::]:0", resolver.uid, resolver.gid).await {
                Ok(socket) => (socket, true),
                Err(_) => {
                    if all_v6 {
                        return None;
                    }
                    match UdpSocket::bind_with_owner("0.0.0.0:0", resolver.uid, resolver.gid).await
                    {
                        Ok(socket) => (socket, false),
                        Err(_) => return None,
                    }
                }
            }
        } else {
            match UdpSocket::bind_with_owner("0.0.0.0:0", resolver.uid, resolver.gid).await {
                Ok(socket) => (socket, false),
                Err(_) => return None,
            }
        };
        let (nv4, nv6, multi_v4, first_try, sec_try) = compute_try_sets(servers, conf.non_public);
        Some(Exchange {
            resolver,
            servers,
            query,
            socket,
            v6_socket,
            deadline,
            ans: [None, None],
            no_valid_v4: [false; 2],
            retry: [0; 2],
            nres_v4: 0,
            nres_invalid_v4: 0,
            nres_v6: 0,
            query_round: 0,
            end_query: false,
            servfail_retry: 0,
            v4_seen_at: None,
            v4_sent_this_round: 0,
            v4_recv_this_round: 0,
            v4_invalid_this_round: 0,
            mask,
            retry_count: 0,
            non_public: conf.non_public,
            nv4,
            nv6,
            multi_v4,
            first_try,
            sec_try,
            last_retry: 0,
            buf: [0u8; UDP_RECV_BUF],
        })
    }

    /// On the IPv6 socket, v4 servers are addressed as v4-mapped (musl
    /// L371-384 converts them the same way).
    fn send_addr(&self, server: &SocketAddr) -> SocketAddr {
        if self.v6_socket {
            if let IpAddr::V4(v4) = server.ip() {
                return SocketAddr::new(IpAddr::V6(v4.to_ipv6_mapped()), server.port());
            }
        }
        *server
    }

    /// musl L426-441: the exchange ends when every QUERIED family holds an
    /// accepted answer (the filtered family has no query, L426's loop runs
    /// over `nqueries`), when the v4 fast-exit granted its final window
    /// (`end_query`), or when an invalid-only A answer and v6 records are
    /// both in.
    fn exchange_complete(&self) -> bool {
        [0usize, 1]
            .into_iter()
            .filter(|&slot| self.mask.is_active(slot))
            .all(|slot| self.ans[slot].is_some() && !self.no_valid_v4[slot])
            || self.end_query
            || (self.nres_v6 > 0 && self.nres_invalid_v4 > 0)
    }

    /// musl `nqueries` (lookup_name.c L360-367): the number of family
    /// queries this exchange actually built; bounds the per-pass drain.
    fn query_count(&self) -> usize {
        match self.mask {
            FamilyMask::Both => 2,
            FamilyMask::V4Only | FamilyMask::V6Only => 1,
        }
    }

    /// musl L442-445: every A reply of this round was invalid or NXDOMAIN —
    /// the next round fires immediately instead of finishing the wait.
    fn round_accelerated(&self) -> bool {
        self.v4_sent_this_round > 0
            && self.v4_recv_this_round >= self.v4_sent_this_round
            && self.v4_invalid_this_round == self.v4_recv_this_round
    }

    /// musl L448-457: a round boundary with valid v4 records in hand ends
    /// the exchange; rounds are capped by `attempts`.
    fn round_boundary_exit(&self, attempts: u32) -> bool {
        self.nres_v4 > 0 || self.query_round >= attempts
    }

    /// The round-boundary send (musl L462-535): resets the per-round
    /// counters and the per-slot server rotation — multiV4 resumes every
    /// slot from `last_retry` (L466-467) — then re-sends every
    /// still-unanswered query of the ACTIVE families to the selected
    /// server set: the multiV4 first/second-try sets (L472-490), or the
    /// first `non_public` servers on the first pass (L492-500), otherwise
    /// all of them. The SERVFAIL budget is `2 * nqueries` (L534). A-query
    /// sends are counted for the invalid-round acceleration. `query_round`
    /// is NOT touched here: it counts the boundaries passed and is advanced
    /// by the caller (musl L461).
    async fn send_round(&mut self) {
        self.retry = if self.multi_v4 {
            [self.last_retry; 2]
        } else {
            [0, 0]
        };
        self.v4_sent_this_round = 0;
        self.v4_recv_this_round = 0;
        self.v4_invalid_this_round = 0;
        // musl L534: the SERVFAIL resend budget is 2 * nqueries (the slot
        // count of the active families), not a constant.
        self.servfail_retry = 2 * self.query_count() as u32;
        for i in [1usize, 0] {
            if !self.mask.is_active(i) {
                continue;
            }
            if self.ans[i].is_some() && !self.no_valid_v4[i] {
                continue;
            }
            let bytes = if i == 1 {
                &self.query.query_a
            } else {
                &self.query.query_aaaa
            };
            let is_a_query = i == 1;
            if self.multi_v4 {
                // musl L473-490: the first pass uses the first-try set
                // (two v4 plus all v6, or four v4), later passes the
                // remaining v4.
                let (limit, set) = if self.retry_count <= 1 {
                    (if self.nv6 > 0 { 2 + self.nv6 } else { 4 }, &self.first_try)
                } else {
                    (
                        if self.nv6 > 0 {
                            self.nv4.saturating_sub(2)
                        } else {
                            self.nv4.saturating_sub(4)
                        },
                        &self.sec_try,
                    )
                };
                for j in 0..limit {
                    if j >= set.len() {
                        break; // musl indexes `int try_ns[MAXNS]`; the sets are
                               // bounded the same way
                    }
                    let server = &self.servers[set[j]];
                    let sent = self
                        .socket
                        .send_to(bytes, self.send_addr(server))
                        .await
                        .is_ok();
                    if sent && is_a_query {
                        self.v4_sent_this_round += 1;
                    }
                }
            } else {
                // musl L492-535: the first pass sends only to the leading
                // `non_public` servers when the musl build marks any ("First time
                // only use non public ns"); otherwise and afterwards to all.
                let limit = if self.retry_count <= 1 && self.non_public > 0 {
                    self.non_public.min(self.servers.len())
                } else {
                    self.servers.len()
                };
                for server in &self.servers[..limit] {
                    let sent = self
                        .socket
                        .send_to(bytes, self.send_addr(server))
                        .await
                        .is_ok();
                    if sent && is_a_query {
                        self.v4_sent_this_round += 1;
                    }
                }
            }
        }
    }

    /// Computes the poll window (musl L538-574): the total budget cap, the
    /// current round cap, and — once valid v4 records are in — the v4
    /// fast-exit: within `LARGE_LATENCY` of the round start v6 gets
    /// `MIN_WAIT_V6` more, beyond it (or past the grace) the window is
    /// zero and the caller ends the exchange.
    fn poll_window(
        &mut self,
        deadline: Instant,
        round_start: Instant,
        retry_interval: Duration,
    ) -> Duration {
        let now = Instant::now();
        let mut window = deadline.checked_duration_since(now).unwrap_or_default();
        if let Some(left) = round_start
            .checked_add(retry_interval)
            .and_then(|next| next.checked_duration_since(now))
        {
            window = window.min(left);
        }
        if self.nres_v4 > 0 {
            match self.v4_seen_at {
                None => {
                    if now.duration_since(round_start) <= LARGE_LATENCY {
                        self.v4_seen_at = Some(now);
                        self.end_query = true;
                        window = window.min(MIN_WAIT_V6);
                    } else {
                        // The v4 answer was slow to arrive: no v6 grace.
                        window = Duration::ZERO;
                    }
                }
                Some(seen) => {
                    let left = seen
                        .checked_add(MIN_WAIT_V6)
                        .and_then(|end| end.checked_duration_since(now));
                    window = window.min(left.unwrap_or_default());
                }
            }
        }
        window
    }

    /// Processes one datagram (musl L575-847): source filtering, TXID
    /// matching, rcode dispatch, accept+count through the musl record
    /// classes, and the truncated-reply → TCP retry with rollback. The
    /// `truncated` flag is the kernel-side `recvmsg` `MSG_TRUNC` signal,
    /// OR-ed with the TC bit exactly as musl L739 does. Returns `true`
    /// when the exchange must be abandoned (musl `goto out`).
    ///
    /// Boxed on purpose: the resolver's boxed future needs `Send + Sync`,
    /// and chaining a nested `async fn` opaque type into that bound is
    /// rejected by the OHOS rustc (1.72). The trait object carries the
    /// auto traits by declaration, cutting the opaque-type chain.
    fn handle_reply(
        &mut self,
        len: usize,
        peer: SocketAddr,
        truncated: bool,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + Sync + '_>> {
        Box::pin(async move {
            self.end_query = false; // L575
            // `len` is the datagram length reported by `recv_from`, which is
            // contractually capped at the buffer size.
            debug_assert!(len <= UDP_RECV_BUF);
            if len < 4 {
                return false; // L600
            }
            let Some(peer) = self.filter_peer(peer) else {
                return false;
            };
            let Some(idx) = self.match_query() else {
                return false;
            };
            if self.ans[idx].is_some() && !self.no_valid_v4[idx] {
                return false; // L642/L648
            }
            let is_a_query = idx == 1;
            if is_a_query {
                self.v4_recv_this_round += 1; // L643-646
            }
            match (self.buf[3] & 0x0F) as u16 {
                RCODE_SERVFAIL => {
                    self.resend_servfail(is_a_query, peer).await;
                    return false;
                }
                RCODE_NXDOMAIN => {
                    // Only the last expected server finalizes an NXDOMAIN
                    // (L657-675); earlier ones keep the query waiting and —
                    // multiV4 only (L662-664) — record the rotation for the
                    // next round's resume point.
                    if self.retry[idx] + 1 < self.servers.len() {
                        self.retry[idx] += 1;
                        if self.multi_v4 {
                            self.last_retry = self.retry[idx];
                        }
                        if is_a_query {
                            self.v4_invalid_this_round += 1; // L664-666
                        }
                        return false;
                    }
                }
                RCODE_NOERROR => {}
                _ => return false,
            }
            if self.accept(idx, is_a_query, len) {
                return false; // L724-736: keep polling the other servers.
            }
            if u16::from_be_bytes([self.buf[2], self.buf[3]]) & FLAG_TC != 0 || truncated {
                return self.retry_over_tcp(idx, is_a_query, peer).await;
            }
            false
        })
    }

    /// Source filter (musl L602-634): the reply must come from a configured
    /// server; v4-mapped peers are normalized first. Returns `None` for
    /// foreign sources.
    fn filter_peer(&self, peer: SocketAddr) -> Option<SocketAddr> {
        let peer = match peer {
            SocketAddr::V6(v6) => v6
                .ip()
                .to_ipv4_mapped()
                .map(|v4| SocketAddr::new(IpAddr::V4(v4), v6.port()))
                .unwrap_or(peer),
            other => other,
        };
        Self::peer_matches_server(self.servers, &peer).then_some(peer)
    }

    /// Whether `peer` is one of the configured servers (musl L607-621):
    /// family, port and address must match — except that a configured
    /// unspecified address (0.0.0.0 / ::) accepts any same-port source.
    ///
    /// That wildcard is OHOS musl's deliberate behavior, not an
    /// invention of this port: res_msend.c L612 matches
    /// `ns[j].sin.sin_addr.s_addr == INADDR_ANY ||` for IPv4 and L620
    /// `IN6_IS_ADDR_UNSPECIFIED(...) ||` for IPv6, so a
    /// `nameserver 0.0.0.0` entry works against a local resolver whose
    /// replies come from 127.0.0.1. Upstream musl compares the full
    /// sockaddr instead; diverging here would reject replies the
    /// platform resolver accepts. The transaction id and the
    /// ephemeral source port of the query socket remain the active
    /// anti-spoofing controls.
    fn peer_matches_server(servers: &[SocketAddr], peer: &SocketAddr) -> bool {
        servers.iter().any(|server| {
            server.port() == peer.port()
                && (server.ip().is_unspecified() || server.ip() == peer.ip())
        })
    }

    /// Matches the datagram to one of the two family queries by transaction
    /// id (musl L636-649); `None` = unrelated datagram. A filtered-out
    /// family has no query in flight (musl `nqueries = 1`), so a stray
    /// datagram carrying its id is unrelated too. The header reads are
    /// bounded by the `len < 4` gate at the single call site
    /// (`handle_reply`), and `buf` is a fixed-capacity array, so no
    /// datagram length can panic here.
    fn match_query(&self) -> Option<usize> {
        let id = u16::from_be_bytes([self.buf[0], self.buf[1]]);
        let idx = if id == self.query.id_aaaa {
            0
        } else if id == self.query.id_a {
            1
        } else {
            return None;
        };
        if !self.mask.is_active(idx) {
            return None;
        }
        Some(idx)
    }

    /// SERVFAIL (musl L676-680): an immediate resend to the replying
    /// server, bounded by `servfail_retry`.
    async fn resend_servfail(&mut self, is_a_query: bool, peer: SocketAddr) {
        if self.servfail_retry == 0 {
            return;
        }
        self.servfail_retry -= 1;
        let bytes = if is_a_query {
            &self.query.query_a
        } else {
            &self.query.query_aaaa
        };
        let _ = self.socket.send_to(bytes, peer).await;
    }

    /// Stores the accepted answer and updates the musl counters
    /// (res_msend.c L685-736). Returns `true` when the A answer holds
    /// records but every one of them is invalid and another server is
    /// still expected: the query stays in flight (musl `continue`).
    fn accept(&mut self, idx: usize, is_a_query: bool, len: usize) -> bool {
        self.ans[idx] = Some(self.buf[..len].to_vec());
        let (valid_v4, invalid_v4, v6_count) =
            classify_records(self.ans[idx].as_deref().unwrap_or(&[]));
        if is_a_query {
            self.nres_v4 += valid_v4;
            self.nres_invalid_v4 += invalid_v4;
            if valid_v4 == 0 {
                self.v4_invalid_this_round += 1; // L719-721
            }
            // L724 is an assignment, not a sticky set: a later A answer
            // holding valid records clears the flag again.
            self.no_valid_v4[1] = invalid_v4 > 0 && valid_v4 == 0;
            if self.no_valid_v4[1] && self.retry[1] + 1 < self.servers.len() {
                // All-invalid A answer with another server remaining
                // (L725-736): rotate to it (multiV4 records the rotation,
                // L729-731) and keep polling — musl `continue`s here,
                // skipping the TC/TCP check below. On the LAST server the
                // `continue` is gated by `retry[i]+1 < nns` and musl falls
                // through to the TC check instead, so this arm returns
                // false there.
                self.retry[1] += 1;
                if self.multi_v4 {
                    self.last_retry = self.retry[1];
                }
                return true;
            }
        } else {
            self.nres_v6 += v6_count;
        }
        false
    }

    /// TC retry (musl L739-774): back up the truncated UDP answer, retry
    /// over TCP to the replying server with the remaining budget, commit a
    /// NOERROR/NXDOMAIN reply, roll back on failure. A fatal TCP rcode
    /// abandons the whole exchange (`goto out`, returns `true`).
    async fn retry_over_tcp(&mut self, idx: usize, is_a_query: bool, peer: SocketAddr) -> bool {
        let backup = self.ans[idx].clone();
        self.ans[idx] = None;
        self.nres_v4 = 0; // L761
        let bytes = if is_a_query {
            &self.query.query_a
        } else {
            &self.query.query_aaaa
        };
        let window = self
            .deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default();
        match self.tcp_exchange(peer, bytes, window).await {
            Ok(reply) => {
                let tcp_rcode = if reply.len() >= 4 {
                    (reply[3] & 0x0F) as u16
                } else {
                    u16::MAX
                };
                if tcp_rcode == RCODE_NOERROR || tcp_rcode == RCODE_NXDOMAIN {
                    self.ans[idx] = Some(reply); // committed (L812-817)
                } else {
                    // musl `goto out`: abandon the whole exchange; the
                    // other family keeps its accepted answer and this one
                    // rolls back to the truncated UDP bytes (L822-834).
                    self.ans[idx] = backup;
                    return true;
                }
            }
            // Incomplete TCP → roll back to the truncated UDP answer
            // (L822-834).
            Err(_) => {
                self.ans[idx] = backup;
            }
        }
        false
    }

    /// Returns the accepted raw answers: AAAA first, then A.
    fn into_answers(mut self) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        (self.ans[0].take(), self.ans[1].take())
    }

    /// Retries one query over TCP, with the same owner set on the TCP
    /// socket. The request and the response are prefixed with a two-byte
    /// big-endian length ([RFC1035, Section 4.2.2]). `window` is the
    /// remaining total budget (musl keeps the TCP exchange inside the same
    /// poll loop); a response shorter than 13 bytes is abandoned like
    /// musl's `alen < 13` check (L805).
    ///
    /// [RFC1035, Section 4.2.2]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2
    async fn tcp_exchange(
        &self,
        server: SocketAddr,
        query: &[u8],
        window: Duration,
    ) -> io::Result<Vec<u8>> {
        let mut stream =
            TcpStream::connect_with_owner(server, self.resolver.uid, self.resolver.gid).await?;
        let mut request = Vec::with_capacity(query.len() + 2);
        request.extend_from_slice(&(query.len() as u16).to_be_bytes());
        request.extend_from_slice(query);
        timeout(window, stream.write_all(&request))
            .await
            .map_err(|_| timeout_error())??;

        let mut length = [0u8; 2];
        timeout(window, stream.read_exact(&mut length))
            .await
            .map_err(|_| timeout_error())??;
        let len = u16::from_be_bytes(length) as usize;
        if len < 13 {
            return Err(fail_to_parse("DNS TCP response too short"));
        }
        let mut response = vec![0u8; len];
        timeout(window, stream.read_exact(&mut response))
            .await
            .map_err(|_| timeout_error())??;
        Ok(response)
    }
}

/// musl L281-334: the server bookkeeping, computed once per
/// exchange. Walks the server list recording v4/v6 indexes (`iv4`/`iv6`,
/// bounded by MAXNS = the config's server cap), then evaluates the
/// multiV4 formula — `(nv4 > 3 && nns != non_public) || (nv4 > 2 && nns ==
/// non_public)` — and fills the first-try / second-try index sets: the
/// first pass uses two v4 plus all v6 (or four v4), the second the
/// remaining v4. With the MAXNS = 3 server cap, `nv4 + nv6 <= 3` holds, so
/// the formula's second branch (`nv4 > 2`) forces `nv6 == 0` and the
/// adjustment block resets `multiV4` — the flag is provably dead under the
/// current caps, kept verbatim for 1:1 reviewability (a future MAXNS lift
/// reactivates it unchanged).
///
/// The caps are enforced at every entry point (the resolv.conf parse, the
/// `parse_dns_servers` override); `Exchange::bind` debug-asserts the bound
/// before this function runs, so the array walks below stay in their
/// defined domain by construction.
fn compute_try_sets(
    servers: &[SocketAddr],
    non_public: usize,
) -> (usize, usize, bool, [usize; 3], [usize; 3]) {
    let mut iv4 = [0usize; 3];
    let mut iv6 = [0usize; 3];
    let (mut nv4, mut nv6) = (0usize, 0usize);
    // musl walks `conf->ns` unguarded (L283-299) and relies on the config
    // capping it at MAXNS; the write guards below keep the same walk
    // defined for longer lists (a Rust test feeds one to exercise the
    // live branch math).
    for (nns, server) in servers.iter().enumerate() {
        if server.is_ipv4() {
            if nv4 < 3 {
                iv4[nv4] = nns;
            }
            nv4 += 1;
        } else {
            if nv6 < 3 {
                iv6[nv6] = nns;
            }
            nv6 += 1;
        }
    }
    let mut multi_v4 =
        (nv4 > 3 && servers.len() != non_public) || (nv4 > 2 && servers.len() == non_public);
    let mut first_try = [0usize; 3];
    let mut sec_try = [0usize; 3];
    if multi_v4 {
        if nv6 > 0 {
            // Use two v4 and all v6 for the first try, the other v4 for
            // the second (L315-323).
            first_try[0] = iv4[0];
            first_try[1] = iv4[1];
            for k in 0..nv6 {
                if 2 + k < 3 {
                    first_try[2 + k] = iv6[k];
                }
            }
            for l in 2..nv4 {
                if l - 2 < 3 {
                    sec_try[l - 2] = iv4[l];
                }
            }
        } else if nv4 > 4 {
            // Use four v4 for the first try, the rest for the second
            // (L324-331).
            for k in 0..4 {
                if k < 3 {
                    first_try[k] = iv4[k];
                }
            }
            for l in 4..nv4 {
                if l - 4 < 3 {
                    sec_try[l - 4] = iv4[l];
                }
            }
        } else {
            multi_v4 = false; // L332-334
        }
    }
    (nv4, nv6, multi_v4, first_try, sec_try)
}

/// Counts one accepted answer through the musl record classes
/// (res_msend.c `type_parse_callback` L129-169): valid v4 records —
/// anything but 127.0.0.0/8 and 0.0.0.0 per OHOS musl `get_ipv4_invalid_type`
/// (dns_parse.c L5-19) — vs invalid ones; v6 records are never filtered.
fn classify_records(msg: &[u8]) -> (u32, u32, u32) {
    let mut valid_v4 = 0u32;
    let mut invalid_v4 = 0u32;
    let mut v6 = 0u32;
    if let ParseOutcome::Records(parsed) = parse_response(msg) {
        for (ip, _) in parsed.records {
            match ip {
                IpAddr::V4(v4) if v4.is_loopback() || v4.is_unspecified() => invalid_v4 += 1,
                IpAddr::V4(_) => valid_v4 += 1,
                IpAddr::V6(_) => v6 += 1,
            }
        }
    }
    (valid_v4, invalid_v4, v6)
}

#[cfg(test)]
mod ut_test {
    use std::io::{Read, Write};
    use std::net::{IpAddr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::super::config::ResolvConf;
    use super::super::query::DualQuery;
    use super::super::owner_resolver::OwnerAwareResolver;
    use super::super::test_util::{mock_reply, TEST_NAME};
    use super::{compute_try_sets, Exchange, FamilyMask};

    fn current_owner() -> (libc::uid_t, libc::gid_t) {
        // fchown to the process's own uid/gid is always permitted.
        unsafe { (libc::getuid(), libc::getgid()) }
    }

    /// With the TC bit clear, the kernel-side `recvmsg` `MSG_TRUNC` flag
    /// alone must trigger the TCP fallback exactly like TC does (musl
    /// res_msend.c L739 ORs TC with MSG_TRUNC): the committed answer is
    /// the TCP reply, not the partial UDP bytes.
    #[test]
    fn ut_handle_reply_msg_trunc_over_tcp() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let listener = std::net::TcpListener::bind(server).unwrap();
        let tcp_thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut length = [0u8; 2];
            stream.read_exact(&mut length).unwrap();
            let len = u16::from_be_bytes(length) as usize;
            let mut query = vec![0u8; len];
            stream.read_exact(&mut query).unwrap();
            let reply = mock_reply(&query, &[IpAddr::from([10, 0, 0, 7])], false, 0);
            let mut framed = Vec::with_capacity(reply.len() + 2);
            framed.extend((reply.len() as u16).to_be_bytes());
            framed.extend(reply);
            stream.write_all(&framed).unwrap();
        });

        ylong_runtime::block_on(async move {
            let resolver = OwnerAwareResolver::new(uid, gid);
            let query = DualQuery::build(TEST_NAME).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let servers = [server];
            let mut ex = Exchange::bind(
                &resolver,
                &servers,
                &query,
                &ResolvConf::default(),
                FamilyMask::Both,
                deadline,
            )
            .await
            .expect("bind exchange socket failed");

            // A clean NOERROR reply with one A record, TC clear; only the
            // MSG_TRUNC flag marks it as truncated.
            let udp_reply = mock_reply(&query.query_a, &[IpAddr::from([10, 0, 0, 9])], false, 0);
            ex.buf[..udp_reply.len()].copy_from_slice(&udp_reply);

            let abandon = ex.handle_reply(udp_reply.len(), server, true).await;
            assert!(!abandon);

            // The TCP thread echoes the A query, so the committed answer
            // is exactly the reply built from `query.query_a`.
            let tcp_reply = mock_reply(&query.query_a, &[IpAddr::from([10, 0, 0, 7])], false, 0);
            assert_eq!(ex.ans[1].as_deref(), Some(tcp_reply.as_slice()));
        });
        tcp_thread.join().unwrap();
    }

    /// Control case: TC clear and no MSG_TRUNC — the UDP answer is
    /// committed as-is and no TCP connection is attempted.
    #[test]
    fn ut_handle_reply_without_trunc_commits_udp() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let listener = std::net::TcpListener::bind(server).unwrap();
        let tcp_hits = Arc::new(AtomicUsize::new(0));
        let hits = tcp_hits.clone();
        let tcp_thread = std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_millis(500);
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let mut length = [0u8; 2];
                        let _ = stream.read_exact(&mut length);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => break,
                }
                if Instant::now() > deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });

        ylong_runtime::block_on(async move {
            let resolver = OwnerAwareResolver::new(uid, gid);
            let query = DualQuery::build(TEST_NAME).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let servers = [server];
            let mut ex = Exchange::bind(
                &resolver,
                &servers,
                &query,
                &ResolvConf::default(),
                FamilyMask::Both,
                deadline,
            )
            .await
            .expect("bind exchange socket failed");

            let udp_reply = mock_reply(&query.query_a, &[IpAddr::from([10, 0, 0, 9])], false, 0);
            ex.buf[..udp_reply.len()].copy_from_slice(&udp_reply);

            let abandon = ex.handle_reply(udp_reply.len(), server, false).await;
            assert!(!abandon);
            assert_eq!(ex.ans[1].as_deref(), Some(udp_reply.as_slice()));
        });
        tcp_thread.join().unwrap();
        assert_eq!(tcp_hits.load(Ordering::SeqCst), 0);
    }

    /// musl no_valid fall-through parity (res_msend.c L725-739): an
    /// all-invalid A answer (every record 0.0.0.0) on the LAST server must
    /// NOT skip the TC check — the `continue` in musl is gated by
    /// `retry[i]+1 < nns`, so on the last server the reply falls through to
    /// the TC/TCP path. With TC set, the truncated UDP answer is backed up
    /// and the query retries over TCP, whose valid answer is committed.
    ///
    /// # Brief
    /// 1. Binds one exchange against a single (hence last) mock server
    ///    listening on UDP and TCP at the same address.
    /// 2. Feeds an all-zero A answer carrying TC=1 into `handle_reply`.
    /// 3. Verifies no abandon, and that the committed A answer is the TCP
    ///    reply with a valid address.
    #[test]
    fn ut_handle_reply_allzero_last_server_falls_to_tcp() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let listener = std::net::TcpListener::bind(server).unwrap();
        let tcp_thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut length = [0u8; 2];
            stream.read_exact(&mut length).unwrap();
            let len = u16::from_be_bytes(length) as usize;
            let mut query = vec![0u8; len];
            stream.read_exact(&mut query).unwrap();
            let reply = mock_reply(&query, &[IpAddr::from([10, 0, 0, 7])], false, 0);
            let mut framed = Vec::with_capacity(reply.len() + 2);
            framed.extend((reply.len() as u16).to_be_bytes());
            framed.extend(reply);
            stream.write_all(&framed).unwrap();
        });

        ylong_runtime::block_on(async move {
            let resolver = OwnerAwareResolver::new(uid, gid);
            let query = DualQuery::build(TEST_NAME).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let servers = [server]; // a single server is the LAST server
            let mut ex = Exchange::bind(
                &resolver,
                &servers,
                &query,
                &ResolvConf::default(),
                FamilyMask::Both,
                deadline,
            )
            .await
            .expect("bind exchange socket failed");

            // An all-invalid A answer (0.0.0.0) with the TC bit set.
            let udp_reply = mock_reply(&query.query_a, &[IpAddr::from([0, 0, 0, 0])], true, 0);
            ex.buf[..udp_reply.len()].copy_from_slice(&udp_reply);

            let abandon = ex.handle_reply(udp_reply.len(), server, true).await;
            assert!(!abandon);

            // The TCP retry committed the valid answer.
            let tcp_reply = mock_reply(&query.query_a, &[IpAddr::from([10, 0, 0, 7])], false, 0);
            assert_eq!(ex.ans[1].as_deref(), Some(tcp_reply.as_slice()));
        });
        tcp_thread.join().unwrap();
    }

    /// UT case for `compute_try_sets`: the multiV4 bookkeeping (musl
    /// L281-334) and its death under the MAXNS server cap.
    ///
    /// # Brief
    /// 1. Three v4 servers all non-public satisfy the formula's second branch
    ///    (`nv4 > 2 && nns == non_public`) but the adjustment block resets the
    ///    flag (`nv6 == 0 && nv4 <= 4`) — multiV4 is unreachable while servers
    ///    are capped at MAXNS.
    /// 2. With a v6 server present (beyond the config cap, exercising the live
    ///    math) the first-try set is two v4 + all v6 and the second set the
    ///    remaining v4.
    /// 3. Plain file configs (`non_public` = 0) never set the flag.
    #[test]
    fn ut_compute_try_sets() {
        let v4 = SocketAddr::from(([192, 0, 2, 1], 53));
        let v6 = SocketAddr::from((
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            53,
        ));
        // Second branch satisfied, then reset by the adjustment block.
        let servers = [v4, v4, v4];
        let (nv4, nv6, multi_v4, first, sec) = compute_try_sets(&servers, 3);
        assert_eq!((nv4, nv6), (3, 0));
        assert!(!multi_v4);
        assert_eq!(first, [0, 0, 0]);
        assert_eq!(sec, [0, 0, 0]);

        // Live branch math beyond the config cap: 3 v4 + 1 v6, all
        // non-public.
        let servers = [v4, v4, v4, v6];
        let (nv4, nv6, multi_v4, first, sec) = compute_try_sets(&servers, 4);
        assert_eq!((nv4, nv6), (3, 1));
        assert!(multi_v4);
        assert_eq!(first, [0, 1, 3]); // two v4 + the v6
        assert_eq!(sec, [2, 0, 0]); // the remaining v4

        // File config: the flag never fires.
        let servers = [v4, v4];
        let (nv4, nv6, multi_v4, _, _) = compute_try_sets(&servers, 0);
        assert_eq!((nv4, nv6), (2, 0));
        assert!(!multi_v4);
    }

    /// UT case for the source filter's unspecified-server wildcard (musl
    /// res_msend.c L612/L620): a configured 0.0.0.0/:: accepts any
    /// same-port source, while a concrete address only matches itself —
    /// a foreign source or a foreign port is rejected.
    #[test]
    fn ut_filter_peer_unspecified_wildcard_and_strict() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        let any_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53);
        let any_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 53);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
        let foreign = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 53);
        let other_port = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 54);
        let v6_peer =
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 53);

        // Configured 0.0.0.0 accepts a reply from 127.0.0.1:53 (OHOS musl
        // wildcard), but not from another port.
        assert!(Exchange::peer_matches_server(&[any_v4], &local));
        assert!(!Exchange::peer_matches_server(&[any_v4], &other_port));
        // Configured :: accepts a same-port IPv6 source.
        assert!(Exchange::peer_matches_server(&[any_v6], &v6_peer));
        // A concrete server matches only itself: a foreign source on the
        // same port is rejected (anti-spoofing).
        assert!(Exchange::peer_matches_server(&[local], &local));
        assert!(!Exchange::peer_matches_server(&[local], &foreign));
    }
}
