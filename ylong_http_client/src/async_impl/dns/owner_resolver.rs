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

//! Owner-aware UDP DNS resolver, aligned with OHOS musl `getaddrinfo`.
//!
//! Implements [`Resolver`] by sending DNS queries over sockets created with
//! `UdpSocket::bind_with_owner`, so that DNS traffic is owned by the
//! configured uid/gid and can pass through VPN tun devices. The resolution
//! path mirrors the system resolver one to one:
//!
//! - [`super::hosts`]: `/etc/hosts` before DNS, exact name, with musl's
//!   built-in fallback entries for an unreadable file (`name_from_hosts`).
//! - [`super::config`]: `/etc/resolv.conf` re-read on every resolution and the
//!   search-list candidate expansion (`resolvconf.c`, `name_from_dns_search`).
//! - [`super::exchange`]: both family queries broadcast to every server through
//!   one owner socket under a total budget (`res_msend.c`), with the OHOS musl
//!   rules for NXDOMAIN consensus, SERVFAIL resends, the v4 fast-exit and the
//!   TC-over-TCP retry with rollback.
//! - This file: the candidate loop and the `checkBuf` gate, record collection
//!   through the musl invalid-address classes, the single CNAME chase for bare
//!   names and the result cache (`lookup_name.c`).
//! - [`super::sort`]: the RFC 6724 preference order musl applies.
//!
//! Failure policy: resolution failures are returned as errors and never
//! fall back to the system resolver, so DNS traffic cannot silently bypass
//! the VPN policy. Cache posture — none: no cache tier is consulted and no
//! cache is written (not the system's positive or AAAA-nodata caches, and
//! no local one), so repeated lookups re-query. This resolver has no
//! platform service dependency: server lists come from the caller
//! (`dns_servers`) or the resolv.conf file.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use libc::{gid_t, uid_t};

use super::config::{
    candidates, load_resolv_conf, ResolvConf, DEFAULT_ATTEMPTS, DEFAULT_TIMEOUT, DNS_PORT,
    MAX_NAMESERVERS,
};
use super::error::{
    config_unavailable, fail_to_parse, gate_again, invalid_authority, no_such_name,
    server_no_result,
};
use super::exchange;
use super::exchange::FamilyMask;
use super::hosts::lookup_hosts;
use super::query::DualQuery;
use super::sort::sort_addrs_like_musl;
use super::wire::{parse_response, ParseOutcome, MAX_ADDRS, RCODE_NOERROR, RCODE_NXDOMAIN};
use crate::async_impl::dns::resolver::ResolvedAddrs;
use crate::async_impl::{Addrs, Resolver, SocketFuture, StdError};

/// musl `MAX_QUERY_SIZE` (lookup_name.c L141): CNAME chase budget. The
/// OHOS musl build breaks on `queryName == ctx.canon` pointer equality, so at
/// most one chase round ever runs; the cap is kept for parity.
const MAX_QUERY_SIZE: usize = 5;

/// Outcome of resolving one candidate name, mirroring musl `name_from_dns`
/// return-value semantics one to one (`lookup_name.c` L504-517:
/// `int cnt = name_from_dns(...); if (cnt) return cnt;`).
enum CandidateOutcome {
    /// `cnt > 0`: address records were found for this candidate.
    Found(Vec<SocketAddr>),
    /// `cnt == 0`: the `checkBuf` gate short-circuited with
    /// `ret = checkBuf[0] == 0` — an authoritative NXDOMAIN — or the query
    /// name failed to encode (musl `__res_mkquery` → `return 0`,
    /// `lookup_name.c` L349-352). The candidate name does not exist and the
    /// search proceeds to the next candidate.
    CandidateDead,
    /// `cnt < 0`: any negative reason from `name_from_dns` — the
    /// `FAIL_TO_PARSE_DNS` path (answers parsed to no records), the
    /// all-zero-address `SERVER_NO_RESULT`, the `EAI_AGAIN` gate outcomes
    /// (which include a total transport failure: with every server silent,
    /// res_msend returns no answers and the gate maps that to EAI_AGAIN,
    /// closing the A1-aligned deviation ④) — aborts the whole search, with
    /// no further candidates and no bare-name fallback.
    SearchAbort(io::Error),
}

/// Result of collecting the accepted answers of one exchange, mirroring
/// musl's record loop and its invalid-address classes (lookup_name.c
/// L391-449).
enum CollectOutcome {
    /// Valid records were collected, sorted and port-filled.
    Found(Vec<SocketAddr>),
    /// Only all-zero (0.0.0.0) v4 records were seen: musl returns
    /// DNS_FAIL_REASON_SERVER_NO_RESULT and the search aborts.
    AllZero,
    /// No records at all, with the CNAME canon (if any) for the chase.
    Empty(Option<String>),
}

/// Verdict of one accepted answer, mirroring musl `IsAnswerValid`
/// (`lookup_name.c` L256-265): rcode 0 is VALID (even without records);
/// rcode 3 returns 0; SERVFAIL is EAI_AGAIN and any other rcode is
/// EAI_FAIL. A missing answer is `IsAnswerValid(abuf, 0)`: alen < 4 →
/// EAI_AGAIN. EAI_AGAIN and EAI_FAIL share one variant because both map to
/// a negative gate outcome.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AnswerVerdict {
    /// NOERROR answer, with or without records.
    Valid,
    /// Authoritative negative answer (rcode 3): the gate returns 0.
    NxDomain,
    /// No answer, SERVFAIL or another rcode: the gate returns a negative.
    NoAnswer,
}

/// Owner-aware DNS resolver used by `HttpConnector` when `sockets_owner` is
/// configured. Implements the existing [`Resolver`] trait.
///
/// Cache posture — NONE: no cache tier is consulted and no cache is
/// written (not the system's positive or AAAA-nodata caches, and no local
/// one), so repeated lookups re-query; that is the deliberate price of
/// never touching system-shared state. Resolution sources are strictly
/// `/etc/hosts`, then DNS queries against the configured servers.
pub(crate) struct OwnerAwareResolver {
    pub(crate) uid: uid_t,
    pub(crate) gid: gid_t,
    /// DNS server override from the client builder (`dns_servers`): when
    /// set, resolution targets these servers directly and the system
    /// `/etc/resolv.conf` is not consulted. Search-list expansion is
    /// disabled in this mode (empty search list), so the resolved names
    /// are treated as absolute. Stored unparsed; parsing (skipping invalid
    /// entries, truncating to [`MAX_NAMESERVERS`]) happens when the
    /// resolver configuration is assembled, after the port override is
    /// known.
    pub(crate) dns_servers: Option<Vec<String>>,
    /// Port for the parsed override servers (`ClientBuilder::dns_port`);
    /// defaults to the standard DNS port.
    pub(crate) dns_port: u16,
    /// Total UDP budget override of the override mode
    /// (`ClientBuilder::dns_timeout`); defaults to the musl value.
    pub(crate) dns_timeout: Option<Duration>,
    /// Round count override of the override mode
    /// (`ClientBuilder::dns_attempts`); defaults to the musl value.
    pub(crate) dns_attempts: Option<u32>,
}

/// Parses the client-builder DNS server override into socket addresses,
/// mirroring the musl nameserver ingestion contract: invalid entries are
/// skipped (an unparsable entry never occupies a slot) and the result is
/// truncated to [`MAX_NAMESERVERS`] keeping the first valid entries in
/// caller order — the same bound musl enforces when storing nameservers
/// (`resolvconf.c` L157/L217: `nns >= MAXNS`). Keeping the bound here is
/// what keeps the exchange's round bookkeeping (`compute_try_sets`) in its
/// defined domain; `Exchange::bind` asserts it as a contract. When nothing
/// valid remains the override degrades to an empty server list and
/// resolution fails fast instead of silently falling back to the system
/// configuration.
fn parse_dns_servers(servers: &[String], port: u16) -> Vec<SocketAddr> {
    let mut parsed = Vec::new();
    for server in servers {
        if parsed.len() >= MAX_NAMESERVERS {
            break;
        }
        if let Ok(ip) = server.parse::<IpAddr>() {
            parsed.push(SocketAddr::new(ip, port));
        }
    }
    parsed
}

impl OwnerAwareResolver {
    pub(crate) fn new(uid: uid_t, gid: gid_t) -> Self {
        OwnerAwareResolver {
            uid,
            gid,
            dns_servers: None,
            dns_port: DNS_PORT,
            dns_timeout: None,
            dns_attempts: None,
        }
    }

    /// Sets the DNS server override (`ClientBuilder::dns_servers`). The
    /// list is stored unparsed and parsed when the resolver configuration
    /// is assembled: invalid entries are skipped and the list is truncated
    /// to the musl MAXNS bound (see `parse_dns_servers`); when nothing
    /// valid remains the override degrades to an empty server list and
    /// resolution fails fast instead of silently falling back to the
    /// system configuration.
    pub(crate) fn with_dns_servers(mut self, servers: Option<Vec<String>>) -> Self {
        self.dns_servers = servers;
        self
    }

    /// Sets the port for the parsed DNS server override
    /// (`ClientBuilder::dns_port`). Only meaningful together with
    /// `dns_servers`; defaults to the standard DNS port.
    pub(crate) fn with_dns_port(mut self, port: u16) -> Self {
        self.dns_port = port;
        self
    }

    /// Overrides the total UDP budget of the override mode
    /// (`ClientBuilder::dns_timeout`); defaults to the musl value.
    pub(crate) fn with_dns_timeout(mut self, timeout: Duration) -> Self {
        self.dns_timeout = Some(timeout);
        self
    }

    /// Overrides the round count of the override mode
    /// (`ClientBuilder::dns_attempts`); defaults to the musl value.
    pub(crate) fn with_dns_attempts(mut self, attempts: u32) -> Self {
        self.dns_attempts = Some(attempts);
        self
    }

    /// Full resolution path, matching musl `getaddrinfo` (L11-23) order:
    /// `/etc/hosts` first, then the DNS stage. Never falls back to the
    /// system resolver on failure; errors are propagated to the caller.
    async fn resolve_impl(&self, authority: &str) -> io::Result<Vec<SocketAddr>> {
        let (host, port) = parse_authority(authority)?;
        // musl getaddrinfo.c L15: musl consults the OHOS service-side
        // result cache here, read-only. This resolver has no service
        // dependency and no cache tier of any kind — it never reads or
        // writes one — so resolution always proceeds to hosts and DNS.

        // Files before dns, exact name, matching getaddrinfo order. Small
        // file reads here are page-cache hits (microseconds), the same cost
        // musl pays inside every getaddrinfo call.
        let hosts_addrs = lookup_hosts(&host, port, Some((self.uid, self.gid)));
        if !hosts_addrs.is_empty() {
            return Ok(hosts_addrs);
        }

        // The DNS stage resolves against the configured servers: with a
        // `dns_servers` override the servers come from the client builder
        // (the caller-supplied server list) and
        // the system configuration is not consulted (search-list expansion
        // is disabled, names are absolute); without one it reads the
        // resolv.conf file itself (`name_from_dns_search` →
        // `load_resolv_conf`; absent on OHOS → the lookup fails);
        // an unexpected read error fails the resolution
        // (DNS_FAIL_REASON_GET_RESOLV_CONF_FAILED).
        let conf = match &self.dns_servers {
            Some(servers) => {
                // Override mode: the caller's policy values (port, budget,
                // rounds) apply over the musl defaults; parsing truncates
                // the list to the musl MAXNS bound (see `parse_dns_servers`).
                // When nothing valid remains the override has no usable
                // server: fail fast instead of starting an exchange that
                // can never send — musl fails the lookup the same way when
                // the netsys configuration cannot be read (resolvconf.c
                // L134-139 → EAI_NONAME) and never falls back to a default
                // server (DNS_FAIL_REASON_GET_RESOLV_CONF_FAILED).
                let parsed = parse_dns_servers(servers, self.dns_port);
                if parsed.is_empty() {
                    return Err(config_unavailable());
                }
                ResolvConf {
                    servers: parsed,
                    timeout: self.dns_timeout.unwrap_or(DEFAULT_TIMEOUT),
                    attempts: self.dns_attempts.unwrap_or(DEFAULT_ATTEMPTS),
                    ..Default::default()
                }
            }
            None => load_resolv_conf()?,
        };
        self.resolve_host(authority, &host, port, &conf).await
    }

    /// Candidate loop over one already-parsed host and port under the
    /// given configuration. Mirrors musl `name_from_dns_search`
    /// (lookup_name.c L466-545): `cnt == 0` moves to the next candidate,
    /// any negative reason aborts the whole search. `authority` is the
    /// original "host:port" string, kept for the final error message.
    async fn resolve_host(
        &self,
        authority: &str,
        host: &str,
        port: u16,
        conf: &ResolvConf,
    ) -> io::Result<Vec<SocketAddr>> {
        // Family selection: musl L308-330 decides the mask once per lookup
        // from the musl family judges. This resolver has no platform
        // dependency, so both families are always queried — the same
        // outcome as musl with absent or erroring hooks (-1 = enabled).
        let mask = FamilyMask::Both;

        for (name, chase_allowed) in candidates(host, conf)? {
            match self
                .resolve_name(&name, chase_allowed, port, conf, mask)
                .await
            {
                CandidateOutcome::Found(addrs) => {
                    // Zero-write posture: nothing is recorded anywhere —
                    // musl would hand the result to the service caches here
                    // (getaddrinfo.c L105-161); this resolver has no cache
                    // tier at all.
                    return Ok(addrs);
                }
                // musl `if (cnt) return cnt` with cnt == 0: NXDOMAIN, the
                // candidate name does not exist — try the next candidate.
                CandidateOutcome::CandidateDead => {
                    continue;
                }
                // musl `if (cnt) return cnt` with cnt < 0: any negative
                // reason aborts the whole search — no further candidates,
                // no bare-name fallback. With the A1 alignment this also
                // covers a total transport failure: with every server
                // silent, res_msend returns no answers and the `checkBuf`
                // gate maps that to EAI_AGAIN.
                CandidateOutcome::SearchAbort(err) => {
                    return Err(err);
                }
            }
        }
        Err(no_such_name(authority))
    }

    /// Resolves one candidate name exactly like musl `name_from_dns`
    /// (lookup_name.c L340-452): build both family queries (`__res_mkquery`
    /// failure → `return 0` → candidate dead), exchange with all servers
    /// through the `res_msend` port under the family mask decided by the
    /// caller, apply the `checkBuf` gate, collect the records through the
    /// musl invalid-address classes, and — for bare names only — chase
    /// the CNAME canon once (search candidates break on
    /// `queryName == ctx.canon` before any chase can start).
    async fn resolve_name(
        &self,
        name: &str,
        chase_allowed: bool,
        port: u16,
        conf: &ResolvConf,
        mask: FamilyMask,
    ) -> CandidateOutcome {
        let mut query_name = name.to_string();
        // musl chases the CNAME canon while re-querying the same buffer; the
        // second round always breaks on the pointer equality (chase once).
        let mut chases = 0usize;
        loop {
            let query = match DualQuery::build(&query_name) {
                Ok(query) => query,
                // musl `__res_mkquery` failure → `return 0` (L349-352).
                Err(_) => return CandidateOutcome::CandidateDead,
            };
            let (resp_aaaa, resp_a) = exchange::run(self, &conf.servers, &query, conf, mask).await;
            if let Some(outcome) = gate_outcome(&resp_aaaa, &resp_a, mask) {
                return outcome;
            }
            match collect_answers(&resp_a, &resp_aaaa, port, Some((self.uid, self.gid))) {
                CollectOutcome::Found(addrs) => {
                    return CandidateOutcome::Found(addrs);
                }
                CollectOutcome::AllZero => {
                    // musl L445-449: only all-zero v4 records were seen →
                    // DNS_FAIL_REASON_SERVER_NO_RESULT, a negative reason.
                    return CandidateOutcome::SearchAbort(server_no_result(
                        "DNS answer holds no usable address",
                    ));
                }
                CollectOutcome::Empty(canon) => {
                    // ctx.cnt == 0 (L436-439 + L343): search candidates
                    // break on `queryName == ctx.canon` immediately; a bare
                    // name chases the CNAME canon once — the second round
                    // always breaks on the same pointer equality. No canon
                    // (or an empty one) ends the while-loop with
                    // DNS_FAIL_REASON_FAIL_TO_PARSE_DNS (-1104). Every
                    // path here aborts the search.
                    if !chase_allowed || chases >= MAX_QUERY_SIZE {
                        break;
                    }
                    match canon {
                        Some(target) if !target.is_empty() => {
                            // The OHOS musl build breaks on the canon pointer
                            // equality after one chase; the counter mirrors
                            // the musl `MAX_QUERY_SIZE` budget.
                            chases += 1;
                            query_name = target;
                        }
                        _ => break,
                    }
                }
            }
        }
        CandidateOutcome::SearchAbort(fail_to_parse("failed to parse DNS answer"))
    }
}

impl Resolver for OwnerAwareResolver {
    fn resolve(&self, authority: &str) -> SocketFuture<'_> {
        let authority = authority.to_string();
        Box::pin(async move {
            self.resolve_impl(authority.as_str())
                .await
                .map(|addrs| Box::new(ResolvedAddrs::new(addrs.into_iter())) as Addrs)
                .map_err(|err| Box::new(err) as StdError)
        })
    }
}

/// Splits an "authority" into host and port. Pure IP literals never reach the
/// resolver (the connector resolves them directly), but bracketed IPv6 is
/// accepted for robustness. A missing or invalid port is an error, matching
/// the `ToSocketAddrs` behavior of the default resolver.
fn parse_authority(authority: &str) -> io::Result<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']').ok_or_else(|| invalid_authority(authority))?;
        let host = &rest[..close];
        let port = rest[close + 1..]
            .strip_prefix(':')
            .ok_or_else(|| invalid_authority(authority))?;
        let port: u16 = port.parse().map_err(|_| invalid_authority(authority))?;
        return Ok((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            if host.is_empty() {
                return Err(invalid_authority(authority));
            }
            let port: u16 = port.parse().map_err(|_| invalid_authority(authority))?;
            Ok((host.to_string(), port))
        }
        None => Err(invalid_authority(authority)),
    }
}

/// Applies the `checkBuf` gate (musl lookup_name.c L368-389) over the
/// accepted answers. Dual (`queryNum = 2`): the gate fires when the first
/// (AAAA) answer is not VALID and the second is not VALID either; its
/// value decides — 0 (NXDOMAIN) kills the candidate, a negative reason (no
/// answer at all, SERVFAIL, another rcode) aborts the search. Single
/// family (`queryNum = 1`): the second condition short-circuits on
/// `nq < MAX_ANSWER_TYPE` (L373) and the one answer's verdict decides
/// alone. `None` = at least one queried family is VALID and collection
/// proceeds.
fn gate_outcome(
    resp_aaaa: &Option<Vec<u8>>,
    resp_a: &Option<Vec<u8>>,
    mask: FamilyMask,
) -> Option<CandidateOutcome> {
    if mask == FamilyMask::V4Only {
        return gate_single_family(resp_a);
    }
    if mask == FamilyMask::V6Only {
        return gate_single_family(resp_aaaa);
    }
    let verdict_aaaa = answer_verdict(resp_aaaa.as_deref());
    let verdict_a = answer_verdict(resp_a.as_deref());
    if verdict_aaaa == AnswerVerdict::Valid || verdict_a == AnswerVerdict::Valid {
        return None;
    }
    match verdict_aaaa {
        AnswerVerdict::NxDomain => Some(CandidateOutcome::CandidateDead),
        // VALID cannot happen: the early return above handled it.
        AnswerVerdict::Valid => None,
        AnswerVerdict::NoAnswer => Some(CandidateOutcome::SearchAbort(gate_again(
            "no usable DNS answer",
        ))),
    }
}

/// The `queryNum = 1` gate: the single answer's verdict decides
/// (lookup_name.c L372-378 with `nq = 1`).
fn gate_single_family(resp: &Option<Vec<u8>>) -> Option<CandidateOutcome> {
    match answer_verdict(resp.as_deref()) {
        AnswerVerdict::Valid => None,
        AnswerVerdict::NxDomain => Some(CandidateOutcome::CandidateDead),
        AnswerVerdict::NoAnswer => Some(CandidateOutcome::SearchAbort(gate_again(
            "no usable DNS answer",
        ))),
    }
}

/// Collects the accepted answers exactly like musl (lookup_name.c L391-449):
/// the A answer is parsed first, then AAAA (i = nq-1..0, which fixes the
/// pre-sort record order); valid records stay, 127.0.0.0/8 (LOCAL) is set
/// aside, 0.0.0.0 (ALLZERO) is dropped; the set-aside loopback addresses
/// come back only when no valid v4 address was found at all. `owner` is
/// forwarded to the RFC 6724 source probe so the ranking sees the same
/// source addresses as the owner-tagged resolver sockets.
fn collect_answers(
    resp_a: &Option<Vec<u8>>,
    resp_aaaa: &Option<Vec<u8>>,
    port: u16,
    owner: Option<(u32, u32)>,
) -> CollectOutcome {
    let mut ips: Vec<IpAddr> = Vec::new();
    let mut local_v4: Vec<IpAddr> = Vec::new();
    let mut invalid_v4 = 0usize;
    let mut canon = None;
    for resp in [resp_a, resp_aaaa] {
        let parsed = match resp {
            Some(bytes) => match parse_response(bytes) {
                ParseOutcome::Records(parsed) => parsed,
                // An accepted NXDOMAIN contributes no records
                // (`__dns_parse` returns early on rcodes != 0).
                ParseOutcome::NxDomain | ParseOutcome::Unusable => continue,
            },
            None => continue,
        };
        if parsed.canon.is_some() {
            canon = parsed.canon;
        }
        for (ip, _ttl) in parsed.records {
            // musl `dns_parse_callback` L159: one ctx carries the shared
            // counter across BOTH family parses, so 48 (`MAXADDRS`) is the
            // TOTAL cap, not a per-family one.
            if ips.len() + local_v4.len() >= MAX_ADDRS {
                break;
            }
            match ip {
                IpAddr::V4(v4) if v4.is_loopback() => local_v4.push(ip),
                IpAddr::V4(v4) if v4.is_unspecified() => invalid_v4 += 1,
                _ => ips.push(ip),
            }
        }
    }
    if !ips.iter().any(|ip| ip.is_ipv4()) && !local_v4.is_empty() {
        ips.extend(local_v4);
    }
    if ips.is_empty() {
        return if invalid_v4 > 0 {
            CollectOutcome::AllZero
        } else {
            CollectOutcome::Empty(canon)
        };
    }
    // musl sorts the collected addresses before returning (A2: RFC 6724
    // subset, lookup_name.c L665-737); the address set is unchanged
    // (AC-1.7).
    sort_addrs_like_musl(&mut ips, owner);
    CollectOutcome::Found(
        ips.into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect(),
    )
}

/// Verdict over one ACCEPTED answer, mirroring musl `IsAnswerValid`
/// (lookup_name.c L256-265): rcode 0 is VALID even without records
/// (NODATA); rcode 3 returns 0 (the gate kills the candidate); SERVFAIL is
/// EAI_AGAIN and any other rcode is EAI_FAIL. A missing answer is
/// `IsAnswerValid(abuf, 0)`: alen < 4 → EAI_AGAIN. EAI_AGAIN and EAI_FAIL
/// share one variant because both map to a negative gate outcome (search
/// abort).
fn answer_verdict(msg: Option<&[u8]>) -> AnswerVerdict {
    match msg {
        None => AnswerVerdict::NoAnswer,
        Some(bytes) => {
            if bytes.len() < 4 {
                return AnswerVerdict::NoAnswer;
            }
            match (bytes[3] & 0x0F) as u16 {
                RCODE_NXDOMAIN => AnswerVerdict::NxDomain,
                RCODE_NOERROR => AnswerVerdict::Valid,
                _ => AnswerVerdict::NoAnswer,
            }
        }
    }
}

#[cfg(test)]
mod ut_test {
    use std::io::{Read, Write};
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::async_impl::dns::wire::{RCODE_SERVFAIL, TYPE_A, TYPE_AAAA};
    use crate::async_impl::dns::test_util::{
        mock_reply, mock_reply_cname, mock_reply_echo, qname_of, test_response, TEST_NAME,
    };

    /// UT case for `with_dns_servers` and `parse_dns_servers`: valid
    /// entries are parsed to `server:port` socket addresses, invalid
    /// entries never occupy a slot, more valid entries than the musl MAXNS
    /// bound keep only the first three — the truncation that keeps the
    /// exchange's round bookkeeping in its defined domain
    /// (`resolvconf.c` L157/L217) — and a `None` override keeps the field
    /// unset. The builder stores the raw list.
    #[test]
    fn ut_with_dns_servers_parse() {
        // Valid and invalid entries mixed: invalid entries never occupy a
        // slot, every parsed entry carries the requested port.
        let servers = parse_dns_servers(
            &[
                "192.168.1.1".to_string(),
                "not-an-ip".to_string(),
                "fd00::1".to_string(),
            ],
            DNS_PORT,
        );
        assert_eq!(
            servers,
            vec![
                SocketAddr::from(([192, 168, 1, 1], DNS_PORT)),
                SocketAddr::from(([0xfd00, 0, 0, 0, 0, 0, 0, 1], DNS_PORT)),
            ]
        );

        // Cap contract: five valid v4 entries truncate to the first three
        // (musl MAXNS), preserving caller order. Feeding more than three
        // entries is exactly the input that used to activate the dead
        // branch in `compute_try_sets` (the iv4 index-out-of-bounds panic),
        // so the truncation is the regression guard for that bug.
        let servers = parse_dns_servers(
            &[
                "114.114.114.114".to_string(),
                "114.114.115.115".to_string(),
                "223.5.5.5".to_string(),
                "223.6.6.6".to_string(),
                "180.76.76.76".to_string(),
            ],
            DNS_PORT,
        );
        assert_eq!(servers.len(), MAX_NAMESERVERS);
        assert_eq!(
            servers,
            vec![
                SocketAddr::from(([114, 114, 114, 114], DNS_PORT)),
                SocketAddr::from(([114, 114, 115, 115], DNS_PORT)),
                SocketAddr::from(([223, 5, 5, 5], DNS_PORT)),
            ]
        );

        // The builder stores the raw list unparsed.
        let resolver = OwnerAwareResolver::new(0, 0).with_dns_servers(Some(vec![
            "192.168.1.1".to_string(),
            "not-an-ip".to_string(),
        ]));
        assert_eq!(
            resolver.dns_servers.unwrap(),
            vec!["192.168.1.1".to_string(), "not-an-ip".to_string()]
        );

        let resolver = OwnerAwareResolver::new(0, 0).with_dns_servers(None);
        assert!(resolver.dns_servers.is_none());

        // All-invalid input degrades to an empty list: resolution fails fast
        // instead of silently falling back to the system configuration.
        let servers = parse_dns_servers(&["bad".to_string()], DNS_PORT);
        assert!(servers.is_empty());
    }

    /// UT case for the override-mode policy setters: values are stored as
    /// given, the defaults keep the overrides unset.
    #[test]
    fn ut_dns_policy_overrides() {
        let resolver = OwnerAwareResolver::new(0, 0)
            .with_dns_port(5353)
            .with_dns_timeout(Duration::from_secs(4))
            .with_dns_attempts(3);
        assert_eq!(resolver.dns_port, 5353);
        assert_eq!(resolver.dns_timeout, Some(Duration::from_secs(4)));
        assert_eq!(resolver.dns_attempts, Some(3));

        let resolver = OwnerAwareResolver::new(0, 0);
        assert_eq!(resolver.dns_port, DNS_PORT);
        assert!(resolver.dns_timeout.is_none());
        assert!(resolver.dns_attempts.is_none());
    }

    /// UT case for the fail-fast override (musl
    /// DNS_FAIL_REASON_GET_RESOLV_CONF_FAILED): a `dns_servers` override
    /// whose entries ALL fail to parse leaves no usable server — the
    /// resolution must fail immediately instead of burning the whole
    /// budget on an exchange that cannot send. musl fails the lookup the
    /// same way on a netsys configuration failure (resolvconf.c L134-139
    /// → EAI_NONAME) and never falls back to a default server.
    ///
    /// # Brief
    /// 1. Builds a resolver with an all-invalid `dns_servers` override.
    /// 2. Resolves and verifies the error carries the -1103 reason code.
    /// 3. Verifies the call returns long before the 5-second budget.
    #[test]
    fn ut_resolve_impl_empty_override_fails_fast() {
        let resolver = OwnerAwareResolver::new(0, 0).with_dns_servers(Some(vec![
            "not-an-ip".to_string(),
            "still-bad".to_string(),
        ]));
        let start = std::time::Instant::now();
        let err =
            ylong_runtime::block_on(resolver.resolve_impl("owner.vpn.test:80")).unwrap_err();
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(500),
            "override with no usable server must fail fast, took {elapsed:?}"
        );
        let message = err.to_string();
        assert!(
            message.contains("-1103") && message.contains("GET_RESOLV_CONF_FAILED"),
            "unexpected error: {message}"
        );
    }

    /// UT case for `resolve_name` classification: a candidate name that
    /// cannot be encoded (over the 253-byte limit) maps to musl's
    /// `__res_mkquery` failure → `return 0` (`lookup_name.c` L349-352) —
    /// the candidate dies and the search moves on. Fails before any
    /// server I/O.
    #[test]
    fn ut_resolve_name_long_name_dead() {
        let resolver = OwnerAwareResolver::new(0, 0);
        let long_name = "a".repeat(300);
        let result = ylong_runtime::block_on(resolver.resolve_name(
            &long_name,
            true,
            80,
            &test_conf(SocketAddr::from(([127, 0, 0, 1], 1))),
            FamilyMask::Both,
        ));
        assert!(matches!(result, CandidateOutcome::CandidateDead));
    }

    /// UT case for `parse_authority`.
    #[test]
    fn ut_parse_authority() {
        assert_eq!(
            parse_authority("example.com:80").unwrap(),
            ("example.com".to_string(), 80)
        );
        assert_eq!(
            parse_authority("[2001:db8::1]:443").unwrap(),
            ("2001:db8::1".to_string(), 443)
        );
        assert!(parse_authority("example.com").is_err());
        assert!(parse_authority("example.com:port").is_err());
        assert!(parse_authority(":80").is_err());
        assert!(parse_authority("[2001:db8::1]").is_err());
    }

    /// UT case for `collect_answers` record collection: the A answer is
    /// parsed first, then AAAA (musl's record order), both port-filled.
    /// (The per-record TTL is consumed by the `ylong_http` wire codec's
    /// own tests; this layer only collects addresses.)
    #[test]
    fn ut_collect_records() {
        let v6 = IpAddr::from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4]);
        let resp_a = test_response(
            0x01,
            "example.com",
            TYPE_A,
            &[IpAddr::from([10, 0, 0, 4])],
            false,
            0,
        );
        let resp_aaaa = test_response(0x02, "example.com", TYPE_AAAA, &[v6], false, 0);
        match collect_answers(&Some(resp_a), &Some(resp_aaaa), 80, None) {
            CollectOutcome::Found(addrs) => {
                assert_eq!(
                    addrs,
                    vec![
                        SocketAddr::from(([10, 0, 0, 4], 80)),
                        SocketAddr::from((v6, 80))
                    ]
                );
            }
            _ => panic!("expected records"),
        }
        // A single A answer alone is collected the same way.
        let msg = test_response(
            0x01,
            "example.com",
            TYPE_A,
            &[IpAddr::from([10, 0, 0, 9])],
            false,
            0,
        );
        match collect_answers(&Some(msg), &None, 80, None) {
            CollectOutcome::Found(addrs) => {
                assert_eq!(addrs, vec![SocketAddr::from(([10, 0, 0, 9], 80))]);
            }
            _ => panic!("expected records"),
        }
    }

    // Socket-level behavior tests: they drive the [`resolve_via`] helper
    // (over `resolve_host`) and `resolve_name` against mock DNS servers,
    // asserting the musl-parity flow end to end. They stay in the inline
    // test suite because they exercise private items; the public-API
    // integration tests live in `tests/sdv_async_owner_dns_resolver.rs`.

    fn current_owner() -> (uid_t, gid_t) {
        // fchown to the process's own uid/gid is always permitted.
        unsafe { (libc::getuid(), libc::getgid()) }
    }

    /// Test helper: parses the authority and drives
    /// [`OwnerAwareResolver::resolve_host`] — the pre-refactor
    /// `resolve_via` shape, kept so the socket-level tests read like the
    /// resolution flow.
    async fn resolve_via(
        resolver: &OwnerAwareResolver,
        authority: &str,
        conf: &ResolvConf,
    ) -> io::Result<Vec<SocketAddr>> {
        let (host, port) = parse_authority(authority)?;
        resolver.resolve_host(authority, &host, port, conf).await
    }

    /// Whether this environment delivers IP-fragmented UDP datagrams
    /// (>1472 bytes needs fragmentation on a 1500-MTU path; some CI
    /// sandboxes drop fragments silently). Probed once per process so the
    /// oversized-datagram cases skip themselves where undeliverable.
    fn delivers_fragmented_udp() -> bool {
        use std::sync::OnceLock;
        static CACHE: OnceLock<bool> = OnceLock::new();
        *CACHE.get_or_init(|| {
            let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let tx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let addr = rx.local_addr().unwrap();
            if tx.send_to(&vec![0u8; 5000], addr).is_err() {
                return false;
            }
            rx.set_read_timeout(Some(Duration::from_millis(300)))
                .is_ok()
                && {
                    let mut buf = [0u8; 4096];
                    rx.recv_from(&mut buf).is_ok()
                }
        })
    }

    fn test_conf(server: SocketAddr) -> ResolvConf {
        ResolvConf {
            servers: vec![server],
            timeout: Duration::from_millis(500),
            attempts: 1,
            ..Default::default()
        }
    }

    /// Both families answer: the exchange completes with one address per
    /// family through the single owner socket (spec AC for basic UDP).
    #[test]
    fn ut_owner_resolver_udp_basic() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (len, src) = mock.recv_from(&mut buf).unwrap();
                let addrs = if buf[len - 4] == 0 && buf[len - 3] == TYPE_A as u8 {
                    vec![IpAddr::from([10, 0, 0, 1])]
                } else {
                    vec![IpAddr::from([
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ])]
                };
                mock.send_to(&mock_reply(&buf[..len], &addrs, false, 0), src)
                    .unwrap();
            }
        });

        let resolver = OwnerAwareResolver::new(uid, gid);
        let authority = format!("{}:80", TEST_NAME);
        let addrs =
            ylong_runtime::block_on(resolve_via(&resolver, authority.as_str(), &test_conf(server)))
                .unwrap();
        thread.join().unwrap();
        assert_eq!(addrs.len(), 2);
        assert!(addrs.iter().any(|addr| addr.is_ipv4()));
        assert!(addrs.iter().any(|addr| addr.is_ipv6()));
        assert!(addrs.iter().all(|addr| addr.port() == 80));
    }

    /// A SERVFAIL answer triggers one immediate resend of the same query
    /// to the replying server inside the window (musl `res_msend`
    /// `servfail_retry` semantics, L780-800), and the retry answer is
    /// accepted.
    #[test]
    fn ut_owner_resolver_servfail_retry() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let mut first_a = true;
            // AAAA + A(SERVFAIL) + A(retry) = 3 received queries.
            for _ in 0..3 {
                let (len, src) = mock.recv_from(&mut buf).unwrap();
                let is_a = buf[len - 4] == 0 && buf[len - 3] == TYPE_A as u8;
                let rcode = if is_a && first_a {
                    first_a = false;
                    RCODE_SERVFAIL
                } else {
                    0
                };
                let addrs = if is_a {
                    vec![IpAddr::from([10, 0, 0, 9])]
                } else {
                    vec![IpAddr::from([
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9,
                    ])]
                };
                mock.send_to(&mock_reply(&buf[..len], &addrs, false, rcode), src)
                    .unwrap();
            }
        });

        let resolver = OwnerAwareResolver::new(uid, gid);
        let authority = format!("{}:80", TEST_NAME);
        let addrs =
            ylong_runtime::block_on(resolve_via(&resolver, authority.as_str(), &test_conf(server)))
                .unwrap();
        thread.join().unwrap();
        assert_eq!(addrs.len(), 2);
        assert!(addrs.iter().all(|addr| addr.port() == 80));
    }

    /// TC=1 on UDP must be retried over TCP with the owner set, ending with
    /// the full answer (spec AC for truncation handling).
    #[test]
    fn ut_owner_resolver_tc_over_tcp() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let listener = std::net::TcpListener::bind(server).unwrap();
        let udp_thread = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (len, src) = mock.recv_from(&mut buf).unwrap();
                mock.send_to(&mock_reply(&buf[..len], &[], true, 0), src)
                    .unwrap();
            }
        });
        let tcp_thread = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut length = [0u8; 2];
                stream.read_exact(&mut length).unwrap();
                let len = u16::from_be_bytes(length) as usize;
                let mut query = vec![0u8; len];
                stream.read_exact(&mut query).unwrap();
                let addrs = if query[len - 3] == TYPE_A as u8 {
                    vec![IpAddr::from([10, 0, 0, 7])]
                } else {
                    vec![IpAddr::from([
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
                    ])]
                };
                let reply = mock_reply(&query, &addrs, false, 0);
                let mut framed = Vec::with_capacity(reply.len() + 2);
                framed.extend((reply.len() as u16).to_be_bytes());
                framed.extend(reply);
                stream.write_all(&framed).unwrap();
            }
        });

        let resolver = OwnerAwareResolver::new(uid, gid);
        let authority = format!("{}:443", TEST_NAME);
        let mut conf = test_conf(server);
        conf.timeout = Duration::from_secs(2);
        let addrs =
            ylong_runtime::block_on(resolve_via(&resolver, authority.as_str(), &conf)).unwrap();
        udp_thread.join().unwrap();
        tcp_thread.join().unwrap();
        assert_eq!(addrs.len(), 2);
        assert!(addrs
            .iter()
            .all(|addr| addr.ip().to_string().ends_with('7')));
    }

    /// The UDP reply exceeds the 4096-byte receive buffer with the TC bit
    /// clear: only the kernel-side `recvmsg` `MSG_TRUNC` signal can detect
    /// the truncation (musl res_msend.c L739 ORs it with TC). The resolver
    /// must back up the partial UDP answer, retry over TCP, and the
    /// committed address comes from the TCP reply, not the partial one.
    ///
    /// The scenario needs an unfragmented-size-exceeding datagram
    /// (>4096 bytes, hence IP-fragmented). Environments whose network
    /// sandbox drops IP fragments (some CI containers) cannot deliver it;
    /// such environments are probed and the case is skipped there — real
    /// devices and standard CI run it fully.
    #[test]
    fn ut_owner_resolver_msg_trunc_over_tcp() {
        if !delivers_fragmented_udp() {
            eprintln!(
                "SKIP sdv_owner_resolver_msg_trunc_over_tcp: this environment drops \
                 IP-fragmented UDP datagrams, the >4096-byte scenario cannot be exercised"
            );
            return;
        }
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let listener = std::net::TcpListener::bind(server).unwrap();
        let udp_thread = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (len, src) = mock.recv_from(&mut buf).unwrap();
                // 300 records make the datagram ≈4800 bytes, well beyond
                // the 4096-byte receive buffer, with TC unset.
                let addrs: Vec<IpAddr> = (0..300).map(|_| IpAddr::from([10, 0, 0, 9])).collect();
                mock.send_to(&mock_reply(&buf[..len], &addrs, false, 0), src)
                    .unwrap();
            }
        });
        let tcp_thread = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut length = [0u8; 2];
                stream.read_exact(&mut length).unwrap();
                let len = u16::from_be_bytes(length) as usize;
                let mut query = vec![0u8; len];
                stream.read_exact(&mut query).unwrap();
                let addrs = if query[len - 3] == TYPE_A as u8 {
                    vec![IpAddr::from([10, 0, 0, 7])]
                } else {
                    vec![IpAddr::from([
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
                    ])]
                };
                let reply = mock_reply(&query, &addrs, false, 0);
                let mut framed = Vec::with_capacity(reply.len() + 2);
                framed.extend((reply.len() as u16).to_be_bytes());
                framed.extend(reply);
                stream.write_all(&framed).unwrap();
            }
        });

        let resolver = OwnerAwareResolver::new(uid, gid);
        let authority = format!("{}:443", TEST_NAME);
        let mut conf = test_conf(server);
        conf.timeout = Duration::from_secs(2);
        let addrs =
            ylong_runtime::block_on(resolve_via(&resolver, authority.as_str(), &conf)).unwrap();
        udp_thread.join().unwrap();
        tcp_thread.join().unwrap();
        // Every address comes from the TCP reply (10.0.0.7 / ...7); none
        // from the truncated UDP partial answer (10.0.0.9).
        assert_eq!(addrs.len(), 2);
        assert!(addrs
            .iter()
            .all(|addr| addr.ip().to_string().ends_with('7')));
    }

    /// Zero-write posture: neither the read-only OHOS service cache (a
    /// miss on the gate build) nor any local tier records results, so the
    /// second resolution of the same authority re-queries — the mock
    /// server receives a full query pair per resolution.
    #[test]
    fn ut_owner_resolver_no_cache() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        let thread_counter = counter.clone();
        let thread = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            for _ in 0..4 {
                let (len, src) = mock.recv_from(&mut buf).unwrap();
                thread_counter.fetch_add(1, Ordering::SeqCst);
                let addrs = vec![IpAddr::from([10, 0, 0, 9])];
                mock.send_to(&mock_reply(&buf[..len], &addrs, false, 0), src)
                    .unwrap();
            }
        });

        let resolver = OwnerAwareResolver::new(uid, gid);
        let authority = format!("{}:80", TEST_NAME);
        let first =
            ylong_runtime::block_on(resolve_via(&resolver, authority.as_str(), &test_conf(server)))
                .unwrap();
        let second =
            ylong_runtime::block_on(resolve_via(&resolver, authority.as_str(), &test_conf(server)))
                .unwrap();
        thread.join().unwrap();
        assert_eq!(first, second);
        // One resolution = one A query + one AAAA query; nothing is
        // cached, so the second resolution queries again.
        assert_eq!(counter.load(Ordering::SeqCst), 4);
    }

    /// NXDOMAIN yields an error, and no system-resolver fallback happens.
    #[test]
    fn ut_owner_resolver_nxdomain() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (len, src) = mock.recv_from(&mut buf).unwrap();
                mock.send_to(&mock_reply(&buf[..len], &[], false, RCODE_NXDOMAIN), src)
                    .unwrap();
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let authority = format!("{}:80", TEST_NAME);
        let result =
            ylong_runtime::block_on(resolve_via(&resolver, authority.as_str(), &test_conf(server)));
        thread.join().unwrap();
        assert!(result.is_err());
    }

    /// An authoritative NXDOMAIN on AAAA does not discard the A family's
    /// records: musl's `checkBuf` gate only short-circuits when BOTH
    /// families miss NOERROR (`lookup_name.c` L368-381), so the surviving
    /// family is returned unchanged.
    #[test]
    fn ut_owner_resolver_aaaa_nxdomain_a_records() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (len, src) = mock.recv_from(&mut buf).unwrap();
                let is_a = buf[len - 4] == 0 && buf[len - 3] == TYPE_A as u8;
                let (rcode, addrs) = if is_a {
                    (0, vec![IpAddr::from([10, 0, 0, 7])])
                } else {
                    (RCODE_NXDOMAIN, vec![])
                };
                mock.send_to(&mock_reply(&buf[..len], &addrs, false, rcode), src)
                    .unwrap();
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let authority = format!("{}:80", TEST_NAME);
        let addrs =
            ylong_runtime::block_on(resolve_via(&resolver, authority.as_str(), &test_conf(server)))
                .unwrap();
        thread.join().unwrap();
        assert_eq!(addrs, vec![SocketAddr::from(([10, 0, 0, 7], 80))]);
    }

    /// An authoritative NXDOMAIN on AAAA combined with a failing A query
    /// (SERVFAIL) kills the candidate name: the `checkBuf` gate returns
    /// `checkBuf[0] == 0` (NXDOMAIN) without waiting for the A family.
    /// The A family keeps its musl `servfail_retry` resends within each
    /// round: with attempts=2 and instant replies the deterministic count
    /// is AAAA(1) + A(1 + 4 resends) x 2 rounds = 11 queries.
    #[test]
    fn ut_owner_resolver_nxdomain_dominates_failed_family() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let received = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (counter, stop_t) = (received.clone(), Arc::clone(&stop));
        let thread = std::thread::spawn(move || {
            mock.set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let mut buf = [0u8; 512];
            while !stop_t.load(Ordering::SeqCst) {
                if let Ok((len, src)) = mock.recv_from(&mut buf) {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let is_a = buf[len - 4] == 0 && buf[len - 3] == TYPE_A as u8;
                    let rcode = if is_a { RCODE_SERVFAIL } else { RCODE_NXDOMAIN };
                    mock.send_to(&mock_reply(&buf[..len], &[], false, rcode), src)
                        .unwrap();
                }
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let authority = format!("{}:80", TEST_NAME);
        let mut conf = test_conf(server);
        conf.attempts = 2;
        let result = ylong_runtime::block_on(resolve_via(&resolver, authority.as_str(), &conf));
        stop.store(true, Ordering::SeqCst);
        thread.join().unwrap();
        // AAAA(1) + A(1 + servfail_retry=4) per round, 2 rounds.
        assert_eq!(received.load(Ordering::SeqCst), 11);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    /// Mirror case with the A1 alignment closed (former deviation ④):
    /// NXDOMAIN on A while AAAA stays silent — the `checkBuf` gate fires
    /// with `checkBuf[0] = EAI_AGAIN` (the AAAA family has no usable
    /// answer) and the whole search aborts at once. The A NXDOMAIN vote
    /// accelerates the round boundary, which resends the pending AAAA
    /// until the attempts budget is burned: A(1) + AAAA(3) = 4 queries.
    #[test]
    fn ut_a_nxdomain_aaaa_silence_aborts_search() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let received = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let counter = received.clone();
        let stop_flag = stop.clone();
        let thread = std::thread::spawn(move || {
            mock.set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let mut buf = [0u8; 512];
            while !stop_flag.load(Ordering::SeqCst) {
                if let Ok((len, src)) = mock.recv_from(&mut buf) {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let is_a = buf[len - 4] == 0 && buf[len - 3] == TYPE_A as u8;
                    if is_a {
                        // AAAA is left unanswered on purpose.
                        mock.send_to(&mock_reply(&buf[..len], &[], false, RCODE_NXDOMAIN), src)
                            .unwrap();
                    }
                }
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let authority = format!("{}:80", TEST_NAME);
        let mut conf = test_conf(server);
        conf.timeout = Duration::from_millis(200);
        conf.attempts = 2;
        let result = ylong_runtime::block_on(resolve_via(&resolver, authority.as_str(), &conf));
        stop.store(true, Ordering::SeqCst);
        thread.join().unwrap();
        // The first send consumes attempt #1 (A + AAAA, musl L461 fires
        // the round boundary on the first pass); the A reply (NXDOMAIN, no
        // records) accelerates the boundary (L442-445), whose resend of
        // the pending AAAA consumes attempt #2 (L461) — 3 datagrams. The
        // gate then aborts the search: AAAA stayed silent.
        assert_eq!(received.load(Ordering::SeqCst), 3);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    /// A silent server maps to a negative gate outcome (`EAI_AGAIN`), so
    /// `resolve_name` ends in `SearchAbort` — the A1-aligned replacement
    /// of the former transport-failure outcome.
    #[test]
    fn ut_resolve_name_silent_server_aborts() {
        let (uid, gid) = current_owner();
        let resolver = OwnerAwareResolver::new(uid, gid);
        // A closed port: sends succeed and nothing ever answers.
        let conf = ResolvConf {
            servers: vec![SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 1)],
            timeout: Duration::from_millis(200),
            attempts: 1,
            ..Default::default()
        };
        let result = ylong_runtime::block_on(resolver.resolve_name(
            TEST_NAME,
            true,
            80,
            &conf,
            FamilyMask::Both,
        ));
        assert!(matches!(result, CandidateOutcome::SearchAbort(_)));
    }

    /// musl `*search = 0` (`lookup_name.c` L482-483): a dot count at or
    /// above `ndots` suppresses the search list entirely — only the bare
    /// name is queried and no search-suffixed candidate may hit the wire.
    #[test]
    fn ut_owner_resolver_ndots_suppresses_search() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(AtomicUsize::new(0));
        let (stop_t, seen_t) = (Arc::clone(&stop), Arc::clone(&seen));
        let thread = std::thread::spawn(move || {
            mock.set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let mut buf = [0u8; 512];
            while !stop_t.load(Ordering::SeqCst) {
                match mock.recv_from(&mut buf) {
                    Ok((len, src)) => {
                        seen_t.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(qname_of(&buf[..len]), "a.b.example");
                        mock.send_to(
                            &mock_reply_echo(&buf[..len], &[], false, RCODE_NXDOMAIN),
                            src,
                        )
                        .unwrap();
                    }
                    Err(_) => continue,
                }
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let mut conf = test_conf(server);
        conf.search = "corp.example.com".to_string();
        let result = ylong_runtime::block_on(resolve_via(&resolver, "a.b.example:80", &conf));
        stop.store(true, Ordering::SeqCst);
        thread.join().unwrap();
        // One round only (attempts = 1): the first pass sends A + AAAA
        // and consumes the single attempt (musl L461 fires the boundary on
        // the first pass); both NXDOMAIN replies are drained in the same
        // pass (L577-600) and the accelerated boundary exits on
        // `query_round >= attempts` (L455-456) — 2 datagrams, all for the
        // bare name.
        assert_eq!(seen.load(Ordering::SeqCst), 2);
        assert!(result.is_err());
    }

    /// musl `DNS_FAIL_REASON_FAIL_TO_PARSE_DNS` (-1104, `lookup.h` L221):
    /// NOERROR answers without records abort the whole search
    /// (`if (cnt) return cnt`, `lookup_name.c` L511-512) — the bare-name
    /// candidate after the search-expanded one must never be queried.
    #[test]
    fn ut_owner_resolver_nodata_aborts_search() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(AtomicUsize::new(0));
        let (stop_t, seen_t) = (Arc::clone(&stop), Arc::clone(&seen));
        let thread = std::thread::spawn(move || {
            mock.set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let mut buf = [0u8; 512];
            while !stop_t.load(Ordering::SeqCst) {
                match mock.recv_from(&mut buf) {
                    Ok((len, src)) => {
                        seen_t.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(qname_of(&buf[..len]), "mail.corp.example.com");
                        // NOERROR with zero answer records (NODATA).
                        mock.send_to(&mock_reply_echo(&buf[..len], &[], false, 0), src)
                            .unwrap();
                    }
                    Err(_) => continue,
                }
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let mut conf = test_conf(server);
        conf.search = "corp.example.com".to_string();
        let result = ylong_runtime::block_on(resolve_via(&resolver, "mail:80", &conf));
        stop.store(true, Ordering::SeqCst);
        thread.join().unwrap();
        // One round only (attempts = 1): the first pass sends A + AAAA and
        // consumes the single attempt; the A reply (NODATA, no records)
        // accelerates the boundary (musl L442-445), which exits on
        // `query_round >= attempts` (L455-456) — 2 datagrams for the
        // search candidate only; the bare name is never queried.
        assert_eq!(seen.load(Ordering::SeqCst), 2);
        assert!(result.is_err());
    }

    /// musl `if (cnt) return cnt` with `cnt == 0` (`lookup_name.c`
    /// L511-512): an authoritative NXDOMAIN on the search-expanded candidate
    /// moves the search to the next candidate — the bare name is still
    /// queried and resolves. Guards `CandidateDead → continue` against
    /// over-broad aborts.
    #[test]
    fn ut_owner_resolver_search_fallback_after_nxdomain() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_t = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            mock.set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let mut buf = [0u8; 512];
            while !stop_t.load(Ordering::SeqCst) {
                match mock.recv_from(&mut buf) {
                    Ok((len, src)) => {
                        if qname_of(&buf[..len]) == "mail.corp.example.com" {
                            mock.send_to(
                                &mock_reply_echo(&buf[..len], &[], false, RCODE_NXDOMAIN),
                                src,
                            )
                            .unwrap();
                        } else {
                            let is_a = buf[len - 4] == 0 && buf[len - 3] == TYPE_A as u8;
                            let addrs = if is_a {
                                vec![IpAddr::from([10, 0, 0, 9])]
                            } else {
                                vec![IpAddr::from([
                                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9,
                                ])]
                            };
                            mock.send_to(&mock_reply_echo(&buf[..len], &addrs, false, 0), src)
                                .unwrap();
                        }
                    }
                    Err(_) => continue,
                }
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let mut conf = test_conf(server);
        conf.search = "corp.example.com".to_string();
        let addrs = ylong_runtime::block_on(resolve_via(&resolver, "mail:80", &conf)).unwrap();
        stop.store(true, Ordering::SeqCst);
        thread.join().unwrap();
        assert_eq!(addrs.len(), 2);
        assert!(addrs
            .iter()
            .any(|addr| addr == &SocketAddr::from(([10, 0, 0, 9], 80))));
    }

    /// musl: the `checkBuf` gate does not fire when one family answered
    /// NOERROR (`lookup_name.c` L368-381), so AAAA-NODATA combined with
    /// A-NXDOMAIN reaches the parse, finds no records and returns
    /// `DNS_FAIL_REASON_FAIL_TO_PARSE_DNS` (-1104) — the whole search
    /// aborts and the bare name is never queried.
    #[test]
    fn ut_owner_resolver_nodata_mixed_families() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(AtomicUsize::new(0));
        let (stop_t, seen_t) = (Arc::clone(&stop), Arc::clone(&seen));
        let thread = std::thread::spawn(move || {
            mock.set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let mut buf = [0u8; 512];
            while !stop_t.load(Ordering::SeqCst) {
                match mock.recv_from(&mut buf) {
                    Ok((len, src)) => {
                        seen_t.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(qname_of(&buf[..len]), "mail.corp.example.com");
                        let is_a = buf[len - 4] == 0 && buf[len - 3] == TYPE_A as u8;
                        let rcode = if is_a { RCODE_NXDOMAIN } else { 0 };
                        mock.send_to(&mock_reply_echo(&buf[..len], &[], false, rcode), src)
                            .unwrap();
                    }
                    Err(_) => continue,
                }
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let mut conf = test_conf(server);
        conf.search = "corp.example.com".to_string();
        let result = ylong_runtime::block_on(resolve_via(&resolver, "mail:80", &conf));
        stop.store(true, Ordering::SeqCst);
        thread.join().unwrap();
        // One round only (attempts = 1): the first pass sends A + AAAA and
        // consumes the single attempt; both replies are drained in the
        // same pass (musl L577-600) and the accelerated boundary exits on
        // `query_round >= attempts` (L455-456) — 2 datagrams; the
        // bare-name candidate is never queried.
        assert_eq!(seen.load(Ordering::SeqCst), 2);
        assert!(result.is_err());
    }

    /// A1 alignment: a total transport failure on the search candidate is
    /// a negative gate outcome and aborts the WHOLE search — the bare-name
    /// candidate is never queried (musl `if (cnt) return cnt` with
    /// `cnt < 0`; this replaces the former try-next-candidate deviation).
    #[test]
    fn ut_transport_failure_aborts_search() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(AtomicUsize::new(0));
        let (stop_t, seen_t) = (Arc::clone(&stop), Arc::clone(&seen));
        let thread = std::thread::spawn(move || {
            mock.set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let mut buf = [0u8; 512];
            while !stop_t.load(Ordering::SeqCst) {
                if let Ok((len, src)) = mock.recv_from(&mut buf) {
                    seen_t.fetch_add(1, Ordering::SeqCst);
                    // Silence for the search candidate; the bare name
                    // WOULD resolve — it must never be queried.
                    let _ = (len, src);
                }
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let mut conf = test_conf(server);
        conf.timeout = Duration::from_millis(200);
        conf.search = "corp.example.com".to_string();
        let result = ylong_runtime::block_on(resolve_via(&resolver, "mail:80", &conf));
        stop.store(true, Ordering::SeqCst);
        thread.join().unwrap();
        // Only the search candidate's two queries hit the wire; the abort
        // prevents the bare-name fallback.
        assert_eq!(seen.load(Ordering::SeqCst), 2);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    /// `/etc/hosts` precedes DNS: "localhost" resolves without any server.
    #[test]
    fn ut_owner_resolver_hosts_precedence() {
        let (uid, gid) = current_owner();
        let resolver = OwnerAwareResolver::new(uid, gid);
        let addrs = ylong_runtime::block_on(resolver.resolve_impl("localhost:80")).unwrap();
        assert!(addrs.contains(&SocketAddr::from(([127, 0, 0, 1], 80))));
    }

    /// Resolution results are consistent with the system resolver for a
    /// real domain (skipped when the network is unavailable).
    #[test]
    fn ut_owner_resolver_getaddrinfo_consistency() {
        use std::collections::HashSet;
        use std::net::ToSocketAddrs;
        let authority = "example.com:80";
        let expected: HashSet<IpAddr> = match authority.to_socket_addrs() {
            Ok(addrs) => addrs.map(|addr| addr.ip()).collect(),
            Err(_) => return, // offline environment: nothing to compare.
        };
        if expected.is_empty() {
            return;
        }
        let (uid, gid) = current_owner();
        let resolver = OwnerAwareResolver::new(uid, gid);
        let addrs = ylong_runtime::block_on(resolver.resolve_impl(authority)).unwrap();
        assert!(!addrs.is_empty());
        // CDN answers may legitimately differ between two lookups; require
        // the two sets to overlap.
        let mine: HashSet<IpAddr> = addrs.iter().map(|addr| addr.ip()).collect();
        assert!(mine.intersection(&expected).next().is_some());
    }

    // ==== A1-aligned res_msend behaviors: broadcast, budget, consensus ====

    /// One socket broadcasts BOTH family queries to EVERY configured
    /// server (musl `res_msend` L448-535): each server receives both
    /// queries, and per-family answers from DIFFERENT servers are both
    /// accepted.
    #[test]
    fn ut_broadcast_all_servers() {
        let (uid, gid) = current_owner();
        let mock1 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server1 = mock1.local_addr().unwrap();
        let mock2 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server2 = mock2.local_addr().unwrap();
        let thread1 = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            // 2 queries arrive (AAAA + A); only A is answered.
            for _ in 0..2 {
                let (len, src) = mock1.recv_from(&mut buf).unwrap();
                let is_a = buf[len - 4] == 0 && buf[len - 3] == TYPE_A as u8;
                if is_a {
                    mock1
                        .send_to(
                            &mock_reply(&buf[..len], &[IpAddr::from([10, 0, 0, 3])], false, 0),
                            src,
                        )
                        .unwrap();
                }
            }
        });
        let thread2 = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            // 2 queries arrive (AAAA + A); only AAAA is answered.
            for _ in 0..2 {
                let (len, src) = mock2.recv_from(&mut buf).unwrap();
                let is_a = buf[len - 4] == 0 && buf[len - 3] == TYPE_A as u8;
                if !is_a {
                    mock2
                        .send_to(
                            &mock_reply(
                                &buf[..len],
                                &[IpAddr::from([
                                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
                                ])],
                                false,
                                0,
                            ),
                            src,
                        )
                        .unwrap();
                }
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let conf = ResolvConf {
            servers: vec![server1, server2],
            timeout: Duration::from_secs(1),
            attempts: 1,
            ..Default::default()
        };
        let addrs =
            ylong_runtime::block_on(resolve_via(&resolver, "owner.vpn.test:80", &conf)).unwrap();
        thread1.join().unwrap();
        thread2.join().unwrap();
        assert_eq!(addrs.len(), 2);
        assert!(addrs
            .iter()
            .any(|addr| addr == &SocketAddr::from(([10, 0, 0, 3], 80))));
        assert!(addrs.iter().any(|addr| addr.is_ipv6() && addr.port() == 80));
    }

    /// The OHOS musl-only `non_public` limiting ("First time only use non
    /// public ns", res_msend.c L492-500): the first send round targets
    /// only the leading `non_public` servers, later rounds all of them.
    ///
    /// # Brief
    /// 1. `non_public = 1` with two silent servers: round 1 sends both queries
    ///    to server 1 only (2 datagrams), round 2 broadcasts to both (4
    ///    datagrams) — the flag would be invisible with `non_public = 0` (4 +
    ///    4).
    /// 2. The exchange fails when the budget runs out.
    #[test]
    fn ut_non_public_first_round_limit() {
        let (uid, gid) = current_owner();
        let mock1 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server1 = mock1.local_addr().unwrap();
        let mock2 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server2 = mock2.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let seen1 = Arc::new(AtomicUsize::new(0));
        let seen2 = Arc::new(AtomicUsize::new(0));
        let (stop1, seen1_t) = (Arc::clone(&stop), Arc::clone(&seen1));
        let thread1 = std::thread::spawn(move || {
            mock1
                .set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let mut buf = [0u8; 512];
            while !stop1.load(Ordering::SeqCst) {
                if mock1.recv_from(&mut buf).is_ok() {
                    seen1_t.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        let (stop2, seen2_t) = (Arc::clone(&stop), Arc::clone(&seen2));
        let thread2 = std::thread::spawn(move || {
            mock2
                .set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let mut buf = [0u8; 512];
            while !stop2.load(Ordering::SeqCst) {
                if mock2.recv_from(&mut buf).is_ok() {
                    seen2_t.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let conf = ResolvConf {
            servers: vec![server1, server2],
            // A 1 s round interval keeps both rounds clear of scheduler
            // stalls under parallel test load: a stall would have to
            // outlast the whole interval to legitimately drop the last
            // round at the deadline (musl drops it the same way).
            timeout: Duration::from_millis(2000),
            attempts: 2,
            non_public: 1,
            ..Default::default()
        };
        let result = ylong_runtime::block_on(resolve_via(&resolver, "silent.vpn.test:80", &conf));
        stop.store(true, Ordering::SeqCst);
        thread1.join().unwrap();
        thread2.join().unwrap();
        // Round 1 (retry_count <= 1) targets the leading non_public server
        // only (musl L492-500); round 2 broadcasts to all (L501-535).
        assert_eq!(seen1.load(Ordering::SeqCst), 4);
        assert_eq!(seen2.load(Ordering::SeqCst), 2);
        assert!(result.is_err());
    }

    /// The total budget `timeout` is split into `attempts` rounds: with a
    /// fully silent server every round resends both queries, and the
    /// exchange ends only when the budget runs out (musl L448-457,
    /// L574-582).
    #[test]
    fn ut_total_budget_rounds() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let seen = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen_t, stop_t) = (Arc::clone(&seen), Arc::clone(&stop));
        let thread = std::thread::spawn(move || {
            mock.set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let mut buf = [0u8; 512];
            while !stop_t.load(Ordering::SeqCst) {
                if mock.recv_from(&mut buf).is_ok() {
                    seen_t.fetch_add(1, Ordering::SeqCst);
                    // Total silence: no reply at all.
                }
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let conf = ResolvConf {
            servers: vec![server],
            // The 1 s round interval keeps the round boundaries clear of
            // scheduler stalls under parallel test load: a stall would
            // have to outlast the whole interval to legitimately drop a
            // round at the deadline (musl drops it the same way).
            timeout: Duration::from_millis(3000),
            attempts: 3,
            ..Default::default()
        };
        let start = std::time::Instant::now();
        let result = ylong_runtime::block_on(resolve_via(&resolver, "owner.vpn.test:80", &conf));
        let elapsed = start.elapsed();
        stop.store(true, Ordering::SeqCst);
        thread.join().unwrap();
        // 3 rounds x (A + AAAA) = 6 datagrams, budget fully consumed.
        assert_eq!(seen.load(Ordering::SeqCst), 6);
        assert!(result.is_err());
        assert!(
            elapsed >= Duration::from_millis(2990),
            "elapsed {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_millis(6000),
            "elapsed {:?}",
            elapsed
        );
    }

    /// NXDOMAIN is finalized only by the LAST expected server
    /// (res_msend.c L657-675): with two servers, the first server's
    /// NXDOMAIN vote only counts the query as waiting — the second
    /// server's VALID answer, arriving later, is still accepted and wins.
    #[test]
    fn ut_nxdomain_consensus() {
        let (uid, gid) = current_owner();
        let mock1 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server1 = mock1.local_addr().unwrap();
        let mock2 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server2 = mock2.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop1 = Arc::clone(&stop);
        let stop2 = Arc::clone(&stop);
        let thread1 = std::thread::spawn(move || {
            mock1
                .set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let mut buf = [0u8; 512];
            while !stop1.load(Ordering::SeqCst) {
                if let Ok((len, src)) = mock1.recv_from(&mut buf) {
                    mock1
                        .send_to(&mock_reply(&buf[..len], &[], false, RCODE_NXDOMAIN), src)
                        .unwrap();
                }
            }
        });
        let thread2 = std::thread::spawn(move || {
            mock2
                .set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let mut buf = [0u8; 512];
            while !stop2.load(Ordering::SeqCst) {
                if let Ok((len, src)) = mock2.recv_from(&mut buf) {
                    // A brief delay keeps this server's answer behind the
                    // first server's NXDOMAIN vote.
                    std::thread::sleep(Duration::from_millis(30));
                    let is_a = buf[len - 4] == 0 && buf[len - 3] == TYPE_A as u8;
                    let addrs = if is_a {
                        vec![IpAddr::from([10, 0, 0, 5])]
                    } else {
                        vec![IpAddr::from([
                            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5,
                        ])]
                    };
                    mock2
                        .send_to(&mock_reply(&buf[..len], &addrs, false, 0), src)
                        .unwrap();
                }
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let conf = ResolvConf {
            servers: vec![server1, server2],
            timeout: Duration::from_secs(1),
            attempts: 2,
            ..Default::default()
        };
        let addrs =
            ylong_runtime::block_on(resolve_via(&resolver, "owner.vpn.test:80", &conf)).unwrap();
        stop.store(true, Ordering::SeqCst);
        thread1.join().unwrap();
        thread2.join().unwrap();
        // The first server's NXDOMAIN votes did NOT finalize the candidate:
        // the second server's records were accepted.
        assert!(addrs
            .iter()
            .any(|addr| addr == &SocketAddr::from(([10, 0, 0, 5], 80))));
        assert!(addrs.iter().any(|addr| addr.is_ipv6() && addr.port() == 80));
    }

    /// v4 fast-exit (res_msend.c L538-571): once valid A records arrive
    /// within `LARGE_LATENCY` of the round start, v6 gets only
    /// `MIN_WAIT_V6` (80ms) of extra grace; a slower AAAA answer is not
    /// waited for and the v4 result is returned alone.
    #[test]
    fn ut_v4_fast_exit_slow_v6() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (len, src) = mock.recv_from(&mut buf).unwrap();
                let is_a = buf[len - 4] == 0 && buf[len - 3] == TYPE_A as u8;
                if is_a {
                    mock.send_to(
                        &mock_reply(&buf[..len], &[IpAddr::from([10, 0, 0, 5])], false, 0),
                        src,
                    )
                    .unwrap();
                } else {
                    // The AAAA answer would arrive far beyond the grace.
                    std::thread::sleep(Duration::from_millis(400));
                    mock.send_to(
                        &mock_reply(
                            &buf[..len],
                            &[IpAddr::from([
                                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5,
                            ])],
                            false,
                            0,
                        ),
                        src,
                    )
                    .unwrap();
                }
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let conf = ResolvConf {
            servers: vec![server],
            timeout: Duration::from_secs(2),
            attempts: 1,
            ..Default::default()
        };
        let start = std::time::Instant::now();
        let addrs =
            ylong_runtime::block_on(resolve_via(&resolver, "owner.vpn.test:80", &conf)).unwrap();
        let elapsed = start.elapsed();
        thread.join().unwrap();
        assert_eq!(addrs, vec![SocketAddr::from(([10, 0, 0, 5], 80))]);
        assert!(
            elapsed < Duration::from_millis(350),
            "elapsed {:?}",
            elapsed
        );
    }

    /// The fast-exit grace window is not premature: an AAAA answer inside
    /// `MIN_WAIT_V6` is still accepted and both families are returned.
    #[test]
    fn ut_v4_fast_exit_grace_window() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (len, src) = mock.recv_from(&mut buf).unwrap();
                let is_a = buf[len - 4] == 0 && buf[len - 3] == TYPE_A as u8;
                let addrs = if is_a {
                    vec![IpAddr::from([10, 0, 0, 6])]
                } else {
                    vec![IpAddr::from([
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6,
                    ])]
                };
                if !is_a {
                    // Inside the 80ms v6 grace window.
                    std::thread::sleep(Duration::from_millis(40));
                }
                mock.send_to(&mock_reply(&buf[..len], &addrs, false, 0), src)
                    .unwrap();
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let conf = ResolvConf {
            servers: vec![server],
            timeout: Duration::from_secs(2),
            attempts: 1,
            ..Default::default()
        };
        let addrs =
            ylong_runtime::block_on(resolve_via(&resolver, "owner.vpn.test:80", &conf)).unwrap();
        thread.join().unwrap();
        assert_eq!(addrs.len(), 2);
    }

    /// An all-invalid A answer (invalid class: 127.0.0.0/8) keeps the query
    /// in flight for another server (res_msend.c L724-736, L724 assignment
    /// clears the flag when a valid answer arrives): the second server's
    /// valid A record is accepted and returned.
    #[test]
    fn ut_invalid_a_retries_other_servers() {
        let (uid, gid) = current_owner();
        let mock1 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server1 = mock1.local_addr().unwrap();
        let mock2 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server2 = mock2.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let (stop1, stop2) = (Arc::clone(&stop), Arc::clone(&stop));
        let thread1 = std::thread::spawn(move || {
            mock1
                .set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let mut buf = [0u8; 512];
            while !stop1.load(Ordering::SeqCst) {
                if let Ok((len, src)) = mock1.recv_from(&mut buf) {
                    let is_a = buf[len - 4] == 0 && buf[len - 3] == TYPE_A as u8;
                    // A: only the loopback 127.0.0.1 (invalid); AAAA: NODATA.
                    let addrs = if is_a {
                        vec![IpAddr::from([127, 0, 0, 1])]
                    } else {
                        vec![]
                    };
                    mock1
                        .send_to(&mock_reply(&buf[..len], &addrs, false, 0), src)
                        .unwrap();
                }
            }
        });
        let thread2 = std::thread::spawn(move || {
            mock2
                .set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let mut buf = [0u8; 512];
            while !stop2.load(Ordering::SeqCst) {
                if let Ok((len, src)) = mock2.recv_from(&mut buf) {
                    let is_a = buf[len - 4] == 0 && buf[len - 3] == TYPE_A as u8;
                    // A: the valid address; AAAA: NODATA.
                    let addrs = if is_a {
                        vec![IpAddr::from([10, 0, 0, 5])]
                    } else {
                        vec![]
                    };
                    mock2
                        .send_to(&mock_reply(&buf[..len], &addrs, false, 0), src)
                        .unwrap();
                }
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let conf = ResolvConf {
            servers: vec![server1, server2],
            timeout: Duration::from_secs(1),
            attempts: 1,
            ..Default::default()
        };
        let addrs =
            ylong_runtime::block_on(resolve_via(&resolver, "owner.vpn.test:80", &conf)).unwrap();
        stop.store(true, Ordering::SeqCst);
        thread1.join().unwrap();
        thread2.join().unwrap();
        // The loopback answer was dropped in favor of the valid one.
        assert_eq!(addrs, vec![SocketAddr::from(([10, 0, 0, 5], 80))]);
    }

    /// OHOS musl LOCAL class (dns_parse.c L5-19): when no valid v4 record
    /// exists at all, the set-aside loopback addresses come back
    /// (res_msend.c type_parse_callback / lookup_name.c collection).
    #[test]
    fn ut_loopback_fallback() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (len, src) = mock.recv_from(&mut buf).unwrap();
                let is_a = buf[len - 4] == 0 && buf[len - 3] == TYPE_A as u8;
                let addrs = if is_a {
                    vec![IpAddr::from([127, 0, 0, 1])]
                } else {
                    vec![]
                };
                mock.send_to(&mock_reply(&buf[..len], &addrs, false, 0), src)
                    .unwrap();
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let mut conf = test_conf(server);
        conf.timeout = Duration::from_millis(200);
        let addrs =
            ylong_runtime::block_on(resolve_via(&resolver, "owner.vpn.test:80", &conf)).unwrap();
        thread.join().unwrap();
        assert_eq!(addrs, vec![SocketAddr::from(([127, 0, 0, 1], 80))]);
    }

    /// OHOS musl ALLZERO class: an A answer of only 0.0.0.0 maps to
    /// `DNS_FAIL_REASON_SERVER_NO_RESULT` (-1203) and aborts the search.
    #[test]
    fn ut_allzero_a_aborts_search() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_t = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            mock.set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let mut buf = [0u8; 512];
            let mut answered = 0;
            while !stop_t.load(Ordering::SeqCst) {
                if let Ok((len, src)) = mock.recv_from(&mut buf) {
                    let is_a = buf[len - 4] == 0 && buf[len - 3] == TYPE_A as u8;
                    let addrs = if is_a {
                        vec![IpAddr::from([0, 0, 0, 0])]
                    } else {
                        vec![]
                    };
                    mock.send_to(&mock_reply(&buf[..len], &addrs, false, 0), src)
                        .unwrap();
                    answered += 1;
                    if answered >= 4 {
                        break;
                    }
                }
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let mut conf = test_conf(server);
        conf.timeout = Duration::from_millis(200);
        let result = ylong_runtime::block_on(resolve_via(&resolver, "owner.vpn.test:80", &conf));
        stop.store(true, Ordering::SeqCst);
        thread.join().unwrap();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    /// TCP rollback (res_msend.c L739-774): a TC answer is retried over
    /// TCP; when the TCP exchange fails, the truncated UDP answer is
    /// restored and the exchange continues — the surviving AAAA family is
    /// returned.
    #[test]
    fn ut_tc_fallback_rollback() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let listener = std::net::TcpListener::bind(server).unwrap();
        let udp_thread = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (len, src) = mock.recv_from(&mut buf).unwrap();
                let is_a = buf[len - 4] == 0 && buf[len - 3] == TYPE_A as u8;
                // AAAA: a normal answer; A: truncated (TC) with no records.
                // Bind the array to a local: borrowing a temporary through a
                // let-tuple relies on temporary-lifetime extension that the
                // OHOS 1.72 toolchain does not provide (E0716 there).
                let aaaa = [IpAddr::from([
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8,
                ])];
                let (addrs, truncated) = if is_a {
                    (&[][..], true)
                } else {
                    (&aaaa[..], false)
                };
                mock.send_to(&mock_reply(&buf[..len], addrs, truncated, 0), src)
                    .unwrap();
            }
        });
        let tcp_thread = std::thread::spawn(move || {
            // Accept the TCP retry and close without answering: the TCP
            // exchange fails and the UDP answer rolls back.
            if let Ok((mut stream, _)) = listener.accept() {
                let mut length = [0u8; 2];
                let _ = stream.read_exact(&mut length);
                let len = u16::from_be_bytes(length) as usize;
                let mut query = vec![0u8; len];
                let _ = stream.read_exact(&mut query);
                drop(stream);
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let authority = format!("{}:443", TEST_NAME);
        let addrs =
            ylong_runtime::block_on(resolve_via(&resolver, authority.as_str(), &test_conf(server)))
                .unwrap();
        udp_thread.join().unwrap();
        tcp_thread.join().unwrap();
        // The rolled-back truncated A answer carries no records; the AAAA
        // family survives.
        assert_eq!(
            addrs,
            vec![SocketAddr::from((
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8],
                443
            ))]
        );
    }

    /// Bare-name CNAME chase (lookup_name.c L430-444): a NOERROR answer
    /// with only a CNAME record re-queries the canon name once
    /// (`MAX_QUERY_SIZE` bounds the rounds; the OHOS musl build chases only
    /// for the bare name, L436-439).
    #[test]
    fn ut_cname_chase_bare_name() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let alias_seen = Arc::new(AtomicUsize::new(0));
        let canon_seen = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (alias_t, canon_t, stop_t) = (
            Arc::clone(&alias_seen),
            Arc::clone(&canon_seen),
            Arc::clone(&stop),
        );
        let thread = std::thread::spawn(move || {
            mock.set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let mut buf = [0u8; 512];
            while !stop_t.load(Ordering::SeqCst) {
                if let Ok((len, src)) = mock.recv_from(&mut buf) {
                    if qname_of(&buf[..len]) == "alias.test" {
                        alias_t.fetch_add(1, Ordering::SeqCst);
                        mock.send_to(&mock_reply_cname(&buf[..len], "canon.test"), src)
                            .unwrap();
                    } else {
                        canon_t.fetch_add(1, Ordering::SeqCst);
                        let is_a = buf[len - 4] == 0 && buf[len - 3] == TYPE_A as u8;
                        let addrs = if is_a {
                            vec![IpAddr::from([10, 0, 0, 8])]
                        } else {
                            vec![IpAddr::from([
                                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8,
                            ])]
                        };
                        mock.send_to(&mock_reply_echo(&buf[..len], &addrs, false, 0), src)
                            .unwrap();
                    }
                }
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let mut conf = test_conf(server);
        conf.timeout = Duration::from_secs(1);
        let addrs = ylong_runtime::block_on(resolve_via(&resolver, "alias.test:80", &conf)).unwrap();
        stop.store(true, Ordering::SeqCst);
        thread.join().unwrap();
        assert!(addrs
            .iter()
            .any(|addr| addr == &SocketAddr::from(([10, 0, 0, 8], 80))));
        assert!(addrs.iter().any(|addr| addr.is_ipv6() && addr.port() == 80));
        // Round 1: A + AAAA (the single attempt, musl L461 on the first
        // pass); both CNAME replies are drained in the same pass
        // (L577-600) and the accelerated boundary exits on
        // `query_round >= attempts` (L455-456) — 2 datagrams for the
        // alias. The chased canon round adds 2.
        assert_eq!(alias_seen.load(Ordering::SeqCst), 2);
        assert_eq!(canon_seen.load(Ordering::SeqCst), 2);
    }

    /// `MAX_ADDRS` guards the collected set through the whole pipeline:
    /// an answer with more records still yields at most 48 addresses.
    #[test]
    fn ut_max_addrs_cap() {
        let (uid, gid) = current_owner();
        let mock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = mock.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            for _ in 0..2 {
                let (len, src) = mock.recv_from(&mut buf).unwrap();
                let is_a = buf[len - 4] == 0 && buf[len - 3] == TYPE_A as u8;
                let addrs: Vec<IpAddr> = if is_a {
                    (0..60u8).map(|i| IpAddr::from([10, 0, i, 1])).collect()
                } else {
                    (0..60u8)
                        .map(|i| {
                            IpAddr::V6(std::net::Ipv6Addr::new(
                                0x2001, 0xdb8, 0, 0, 0, 0, i as u16, 1,
                            ))
                        })
                        .collect()
                };
                mock.send_to(&mock_reply(&buf[..len], &addrs, false, 0), src)
                    .unwrap();
            }
        });
        let resolver = OwnerAwareResolver::new(uid, gid);
        let conf = ResolvConf {
            servers: vec![server],
            timeout: Duration::from_secs(2),
            attempts: 1,
            ..Default::default()
        };
        let addrs =
            ylong_runtime::block_on(resolve_via(&resolver, "owner.vpn.test:80", &conf)).unwrap();
        thread.join().unwrap();
        assert_eq!(addrs.len(), MAX_ADDRS);
    }

    /// UT case for the single-family `checkBuf` gate (`queryNum = 1`,
    /// lookup_name.c L372-378): `nq < MAX_ANSWER_TYPE` short-circuits the
    /// second condition, so the one answer's verdict decides alone and the
    /// filtered slot is ignored.
    ///
    /// # Brief
    /// 1. V4Only: a VALID A answer proceeds, NXDOMAIN kills the candidate, a
    ///    missing answer aborts the search — even when the (unused) AAAA slot
    ///    would have said otherwise.
    /// 2. V6Only mirrors it on the AAAA slot.
    #[test]
    fn ut_gate_outcome_single_family() {
        let noerror = [0u8; 12];
        let mut nxdomain = [0u8; 12];
        nxdomain[3] = 0x03;
        // V4Only evaluates the A answer only.
        assert!(gate_outcome(&None, &Some(noerror.to_vec()), FamilyMask::V4Only).is_none());
        assert!(matches!(
            gate_outcome(
                &Some(noerror.to_vec()),
                &Some(nxdomain.to_vec()),
                FamilyMask::V4Only
            ),
            Some(CandidateOutcome::CandidateDead)
        ));
        assert!(matches!(
            gate_outcome(&None, &None, FamilyMask::V4Only),
            Some(CandidateOutcome::SearchAbort(_))
        ));
        // V6Only evaluates the AAAA answer only.
        assert!(gate_outcome(&Some(noerror.to_vec()), &None, FamilyMask::V6Only).is_none());
        assert!(matches!(
            gate_outcome(&Some(nxdomain.to_vec()), &None, FamilyMask::V6Only),
            Some(CandidateOutcome::CandidateDead)
        ));
        assert!(matches!(
            gate_outcome(&None, &None, FamilyMask::V6Only),
            Some(CandidateOutcome::SearchAbort(_))
        ));
    }
}
