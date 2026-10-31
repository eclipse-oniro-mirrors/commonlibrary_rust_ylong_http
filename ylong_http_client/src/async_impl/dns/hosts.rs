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

//! `/etc/hosts` parsing and exact-name matching, aligned with musl
//! `name_from_hosts` (`lookup_name.c` L27-81), including the built-in
//! fallback entries for an unreadable file.

use std::net::{IpAddr, SocketAddr};

use super::sort::sort_addrs_like_musl;
use super::wire::MAX_ADDRS;

const HOSTS_PATH: &str = "/etc/hosts";

/// musl `name_from_hosts` fallback when /etc/hosts cannot be read
/// (lookup_name.c L27-30): the two entries musl synthesizes in place of the
/// file, parsed through the same entry matcher as the real file.
const FIXED_HOSTS: &str = "127.0.0.1 localhost\n::1 ip6-localhost\n";

/// Looks a host up in `/etc/hosts`, returning all matching addresses in the
/// order musl `getaddrinfo` would hand out: file order, refined by the
/// RFC 6724 sort musl applies to every result (`lookup_name.c` L665-737).
/// `owner` makes the sort's source probe run under the designated socket
/// owner (see [`addrsort::probe`] in `sort`), so the ranking sees the same
/// source addresses as the owner-tagged resolver sockets. When the file
/// cannot be read, musl `name_from_hosts` falls back to two built-in
/// entries (lookup_name.c L27-30, L76-81) — mirrored here with
/// [`FIXED_HOSTS`]; names absent from both sources continue with DNS.
pub(super) fn lookup_hosts(host: &str, port: u16, owner: Option<(u32, u32)>) -> Vec<SocketAddr> {
    let content = match std::fs::read_to_string(HOSTS_PATH) {
        Ok(content) => content,
        Err(_) => FIXED_HOSTS.to_string(),
    };
    let mut ips = match_host_lines(host, content.lines());
    sort_addrs_like_musl(&mut ips, owner);
    ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect()
}

/// Streams `/etc/hosts` content line by line and collects the addresses of
/// entries whose name tokens contain `host`: exact, case-sensitive token
/// equality in file order (musl matches the raw name case-sensitively —
/// `strstr` with whitespace boundaries in `name_from_hosts` — and without
/// stripping a trailing dot), capped at `MAX_ADDRS` the way musl fills its
/// fixed buffer. `#` comments are stripped per line like musl does
/// (lookup_name.c L95); lines whose first token is not an IP address are
/// skipped. Matching streams over the lines instead of materializing every
/// entry's name list first, and stops at the cap.
fn match_host_lines<'a>(host: &str, lines: impl Iterator<Item = &'a str>) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for line in lines {
        if ips.len() >= MAX_ADDRS {
            break;
        }
        let line = line.split('#').next().unwrap_or("");
        let mut tokens = line.split_whitespace();
        let Some(ip) = tokens.next().and_then(|token| token.parse::<IpAddr>().ok()) else {
            continue;
        };
        if tokens.any(|name| name == host) {
            ips.push(ip);
        }
    }
    ips
}

#[cfg(test)]
mod ut_test {
    use std::net::{IpAddr, Ipv6Addr};

    use super::*;

    /// UT case for `/etc/hosts` matching (C3/C4 alignment): exact,
    /// case-sensitive token equality — musl `strstr` with whitespace
    /// boundaries is case-sensitive — plus the `MAXADDRS` cap in file
    /// order.
    #[test]
    fn ut_hosts_match_case_and_cap() {
        let content =
            "127.0.0.1 localhost\n192.0.2.1 LOCALHOST\n198.51.100.1 myhost alias\n";
        assert_eq!(
            match_host_lines("localhost", content.lines()),
            vec![IpAddr::from([127, 0, 0, 1])]
        );
        assert_eq!(
            match_host_lines("LOCALHOST", content.lines()),
            vec![IpAddr::from([192, 0, 2, 1])]
        );
        assert_eq!(
            match_host_lines("alias", content.lines()),
            vec![IpAddr::from([198, 51, 100, 1])]
        );
        assert!(match_host_lines("nomatch", content.lines()).is_empty());
        // Cap: 60 same-name entries keep only the first `MAX_ADDRS`.
        let many: String = (0..60).map(|i| format!("10.0.0.{} host\n", i)).collect();
        assert_eq!(match_host_lines("host", many.lines()).len(), MAX_ADDRS);
    }

    /// UT case for line tokenization: comments, multiple names per line,
    /// malformed lines.
    ///
    /// # Brief
    /// 1. Feeds content with a comment line, a multi-name entry, a
    ///    malformed line and an address-only line.
    /// 2. Only the address-carrying lines match their name tokens; the
    ///    comment and the malformed line contribute nothing.
    #[test]
    fn ut_hosts_line_tokenization() {
        let content = "# comment\n127.0.0.1 localhost localhost.localdomain\n::1 localhost\n\
                       badline\n192.0.2.7 myhost alias\n";
        assert_eq!(
            match_host_lines("localhost", content.lines()),
            vec![IpAddr::from([127, 0, 0, 1]), IpAddr::V6(Ipv6Addr::LOCALHOST)]
        );
        assert_eq!(
            match_host_lines("alias", content.lines()),
            vec![IpAddr::from([192, 0, 2, 7])]
        );
        assert!(match_host_lines("badline", content.lines()).is_empty());
    }

    /// UT case for the fixed-hosts fallback (D8): when `/etc/hosts` is
    /// unreadable, `localhost` and `ip6-localhost` still resolve from the
    /// built-in table — the OHOS musl build guarantees the same.
    #[test]
    fn ut_fixed_hosts_fallback() {
        assert_eq!(
            match_host_lines("localhost", FIXED_HOSTS.lines()),
            vec![IpAddr::from([127, 0, 0, 1])]
        );
        assert_eq!(
            match_host_lines("ip6-localhost", FIXED_HOSTS.lines()),
            vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]
        );
    }
}
