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

//! System resolver configuration: resolv.conf parsing and search-list
//! candidate expansion, aligned with musl `__get_resolv_conf`
//! (`resolvconf.c`) and `name_from_dns_search` (`lookup_name.c` L466-545).

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use super::error::invalid_name;

pub(super) const DNS_PORT: u16 = 53;

/// Default total UDP budget in seconds, aligned with musl `conf->timeout`
/// (`resolvconf.c` L117). Overridable per client through the client
/// builder (`dns_timeout`) so a caller can inject its policy value (e.g.
/// the netsys resolver timeout) instead of the default.
pub(super) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default round count within the budget, aligned with musl
/// `conf->attempts` (`resolvconf.c` L118). Overridable per client through
/// the client builder (`dns_attempts`).
pub(super) const DEFAULT_ATTEMPTS: u32 = 2;

/// Maximum number of nameservers taken from resolv.conf, aligned with musl
/// (`MAXNS`, `resolv.h`).
///
/// Profile constant, deliberately NOT configurable: the exchange's round
/// bookkeeping (`compute_try_sets`) is only defined for lists up to this
/// bound, and every entry point (the resolv.conf parse and
/// `parse_dns_servers`) truncates to it — exactly what musl does
/// (`resolvconf.c` L157/L217: `nns >= MAXNS`). A different bound means a
/// different resolver profile, not a knob.
pub(super) const MAX_NAMESERVERS: usize = 3;

/// musl keeps ONE raw search string, replaced wholesale by every
/// `search`/`domain` line (`resolvconf.c` L229-234); the 256-byte bound is
/// the `canon[256]` buffer that also holds the joined name.
const SEARCH_STRING_MAX: usize = 256;

/// Default value of `options ndots`, aligned with musl (`resolvconf.c`
/// L116) and its 15 cap (L200).
const DEFAULT_NDOTS: usize = 1;

/// Upper bound of `options ndots`, aligned with musl (`x > 15 ? 15 : x`).
const MAX_NDOTS: usize = 15;

/// Upper bound of `options timeout` in seconds, aligned with musl
/// (`x > 60 ? 60 : x`, `resolvconf.c` L208-212) — no lower bound.
const MAX_TIMEOUT_SECS: u64 = 60;

/// Upper bound of `options attempts`, aligned with musl
/// (`x > 10 ? 10 : x`, `resolvconf.c` L202-206) — no lower bound, and no
/// `retry:` alias (that knob only exists in the OHOS musl config).
const MAX_ATTEMPTS: u32 = 10;

/// musl skips resolv.conf lines truncated by its 1024-byte fgets buffer
/// (`!strchr(line, '\n') && !feof(f)`, `resolvconf.c` L174-181): any line
/// of 1023+ bytes is dropped.
const RESOLV_LINE_MAX: usize = 1023;

const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// Linux errnos the OHOS musl resolv.conf loader treats as "no usable
/// configuration" (ENOENT/ENOTDIR/EACCES → the 127.0.0.1 fallback); every
/// other read error fails the DNS stage. Matched via raw_os_error because
/// stable io::ErrorKind does not cover ENOTDIR.
const ENOENT: i32 = 2;

const EACCES: i32 = 13;

const ENOTDIR: i32 = 20;

/// System resolver configuration parsed from `/etc/resolv.conf`.
///
/// Servers carry full socket addresses: parsing fills in the standard DNS
/// port, so production configurations behave exactly like before, while
/// tests can inject a mock server on any port.
pub(super) struct ResolvConf {
    pub(super) servers: Vec<SocketAddr>,
    /// Raw remainder of the LAST `search`/`domain` line: musl keeps one
    /// string and replaces it wholesale (both keywords share the same
    /// branch, `resolvconf.c` L228-234), tokenized on whitespace when the
    /// search list is walked.
    pub(super) search: String,
    pub(super) ndots: usize,
    /// Total UDP budget (musl `conf->timeout`), default 5 s.
    pub(super) timeout: Duration,
    /// Round count within the budget (musl `conf->attempts`), default 2.
    pub(super) attempts: u32,
    /// How many of the (musl-ordered) leading servers are non-public
    /// (musl `conf->non_public`): the first send round targets only these.
    /// File parsing never sets it (resolvconf.c L120), so it stays 0 for
    /// file-only configurations.
    pub(super) non_public: usize,
}

impl Default for ResolvConf {
    fn default() -> Self {
        ResolvConf {
            servers: Vec::new(),
            search: String::new(),
            ndots: DEFAULT_NDOTS,
            timeout: DEFAULT_TIMEOUT,
            attempts: DEFAULT_ATTEMPTS,
            non_public: 0,
        }
    }
}

/// Builds the query candidates for `name` exactly like musl
/// `name_from_dns_search` (lookup_name.c L466-545): the search list is the
/// whitespace-tokenized remainder of the LAST `search`/`domain` line; every
/// joined name must fit the 256-byte canon buffer (L530); a dot count at or
/// above `ndots` or a trailing dot suppresses the list entirely
/// (`*search = 0`, L479-483) and the bare name — the stripped name when a
/// trailing dot marked it absolute — is queried alone. The boolean marks
/// whether `name_from_dns` may chase the CNAME canon: search candidates
/// pass `canon` as both `name` and `queryName`, so the OHOS musl build breaks
/// on the pointer equality before any chase (L436-439), while the bare name
/// passes distinct pointers and may chase once (`MAX_QUERY_SIZE`).
/// Errors mirror musl DNS_FAIL_REASON_HOST_NAME_ILLEGAL (L519-527): an
/// empty name, multiple trailing dots, or a name of 256+ bytes — musl
/// returns the negative reason and the whole search aborts.
pub(super) fn candidates(name: &str, conf: &ResolvConf) -> io::Result<Vec<(String, bool)>> {
    let (bare, had_trailing_dot) = match name.strip_suffix('.') {
        Some(stripped) => (stripped, true),
        None => (name, false),
    };
    if bare.is_empty() || bare.ends_with('.') || bare.len() >= SEARCH_STRING_MAX {
        return Err(invalid_name(name));
    }
    if had_trailing_dot {
        // A trailing dot is an explicit request for global scope.
        return Ok(vec![(bare.to_string(), true)]);
    }
    if bare.matches('.').count() >= conf.ndots {
        // musl: `*search = 0` — the bare name only.
        return Ok(vec![(bare.to_string(), true)]);
    }
    let mut candidates: Vec<(String, bool)> = conf
        .search
        .split_whitespace()
        // musl L530: the joined name must fit the 256-byte canon buffer.
        .filter(|domain| domain.len() < SEARCH_STRING_MAX - bare.len() - 1)
        .map(|domain| (format!("{}.{}", bare, domain), false))
        .collect();
    candidates.push((bare.to_string(), true));
    Ok(candidates)
}

/// Parses resolv.conf exactly like musl `__get_resolv_conf` on the direct
/// file path (resolvconf.c L172-241):
/// - lines truncated by musl's 1024-byte fgets buffer are skipped whole
///   (`!strchr(line, '\n') && !feof(f)`): any line of 1023+ bytes is dropped;
/// - `nameserver` entries are capped at MAXNS (3); unparsable ones are ignored;
/// - `search` and `domain` share one musl branch: the raw remainder after the
///   keyword replaces the previous string wholesale and is skipped entirely
///   when it does not fit the 256-byte buffer (`l >= search_sz`); musl performs
///   no comment stripping — `#` or `;` stay part of the string;
/// - `options` are located with substring search and parsed with strtoul:
///   `ndots:` (cap 15), `attempts:` (cap 10) and `timeout:` (cap 60), without a
///   lower bound and without a `retry:` alias (that knob only exists in the
///   OHOS musl config).
fn parse_resolv_conf(content: &str) -> ResolvConf {
    let mut conf = ResolvConf::default();
    for line in content.lines() {
        if line.len() >= RESOLV_LINE_MAX {
            continue;
        }
        if let Some(rest) = keyword_arg(line, "nameserver") {
            if let Some(token) = rest.split_whitespace().next() {
                if let Ok(ip) = token.parse::<IpAddr>() {
                    if conf.servers.len() < MAX_NAMESERVERS {
                        conf.servers.push(SocketAddr::new(ip, DNS_PORT));
                    }
                }
            }
            continue;
        }
        if let Some(rest) = keyword_arg(line, "search").or_else(|| keyword_arg(line, "domain")) {
            if rest.len() < SEARCH_STRING_MAX {
                conf.search = rest.to_string();
            }
            continue;
        }
        if keyword_arg(line, "options").is_some() {
            if let Some(value) = option_number(line, "ndots:") {
                conf.ndots = (value as usize).min(MAX_NDOTS);
            }
            if let Some(value) = option_number(line, "attempts:") {
                conf.attempts = (value as u32).min(MAX_ATTEMPTS);
            }
            if let Some(value) = option_number(line, "timeout:") {
                conf.timeout = Duration::from_secs(value.min(MAX_TIMEOUT_SECS));
            }
        }
    }
    conf
}

/// musl matches keywords with `strncmp(line, kw, len) || !isspace(line[len])`
/// (resolvconf.c L189-199, L219-228): the keyword must occupy a whole word
/// followed by whitespace; the argument is the whitespace-trimmed remainder.
fn keyword_arg<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(keyword)?;
    if !rest.chars().next()?.is_ascii_whitespace() {
        return None;
    }
    Some(rest[1..].trim_start())
}

/// musl locates `options` with `strstr` anywhere in the line and parses the
/// value with `strtoul` (resolvconf.c L200-213): the first occurrence of the
/// key, at least one decimal digit right after it. Values beyond the u64
/// range saturate to u64::MAX, like strtoul's ULONG_MAX, so the caller's
/// cap wins.
fn option_number(line: &str, key: &str) -> Option<u64> {
    let start = line.find(key)? + key.len();
    let rest = &line[start..];
    let digits: usize = rest.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    if digits >= 20 {
        return Some(u64::MAX);
    }
    match rest[..digits].parse::<u64>() {
        Ok(value) => Some(value),
        // 20-digit overflow: strtoul saturates.
        Err(_) => Some(u64::MAX),
    }
}

/// Applies the musl fallback for an unusable nameserver list: queries go to
/// `127.0.0.1:53` (`resolvconf.c`, `no_resolv_conf` branch), mirroring the
/// system resolver instead of aborting the resolution.
fn with_default_nameserver(mut conf: ResolvConf) -> ResolvConf {
    if conf.servers.is_empty() {
        conf.servers
            .push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DNS_PORT));
    }
    conf
}

/// Reads the system resolver configuration, re-read on every resolution
/// like musl, so configuration changes are picked up by long-lived
/// clients. This resolver never talks to any platform DNS service: the server
/// list is supplied by the caller via `dns_servers`, and this file path
/// only serves generic Linux builds. The 127.0.0.1 fallback applies only
/// when the file is missing or unreadable (ENOENT/ENOTDIR/EACCES → musl
/// `no_resolv_conf`) or when it parses to zero servers (`if (!nns)`);
/// any other read error fails the DNS stage the way musl reports
/// DNS_FAIL_REASON_GET_RESOLV_CONF_FAILED.
pub(super) fn load_resolv_conf() -> io::Result<ResolvConf> {
    // musl `__get_resolv_conf` (resolvconf.c): defaults first, then the
    // file. The OHOS service branch (L131-167) is intentionally absent —
    // this resolver has no platform service dependency by design.
    let conf = match std::fs::read_to_string(RESOLV_CONF_PATH) {
        Ok(content) => parse_resolv_conf(content.as_str()),
        Err(err)
            if matches!(
                err.raw_os_error(),
                Some(ENOENT) | Some(ENOTDIR) | Some(EACCES)
            ) =>
        {
            ResolvConf::default()
        }
        Err(err) => return Err(err),
    };
    let conf = with_default_nameserver(conf);
    Ok(conf)
}

#[cfg(test)]
mod ut_test {
    use std::net::{IpAddr, SocketAddr};
    use std::time::Duration;

    use super::*;

    /// UT case for `parse_resolv_conf`: servers (with cap), the raw
    /// `search`/`domain` remainder, options, ignored lines.
    ///
    /// # Brief
    /// 1. Parses nameserver lines (v4 and v6, capped at MAXNS).
    /// 2. Verifies the search remainder is kept verbatim, `ndots`, `timeout`
    ///    and `attempts` options and the ignored `retry` knob.
    #[test]
    fn ut_parse_resolv_conf() {
        let conf = parse_resolv_conf(
            "# comment\n; another\nnameserver 192.0.2.1\nnameserver 2001:db8::53\n\
             nameserver 192.0.2.3\nnameserver 192.0.2.4\nsearch corp.example.com lab.example.com\n\
             options ndots:5 timeout:2 retry:3\ngarbage line here\n",
        );
        assert_eq!(conf.servers.len(), 3); // capped at MAX_NAMESERVERS
        assert_eq!(
            conf.servers[0],
            SocketAddr::new(IpAddr::from([192, 0, 2, 1]), DNS_PORT)
        );
        assert_eq!(
            conf.servers[1],
            SocketAddr::new(
                IpAddr::from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53]),
                DNS_PORT
            )
        );
        // musl keeps ONE raw string from the LAST search/domain line and
        // performs no comment stripping.
        assert_eq!(conf.search, "corp.example.com lab.example.com");
        assert_eq!(conf.ndots, 5);
        assert_eq!(conf.timeout, Duration::from_secs(2));
        // `retry` is an OHOS musl-only knob: musl's `attempts` is untouched.
        assert_eq!(conf.attempts, DEFAULT_ATTEMPTS);

        let domain = parse_resolv_conf("domain corp.example.com\noptions ndots:0\n");
        assert_eq!(domain.search, "corp.example.com");
        assert_eq!(domain.ndots, 0);

        let caps = parse_resolv_conf("options ndots:99 timeout:99 attempts:99\n");
        assert_eq!(caps.ndots, MAX_NDOTS);
        assert_eq!(caps.timeout, Duration::from_secs(MAX_TIMEOUT_SECS));
        assert_eq!(caps.attempts, MAX_ATTEMPTS);

        let empty = parse_resolv_conf("");
        assert!(empty.servers.is_empty());
        assert_eq!(empty.ndots, DEFAULT_NDOTS);
        assert_eq!(empty.timeout, DEFAULT_TIMEOUT);
        assert_eq!(empty.attempts, DEFAULT_ATTEMPTS);
    }

    /// UT case for the musl `no_resolv_conf` fallback: an empty nameserver
    /// list becomes 127.0.0.1:53; a usable list passes through unchanged.
    #[test]
    fn ut_default_nameserver_fallback() {
        let conf = with_default_nameserver(parse_resolv_conf("# only comments\n"));
        assert_eq!(conf.servers.len(), 1);
        assert_eq!(conf.servers[0], SocketAddr::from(([127, 0, 0, 1], 53)));

        let conf = with_default_nameserver(parse_resolv_conf("nameserver 192.0.2.1\n"));
        assert_eq!(conf.servers.len(), 1);
        assert_eq!(conf.servers[0], SocketAddr::from(([192, 0, 2, 1], 53)));
    }

    /// UT case for the search string handling: a remainder that fits the
    /// 256-byte buffer is kept verbatim (including `#` fragments — musl
    /// strips no comments); one of 256+ bytes is skipped entirely.
    #[test]
    fn ut_resolv_conf_search_string() {
        // A short remainder survives verbatim.
        let conf = parse_resolv_conf("search a.com b.com c.com\n");
        assert_eq!(conf.search, "a.com b.com c.com");
        // A 256+ byte remainder is dropped whole (`l >= search_sz`).
        let long_search = format!("search {}\n", "a".repeat(300));
        let conf = parse_resolv_conf(&long_search);
        assert_eq!(conf.search, "");
        // Exactly 255 bytes still fits.
        let fit = format!("search {}\n", "a".repeat(255));
        let conf = parse_resolv_conf(&fit);
        assert_eq!(conf.search.len(), 255);
        // The last line wins (musl replaces the string wholesale).
        let conf = parse_resolv_conf("search first.com\nsearch second.com\n");
        assert_eq!(conf.search, "second.com");
    }

    /// UT case for musl's 1024-byte fgets buffer: any line of 1023+ bytes
    /// is skipped whole, so a padded nameserver line contributes no server.
    #[test]
    fn ut_resolv_conf_long_line_skip() {
        let padded = format!("nameserver 192.0.2.1 {}\n", "x".repeat(RESOLV_LINE_MAX));
        let conf = parse_resolv_conf(&padded);
        assert!(conf.servers.is_empty());

        // A normal line right after a skipped one still parses.
        let conf = parse_resolv_conf(&format!("{}nameserver 192.0.2.9\n", padded));
        assert_eq!(conf.servers.len(), 1);
        assert_eq!(conf.servers[0], SocketAddr::from(([192, 0, 2, 9], 53)));
    }

    /// UT case for `candidates` (musl `name_from_dns_search`): trailing
    /// dot, ndots ordering, search list, and the failure reasons.
    ///
    /// # Brief
    /// 1. A trailing dot marks the name absolute: the stripped name only.
    /// 2. A dot count at or above `ndots` suppresses the search list.
    /// 3. Otherwise every search domain is prepended and the bare name is last;
    ///    the boolean marks chase eligibility.
    /// 4. Empty names, multiple trailing dots and 256+ names are errors.
    #[test]
    fn ut_candidates() {
        let conf = ResolvConf {
            search: "corp.example.com".to_string(),
            ..Default::default()
        };
        // Trailing dot: absolute only.
        assert_eq!(
            candidates("example.com.", &conf).unwrap(),
            vec![("example.com".to_string(), true)]
        );
        // Two dots >= ndots 1: musl suppresses the search list entirely
        // (`*search = 0`, `lookup_name.c` L482-483) — bare name only.
        assert_eq!(
            candidates("a.b.example", &conf).unwrap(),
            vec![("a.b.example".to_string(), true)]
        );
        // Zero dots < ndots 1: search first (no chase), bare name last.
        assert_eq!(
            candidates("mail", &conf).unwrap(),
            vec![
                ("mail.corp.example.com".to_string(), false),
                ("mail".to_string(), true)
            ]
        );
        // ndots 0: any dot count satisfies `dots >= ndots` → the search
        // list is suppressed (musl semantics), bare name only.
        let conf0 = ResolvConf {
            ndots: 0,
            ..ResolvConf {
                search: "corp.example.com".to_string(),
                ..Default::default()
            }
        };
        assert_eq!(
            candidates("mail", &conf0).unwrap(),
            vec![("mail".to_string(), true)]
        );
        // Multiple search domains keep their resolv.conf order; the bare
        // name is always last.
        let conf2 = ResolvConf {
            search: "a.example.com b.example.com".to_string(),
            ..Default::default()
        };
        assert_eq!(
            candidates("mail", &conf2).unwrap(),
            vec![
                ("mail.a.example.com".to_string(), false),
                ("mail.b.example.com".to_string(), false),
                ("mail".to_string(), true)
            ]
        );
        // Empty search strings contribute nothing.
        let conf3 = ResolvConf {
            search: "  b.example.com ".to_string(),
            ..Default::default()
        };
        assert_eq!(
            candidates("mail", &conf3).unwrap(),
            vec![
                ("mail.b.example.com".to_string(), false),
                ("mail".to_string(), true)
            ]
        );
        // Failure reasons (musl L519-527): empty, multiple trailing dots,
        // 256+ bytes.
        assert!(candidates("", &conf).is_err());
        assert!(candidates("a..", &conf).is_err());
        assert!(candidates(&"a".repeat(300), &conf).is_err());
    }
}
