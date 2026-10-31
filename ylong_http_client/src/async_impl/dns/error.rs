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

//! DNS error constructors shared by the resolver modules.
//!
//! Every message carries the OHOS musl `DNS_FAIL_REASON_*` code
//! (`lookup.h` L216-234) the site maps to, so field logs and telemetry
//! speak the same vocabulary as the system resolver.

use std::io;

/// Appends the musl failure code to a message (`lookup.h` L216-234).
fn with_reason(message: &str, code: i32, name: &str) -> String {
    format!("{message} (musl {code} {name})")
}

/// musl `DNS_FAIL_REASON_PARAM_INVALID` (-1101, `lookup.h` L218): the
/// authority itself failed API-level validation (no host, bad port).
pub(super) fn invalid_authority(authority: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        with_reason(&format!("invalid authority {:?}", authority), -1101, "PARAM_INVALID"),
    )
}

/// musl `DNS_FAIL_REASON_HOST_NAME_ILLEGAL` (-1102, `lookup.h` L219): the
/// host name failed `__res_mkquery` encoding (`resolvconf.c` L519-527).
pub(super) fn invalid_name(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        with_reason(&format!("invalid domain name {:?}", name), -1102, "HOST_NAME_ILLEGAL"),
    )
}

/// musl `DNS_FAIL_REASON_GET_RESOLV_CONF_FAILED` (-1103, `lookup.h` L220):
/// the DNS server configuration itself holds no usable entry — a
/// `dns_servers` override whose entries all failed to parse. The system
/// resolver fails the lookup the same way when the netsys configuration
/// cannot be read (`resolvconf.c` L134-139 → EAI_NONAME); failing fast
/// keeps DNS traffic from silently bypassing the VPN policy.
pub(super) fn config_unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        with_reason("no usable DNS server configured", -1103, "GET_RESOLV_CONF_FAILED"),
    )
}

/// musl `DNS_FAIL_REASON_FAIL_TO_PARSE_DNS` (-1104, `lookup.h` L221): an
/// answer arrived but parsed to no usable records.
pub(super) fn fail_to_parse(message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        with_reason(message, -1104, "FAIL_TO_PARSE_DNS"),
    )
}

/// musl `DNS_FAIL_REASON_SERVER_NO_RESULT` (-1203, `lookup.h` L227): only
/// all-zero (0.0.0.0) v4 records were seen (`lookup_name.c` L445-449).
pub(super) fn server_no_result(message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        with_reason(message, -1203, "SERVER_NO_RESULT"),
    )
}

/// musl `EAI_AGAIN` gate outcome (`lookup_name.c` L259): no usable answer —
/// every server silent, SERVFAIL, or another non-0/3 rcode. The musl
/// `DNS_FAIL_REASON_*` vocabulary has no numeric code for this class; the
/// EAI name is kept for parity.
pub(super) fn gate_again(message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{message} (musl EAI_AGAIN)"),
    )
}

/// musl `DNS_FAIL_REASON_TCP_QUERY_FAILED` (-1204, `lookup.h` L228): a TCP
/// retry stage timed out. The caller rolls back to the truncated UDP
/// answer (`res_msend.c` L822-834), so this usually surfaces in logs only.
pub(super) fn timeout_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        with_reason("DNS TCP query timed out", -1204, "TCP_QUERY_FAILED"),
    )
}

/// musl `DNS_FAIL_REASON_SERVER_NO_SUCH_NAME` (-1105, `lookup.h` L222):
/// every search candidate came back authoritatively dead — musl
/// `getaddrinfo` ends here with `EAI_NONAME`.
pub(super) fn no_such_name(authority: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        with_reason(&format!("failed to resolve {:?}", authority), -1105, "SERVER_NO_SUCH_NAME"),
    )
}
