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

//! DNS wire format: query building and response parsing
//! ([RFC 1035], [RFC 3596]).
//!
//! [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
//! [RFC 3596]: https://datatracker.ietf.org/doc/html/rfc3596

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Maximum number of compression pointer jumps followed when parsing a
/// name. Compression pointers reference prior occurrences
/// [RFC1035, Section 4.1.4]; the strict-backward rule below already rules
/// out loops, so this bound is pure defense in depth.
///
/// [RFC1035, Section 4.1.4]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
const MAX_NAME_JUMPS: usize = 128;

/// Cap on collected answer addresses per response, bounding the memory a
/// single (possibly hostile or oversized) answer can make the parser
/// allocate.
pub const MAX_ADDRS: usize = 48;

/// IPv4 address record type ([RFC1035, Section 3.4.1]).
///
/// [RFC1035, Section 3.4.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.4.1
pub const TYPE_A: u16 = 1;

/// IPv6 address record type ([RFC 3596, Section 2.1]).
///
/// [RFC 3596, Section 2.1]: https://datatracker.ietf.org/doc/html/rfc3596#section-2.1
pub const TYPE_AAAA: u16 = 28;

/// Canonical name record type ([RFC1035, Section 3.3.1]).
///
/// [RFC1035, Section 3.3.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.1
pub const TYPE_CNAME: u16 = 5;

/// Internet class ([RFC1035, Section 3.2.4]).
///
/// [RFC1035, Section 3.2.4]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
pub const CLASS_IN: u16 = 1;

/// Query/response flag of the message header ([RFC1035, Section 4.1.1]).
///
/// [RFC1035, Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
pub const FLAG_QR: u16 = 0x8000;

/// Truncation flag of the message header ([RFC1035, Section 4.1.1]).
///
/// [RFC1035, Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
pub const FLAG_TC: u16 = 0x0200;

/// Recursion-desired flag of the message header ([RFC1035, Section 4.1.1]).
///
/// [RFC1035, Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
pub const FLAG_RD: u16 = 0x0100;

/// No-error condition of the header rcode ([RFC1035, Section 4.1.1]).
///
/// [RFC1035, Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
pub const RCODE_NOERROR: u16 = 0;

/// Server-failure condition of the header rcode ([RFC1035, Section 4.1.1]).
///
/// [RFC1035, Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
pub const RCODE_SERVFAIL: u16 = 2;

/// Name-error (authoritative non-existence) condition of the header rcode
/// ([RFC1035, Section 4.1.1]).
///
/// [RFC1035, Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
pub const RCODE_NXDOMAIN: u16 = 3;

/// Outcome of parsing a single DNS response: the header rcode decides the
/// verdict [RFC1035, Section 4.1.1], the record walk only collects.
///
/// The parser is lenient by design: transaction ids, QR/opcode bits and
/// question sections are not validated here, so the transport layer can
/// apply its own acceptance policy on top of the parsed result.
///
/// [RFC1035, Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
pub enum ParseOutcome {
    /// NOERROR answer ([RFC1035, Section 4.1.1] rcode 0): whatever the
    /// record walk yielded — possibly partial, possibly empty (NODATA).
    Records(ParsedAnswer),
    /// NXDOMAIN (rcode 3): the name authoritatively does not exist.
    NxDomain,
    /// No usable answer: any other rcode (for example SERVFAIL).
    Unusable,
}

/// One parsed NOERROR answer: the collected address records with their
/// per-record TTLs ([RFC1035, Section 3.2.1] caches these to bound
/// staleness), and the last valid CNAME target in parse order
/// ([RFC1035, Section 3.3.1] aliases) for callers that chase bare names.
#[derive(Default)]
pub struct ParsedAnswer {
    /// Address records with their per-record TTL in seconds.
    pub records: Vec<(IpAddr, u32)>,
    /// The last valid CNAME target seen while walking the answer section.
    pub canon: Option<String>,
}

/// Parses a DNS response: the header rcode decides the verdict
/// ([RFC1035, Section 4.1.1]); the record walk collects A/AAAA records
/// with their per-record TTLs ([RFC1035, Section 4.1.3]) and the last
/// valid CNAME target ([RFC1035, Section 3.3.1], root name rejected).
///
/// Messages shorter than the 12-byte header yield an empty record set
/// instead of an error. A structural failure (truncated record, bad
/// compression pointer) stops the walk; records collected so far are kept,
/// so callers can still use a partially received answer.
///
/// [RFC1035, Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
/// [RFC1035, Section 4.1.3]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
/// [RFC1035, Section 3.3.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.1
pub fn parse_response(msg: &[u8]) -> ParseOutcome {
    if msg.len() < 12 {
        // Below the fixed header size there is nothing to walk; treat the
        // message as an empty NOERROR answer.
        return ParseOutcome::Records(ParsedAnswer::default());
    }
    let byte = |idx: usize| msg.get(idx).copied().unwrap_or(0);
    match (byte(3) & 0x0F) as u16 {
        RCODE_NXDOMAIN => return ParseOutcome::NxDomain,
        RCODE_NOERROR => {}
        _ => return ParseOutcome::Unusable,
    }
    let question_count = u16::from_be_bytes([byte(4), byte(5)]);
    let answer_count = u16::from_be_bytes([byte(6), byte(7)]);
    let mut parser = DnsParser { msg, pos: 12 };
    // Skip the question section; a structural failure here ends the walk
    // with no records. The question text is never needed — skip it.
    for _ in 0..question_count {
        if parser.skip_name().is_none() || parser.u16().is_none() || parser.u16().is_none() {
            return ParseOutcome::Records(ParsedAnswer::default());
        }
    }
    let mut answer = ParsedAnswer::default();
    for _ in 0..answer_count {
        // The owner name's text is never needed — skip it like musl's
        // `dn_skipname`; only the CNAME rdata below materializes text.
        if parser.skip_name().is_none() {
            break;
        }
        let Some(record_type) = parser.u16() else { break };
        let Some(class) = parser.u16() else { break };
        let Some(ttl) = parser.u32() else { break };
        let Some(rdlength) = parser.u16() else { break };
        let rdata_start = parser.pos;
        let Some(rdata) = parser.take(rdlength as usize) else { break };
        push_record(&mut answer, msg, record_type, class, ttl, rdata, rdata_start);
    }
    ParseOutcome::Records(answer)
}

/// Appends one answer record to the parse result. The answer RR layout
/// (owner name, type, class, TTL, RDLENGTH, RDATA) follows
/// [RFC1035, Section 4.1.3]; A/AAAA records up to `MAX_ADDRS`, CNAME
/// expands into canon with the root name rejected. Non-IN classes and
/// other record types are skipped.
///
/// [RFC1035, Section 4.1.3]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
fn push_record(
    answer: &mut ParsedAnswer,
    msg: &[u8],
    record_type: u16,
    class: u16,
    ttl: u32,
    rdata: &[u8],
    rdata_start: usize,
) {
    if class != CLASS_IN {
        return;
    }
    match record_type {
        TYPE_A if answer.records.len() < MAX_ADDRS => {
            if let Ok(octets) = <[u8; 4]>::try_from(rdata) {
                answer.records.push((IpAddr::V4(Ipv4Addr::from(octets)), ttl));
            }
        }
        TYPE_AAAA if answer.records.len() < MAX_ADDRS => {
            if let Ok(octets) = <[u8; 16]>::try_from(rdata) {
                answer.records.push((IpAddr::V6(Ipv6Addr::from(octets)), ttl));
            }
        }
        TYPE_CNAME => {
            // [RFC1035, Section 3.3.1]: the rdata of a CNAME record is a
            // (possibly compressed) domain name. Every valid target
            // overwrites canon — the last CNAME in parse order is the one
            // closest to the queried name's chain end that the walk has
            // confirmed; the root name is rejected.
            let mut sub = DnsParser { msg, pos: rdata_start };
            if let Some(target) = sub.name() {
                if !target.is_empty() && target != "." && is_valid_hostname(&target) {
                    answer.canon = Some(target);
                }
            }
        }
        _ => {}
    }
}

/// Checks a parsed CNAME target with the classic resolver name rules: a
/// usable host name is 1..=254 bytes and contains only ASCII
/// alphanumerics, dots, dashes and non-ASCII bytes.
fn is_valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 254 {
        return false;
    }
    host.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-' || byte >= 0x80)
}

/// Builds a standard recursive query for one name and type: the 12-byte
/// header with RD set ([RFC1035, Section 4.1.1]) followed by one question
/// entry ([RFC1035, Section 4.1.2]).
///
/// [RFC1035, Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
/// [RFC1035, Section 4.1.2]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
pub fn build_query(out: &mut Vec<u8>, id: u16, qtype: u16, name: &str) -> io::Result<()> {
    // Reserve the exact wire size up front: the 12-byte header, the
    // encoded name (a length byte per label plus the root terminator)
    // and the question tail.
    out.reserve(16 + name.len() + name.matches('.').count() + 1);
    let mark = out.len();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&FLAG_RD.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an/ns/ar counts
    if let Err(err) = encode_name(out, name) {
        // Transactional: an unparsable name leaves the caller's buffer
        // exactly as it was.
        out.truncate(mark);
        return Err(err);
    }
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(())
}

/// Appends a wire-format name: length-prefixed labels and a zero
/// terminator ([RFC1035, Section 3.1]). Empty labels and labels longer
/// than 63 bytes are rejected; the textual name is limited to 253
/// characters after stripping one optional trailing dot, the classic
/// resolver encoding bound. The stripping mirrors musl `res_mkquery`
/// (res_mkquery.c L12-16); a second trailing dot survives as an empty
/// label and hits the same rejection.
///
/// [RFC1035, Section 3.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.1
pub fn encode_name(out: &mut Vec<u8>, name: &str) -> io::Result<()> {
    let body = name.strip_suffix('.').unwrap_or(name);
    if body.len() > 253 {
        return Err(invalid_name_error(name));
    }
    for label in body.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(invalid_name_error(name));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Error returned when a name cannot be encoded on the wire.
fn invalid_name_error(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid domain name {:?}", name),
    )
}

/// Cursor over a DNS message with support for compressed names.
struct DnsParser<'a> {
    msg: &'a [u8],
    pos: usize,
}

impl<'a> DnsParser<'a> {
    fn u16(&mut self) -> Option<u16> {
        let value = u16::from_be_bytes([*self.msg.get(self.pos)?, *self.msg.get(self.pos + 1)?]);
        self.pos += 2;
        Some(value)
    }

    fn u32(&mut self) -> Option<u32> {
        let mut bytes = [0u8; 4];
        for byte in bytes.iter_mut() {
            *byte = *self.msg.get(self.pos)?;
            self.pos += 1;
        }
        Some(u32::from_be_bytes(bytes))
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let slice = self.msg.get(self.pos..self.pos.checked_add(len)?)?;
        self.pos += len;
        Some(slice)
    }

    /// Walks one (possibly compressed) name from the cursor. When
    /// `collect` is set the label text is materialized into one string,
    /// otherwise the walk allocates nothing — the parse-side
    /// `dn_skipname`. Both entry points share the same acceptance rule:
    /// compression pointers reference prior occurrences
    /// ([RFC1035, Section 4.1.4]) and must point strictly backwards,
    /// which makes pointer loops impossible, and the jump count is
    /// bounded as well.
    ///
    /// [RFC1035, Section 4.1.4]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
    fn walk_name(&mut self, collect: bool) -> Option<String> {
        let mut out = String::new();
        let mut pos = self.pos;
        let mut end = None;
        let mut jumps = 0;
        loop {
            let length = *self.msg.get(pos)?;
            if length & 0xC0 == 0xC0 {
                let pointer =
                    (((length & 0x3F) as usize) << 8) | (*self.msg.get(pos + 1)? as usize);
                if pointer >= pos {
                    return None;
                }
                if end.is_none() {
                    end = Some(pos + 2);
                }
                jumps += 1;
                if jumps > MAX_NAME_JUMPS {
                    return None;
                }
                pos = pointer;
            } else if length == 0 {
                if end.is_none() {
                    end = Some(pos + 1);
                }
                break;
            } else if length & 0xC0 != 0 {
                // 0x40/0x80 label types are not supported (no EDNS).
                return None;
            } else {
                let label = self.msg.get(pos + 1..pos + 1 + length as usize)?;
                if collect {
                    if !out.is_empty() {
                        out.push('.');
                    }
                    out.push_str(String::from_utf8_lossy(label).as_ref());
                }
                pos += 1 + length as usize;
            }
        }
        self.pos = end?;
        Some(out)
    }

    /// Parses a (possibly compressed) name and leaves the cursor after it,
    /// returning the joined label text.
    fn name(&mut self) -> Option<String> {
        self.walk_name(true)
    }

    /// Advances the cursor past one (possibly compressed) name without
    /// building its text — used for the question section and answer owner
    /// names, whose text the record walk never needs (musl skips those
    /// with `dn_skipname`).
    fn skip_name(&mut self) -> Option<()> {
        self.walk_name(false).map(|_| ())
    }
}

#[cfg(test)]
mod ut_test {
    use std::net::IpAddr;

    use super::*;

    /// Fixed question name of the canned [`test_response`] builder.
    const TEST_NAME: &str = "example.com";

    /// Builds a well-formed DNS response for tests: question echo followed
    /// by one answer record per address, owner names compressed to the
    /// question name.
    fn test_response(
        id: u16,
        name: &str,
        qtype: u16,
        addrs: &[IpAddr],
        truncated: bool,
        rcode: u16,
    ) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend(id.to_be_bytes());
        let mut flags: u16 = FLAG_QR | (rcode & 0x000F);
        if truncated {
            flags |= FLAG_TC;
        }
        msg.extend(flags.to_be_bytes());
        msg.extend(1u16.to_be_bytes()); // qdcount
        msg.extend((addrs.len() as u16).to_be_bytes()); // ancount
        msg.extend([0, 0, 0, 0]); // nscount/arcount
        encode_name(&mut msg, name).unwrap();
        msg.extend(qtype.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        if truncated {
            return msg;
        }
        for addr in addrs {
            msg.extend([0xC0, 0x0C]); // owner: pointer to question name
            msg.extend(qtype.to_be_bytes());
            msg.extend(CLASS_IN.to_be_bytes());
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

    /// UT case for `build_query`: header flags, question encoding.
    ///
    /// # Brief
    /// 1. Builds an A query for "a.b".
    /// 2. Verifies id, flags, counts, labels and qtype/qclass bytes.
    #[test]
    fn ut_build_query_a() {
        let mut query = Vec::new();
        build_query(&mut query, 0x1234, TYPE_A, "a.b").unwrap();
        let expect: Vec<u8> = vec![
            0x12, 0x34, // id
            0x01, 0x00, // flags: RD
            0x00, 0x01, // qdcount
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar
            0x01, b'a', 0x01, b'b', 0x00, // qname
            0x00, 0x01, // qtype A
            0x00, 0x01, // qclass IN
        ];
        assert_eq!(query, expect);
    }

    /// UT case for `encode_name` with invalid names.
    ///
    /// # Brief
    /// 1. Empty labels, oversized labels and oversized names are rejected.
    #[test]
    fn ut_build_query_invalid_name() {
        let mut out = Vec::new();
        assert!(encode_name(&mut out, "a..b").is_err());
        assert!(encode_name(&mut out, ".a").is_err());
        assert!(encode_name(&mut out, &"a".repeat(64)).is_err());
        // Total-length bound: 253 characters after stripping one trailing
        // dot; labels stay within the 63-byte rule.
        let long_ok = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(61)
        );
        assert_eq!(long_ok.len(), 253);
        assert!(encode_name(&mut out, &long_ok).is_ok());
        let long_err = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(62)
        );
        assert_eq!(long_err.len(), 254);
        assert!(encode_name(&mut out, &long_err).is_err());
        let label = "x".repeat(60);
        assert!(encode_name(
            &mut out,
            &format!("{}.{}.{}.{}.{}", label, label, label, label, label)
        )
        .is_err());
        assert!(encode_name(&mut out, "a.b.c").is_ok());
    }

    /// UT case for `encode_name` trailing-dot handling (musl res_mkquery.c
    /// L12-16): exactly one optional trailing dot is stripped before the
    /// length bound; a second one is an empty label and is rejected.
    ///
    /// # Brief
    /// 1. `"a.b.c."` encodes byte-for-byte like `"a.b.c"`.
    /// 2. A second trailing dot, a lone root dot, and a name that is only
    ///    within bounds after stripping are covered at the 253-byte bound.
    #[test]
    fn ut_encode_name_trailing_dot() {
        let mut bare = Vec::new();
        encode_name(&mut bare, "a.b.c").unwrap();
        let mut dotted = Vec::new();
        encode_name(&mut dotted, "a.b.c.").unwrap();
        assert_eq!(bare, dotted);

        let mut out = Vec::new();
        // A second trailing dot survives the strip as an empty label; the
        // lone root dot degenerates to the same empty label.
        assert!(encode_name(&mut out, "a.b.c..").is_err());
        assert!(encode_name(&mut out, ".").is_err());
        // The length bound applies after stripping: a 254-character name
        // ending in one dot is accepted, a 255-character one is not.
        let long = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(61)
        );
        assert_eq!(long.len(), 253);
        assert!(encode_name(&mut out, &format!("{}.", long)).is_ok());
        assert!(encode_name(&mut out, &format!("{}..", long)).is_err());
    }

    /// UT case for `parse_response` with an A answer using a compressed
    /// owner name.
    ///
    /// # Brief
    /// 1. Builds a response whose answer owner name is a pointer to the
    ///    question name.
    /// 2. Verifies the parsed address and its per-record TTL.
    #[test]
    fn ut_parse_response_a() {
        let msg = test_response(
            0x0102,
            TEST_NAME,
            TYPE_A,
            &[IpAddr::from([1, 2, 3, 4])],
            false,
            RCODE_NOERROR,
        );
        match parse_response(&msg) {
            ParseOutcome::Records(parsed) => {
                assert_eq!(parsed.records, vec![(IpAddr::from([1, 2, 3, 4]), 60)]);
                assert!(parsed.canon.is_none());
            }
            _ => panic!("expected records"),
        }
    }

    /// UT case for `parse_response` with an AAAA answer.
    #[test]
    fn ut_parse_response_aaaa() {
        let msg = test_response(
            0x0304,
            TEST_NAME,
            TYPE_AAAA,
            &[IpAddr::from([0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])],
            false,
            RCODE_NOERROR,
        );
        match parse_response(&msg) {
            ParseOutcome::Records(parsed) => {
                assert_eq!(parsed.records.len(), 1);
                assert!(parsed.records[0].0.is_ipv6());
            }
            _ => panic!("expected records"),
        }
    }

    /// UT case for `parse_response` following a CNAME chain: the answer
    /// section contains a CNAME record and the terminal A record; the A
    /// record is collected and the CNAME target is exposed as the canon
    /// for the bare-name chase.
    #[test]
    fn ut_parse_response_cname_chain() {
        let mut msg = Vec::new();
        msg.extend(0x0506u16.to_be_bytes());
        msg.extend(FLAG_QR.to_be_bytes()); // QR, NOERROR
        msg.extend(1u16.to_be_bytes()); // qdcount
        msg.extend(2u16.to_be_bytes()); // ancount
        msg.extend([0, 0, 0, 0]); // nscount/arcount
        // question: www.example.com A
        encode_name(&mut msg, "www.example.com").unwrap();
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        // answer 1: CNAME www.example.com -> example.com
        msg.extend([0xC0, 0x0C]); // owner: pointer to question
        msg.extend(TYPE_CNAME.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        let mut rdata = Vec::new();
        encode_name(&mut rdata, "example.com").unwrap();
        msg.extend((rdata.len() as u16).to_be_bytes());
        msg.extend(rdata);
        // answer 2: A example.com = 9.9.9.9, owner compressed to the
        // "example.com" tail of the question name (offset 12 + 4).
        msg.extend([0xC0, 0x10]);
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        msg.extend(4u16.to_be_bytes());
        msg.extend([9, 9, 9, 9]);
        match parse_response(&msg) {
            ParseOutcome::Records(parsed) => {
                assert_eq!(parsed.records, vec![(IpAddr::from([9, 9, 9, 9]), 60)]);
                assert_eq!(parsed.canon.as_deref(), Some("example.com"));
            }
            _ => panic!("expected records"),
        }
    }

    /// UT case for the last-wins CNAME rule: when one answer carries two
    /// CNAME records, the LAST valid target in parse order overwrites
    /// canon, and an invalid target in between must not take over.
    ///
    /// # Brief
    /// 1. Builds an answer with CNAME -> "first.example.com" followed by
    ///    CNAME -> "bad_host.example.com" (underscore is not a legal host
    ///    name character).
    /// 2. Verifies canon stays on the last VALID target.
    #[test]
    fn ut_parse_response_cname_last_wins() {
        let mut msg = Vec::new();
        msg.extend(0x0506u16.to_be_bytes());
        msg.extend(FLAG_QR.to_be_bytes()); // QR, NOERROR
        msg.extend(1u16.to_be_bytes()); // qdcount
        msg.extend(2u16.to_be_bytes()); // ancount
        msg.extend([0, 0, 0, 0]); // nscount/arcount
        encode_name(&mut msg, "www.example.com").unwrap();
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        // answer 1: CNAME -> first.example.com (valid, becomes canon)
        msg.extend([0xC0, 0x0C]);
        msg.extend(TYPE_CNAME.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        let mut rdata = Vec::new();
        encode_name(&mut rdata, "first.example.com").unwrap();
        msg.extend((rdata.len() as u16).to_be_bytes());
        msg.extend(rdata);
        // answer 2: CNAME -> bad_host.example.com (underscore: invalid)
        msg.extend([0xC0, 0x0C]);
        msg.extend(TYPE_CNAME.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        let mut rdata = Vec::new();
        encode_name(&mut rdata, "bad_host.example.com").unwrap();
        msg.extend((rdata.len() as u16).to_be_bytes());
        msg.extend(rdata);
        match parse_response(&msg) {
            ParseOutcome::Records(parsed) => {
                // Last VALID target wins; the invalid one is skipped.
                assert_eq!(parsed.canon.as_deref(), Some("first.example.com"));
                assert!(parsed.records.is_empty());
            }
            _ => panic!("expected records"),
        }
    }

    /// UT case for CNAME target validation: a target that is structurally
    /// valid on the wire but exceeds the classic 254-byte host name bound
    /// is rejected and canon keeps its previous value.
    ///
    /// # Brief
    /// 1. Builds an answer with CNAME -> first.example.com followed by
    ///    CNAME -> a 304-character name (five 60-byte labels, hand-crafted
    ///    on the wire because the encoder caps names at 253).
    /// 2. Verifies the oversized target is dropped and canon keeps the
    ///    first valid target.
    #[test]
    fn ut_parse_response_cname_validity() {
        let mut msg = Vec::new();
        msg.extend(0x0506u16.to_be_bytes());
        msg.extend(FLAG_QR.to_be_bytes()); // QR, NOERROR
        msg.extend(1u16.to_be_bytes()); // qdcount
        msg.extend(2u16.to_be_bytes()); // ancount
        msg.extend([0, 0, 0, 0]); // nscount/arcount
        encode_name(&mut msg, "www.example.com").unwrap();
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        // answer 1: CNAME -> first.example.com (valid)
        msg.extend([0xC0, 0x0C]);
        msg.extend(TYPE_CNAME.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        let mut rdata = Vec::new();
        encode_name(&mut rdata, "first.example.com").unwrap();
        msg.extend((rdata.len() as u16).to_be_bytes());
        msg.extend(rdata);
        // answer 2: CNAME -> a 304-character name (over the 254 bound),
        // hand-crafted on the wire with legal 60-byte labels.
        msg.extend([0xC0, 0x0C]);
        msg.extend(TYPE_CNAME.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        let mut rdata = Vec::new();
        for _ in 0..5 {
            rdata.push(60u8);
            rdata.extend_from_slice(&[b'x'; 60]);
        }
        rdata.push(0);
        msg.extend((rdata.len() as u16).to_be_bytes());
        msg.extend(rdata);
        match parse_response(&msg) {
            ParseOutcome::Records(parsed) => {
                assert_eq!(parsed.canon.as_deref(), Some("first.example.com"));
            }
            _ => panic!("expected records"),
        }
    }

    /// UT case for parse leniency: transaction ids, QR, opcode and
    /// question names are not validated — a response with a foreign id, a
    /// cleared QR bit, a bad opcode or an unrelated question still parses.
    /// Fewer than 12 bytes stop the walk with an empty record set.
    #[test]
    fn ut_parse_response_lenient_header() {
        let msg = test_response(
            0x1111,
            TEST_NAME,
            TYPE_A,
            &[IpAddr::from([1, 2, 3, 4])],
            false,
            RCODE_NOERROR,
        );
        // Foreign transaction id: still parsed (id matching is the
        // transport layer's job).
        match parse_response(&msg) {
            ParseOutcome::Records(parsed) => assert_eq!(parsed.records.len(), 1),
            _ => panic!("expected records"),
        }
        // Fewer than 12 bytes: empty records, not an error verdict.
        match parse_response(&msg[..8]) {
            ParseOutcome::Records(parsed) => assert!(parsed.records.is_empty()),
            _ => panic!("expected empty records"),
        }
        // QR cleared and bad opcode: the walk still runs (no header checks).
        let mut not_reply = msg.clone();
        not_reply[2] = 0x00;
        assert!(matches!(parse_response(&not_reply), ParseOutcome::Records(_)));
        let mut bad_opcode = msg.clone();
        bad_opcode[2] = 0x08; // opcode 1
        assert!(matches!(parse_response(&bad_opcode), ParseOutcome::Records(_)));
        // Question name mismatch: no check, records still collected.
        assert!(matches!(parse_response(&msg), ParseOutcome::Records(_)));
    }

    /// UT case for rcode handling and the TC bit: the rcode decides the
    /// verdict; TC is NOT special-cased (the TC retry lives in the
    /// transport layer, and a truncated UDP answer rolled back from TCP
    /// still parses its partial record set).
    #[test]
    fn ut_parse_response_rcodes() {
        let truncated = test_response(0x0101, TEST_NAME, TYPE_A, &[], true, RCODE_NOERROR);
        assert!(matches!(parse_response(&truncated), ParseOutcome::Records(_)));
        let nx = test_response(0x0101, TEST_NAME, TYPE_A, &[], false, RCODE_NXDOMAIN);
        assert!(matches!(parse_response(&nx), ParseOutcome::NxDomain));
        let servfail = test_response(0x0101, TEST_NAME, TYPE_A, &[], false, RCODE_SERVFAIL);
        assert!(matches!(parse_response(&servfail), ParseOutcome::Unusable));
        let other = test_response(0x0101, TEST_NAME, TYPE_A, &[], false, 4);
        assert!(matches!(parse_response(&other), ParseOutcome::Unusable));
    }

    /// UT case for the compression-pointer loop guard
    /// (`MAX_NAME_JUMPS`): a self-referential name pointer must stop the
    /// walk instead of looping forever; the empty record set is kept.
    #[test]
    fn ut_parse_response_pointer_loop() {
        let mut msg = Vec::new();
        msg.extend(0x0102u16.to_be_bytes()); // id
        msg.extend(FLAG_QR.to_be_bytes()); // QR=1, opcode 0, rcode 0
        msg.extend(1u16.to_be_bytes()); // qdcount
        msg.extend([0, 0, 0, 0]); // nscount/arcount
        msg.extend([0xC0, 0x0C]); // question name: pointer to itself
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        match parse_response(&msg) {
            ParseOutcome::Records(parsed) => assert!(parsed.records.is_empty()),
            _ => panic!("expected empty records"),
        }
    }

    /// UT case for a truncated record: an answer record cut off mid-rdata
    /// stops the walk; records parsed before it are kept.
    #[test]
    fn ut_parse_response_partial_record_kept() {
        let mut msg = Vec::new();
        msg.extend(0x0708u16.to_be_bytes());
        msg.extend(FLAG_QR.to_be_bytes()); // QR, NOERROR
        msg.extend(1u16.to_be_bytes()); // qdcount
        msg.extend(2u16.to_be_bytes()); // ancount (2 claimed, 2nd truncated)
        msg.extend([0, 0, 0, 0]);
        encode_name(&mut msg, "example.com").unwrap();
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        // Complete first record.
        msg.extend([0xC0, 0x0C]);
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        msg.extend(4u16.to_be_bytes());
        msg.extend([10, 0, 0, 1]);
        // Second record truncated mid-rdata: rdlength 4, only 2 bytes left.
        msg.extend([0xC0, 0x0C]);
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        msg.extend(4u16.to_be_bytes());
        msg.extend([10, 0]);
        match parse_response(&msg) {
            ParseOutcome::Records(parsed) => {
                assert_eq!(parsed.records, vec![(IpAddr::from([10, 0, 0, 1]), 60)]);
            }
            _ => panic!("expected records"),
        }
    }

    /// UT case for the collected-address cap: parsing stops at
    /// `MAX_ADDRS` even when the answer carries more records.
    #[test]
    fn ut_parse_response_caps_at_maxaddrs() {
        let addrs: Vec<IpAddr> =
            (0..60u8).map(|i| IpAddr::from([10, 0, 0, i])).collect();
        let msg = test_response(0x0101, TEST_NAME, TYPE_A, &addrs, false, RCODE_NOERROR);
        match parse_response(&msg) {
            ParseOutcome::Records(parsed) => assert_eq!(parsed.records.len(), MAX_ADDRS),
            _ => panic!("expected records"),
        }
    }

    // Conformance vectors borrowed from public industry sources. Vectors
    // are data excerpts with attribution, not ported code: RFC 1035
    // Section 4.1.4 (IETF spec text, freely reproducible) and hickory-proto
    // `crates/proto/src/rr/domain/name.rs` tests (hickory-dns, MIT OR
    // Apache-2.0).

    /// Conformance vector: the four names tabulated in RFC 1035 Section
    /// 4.1.4 at offsets 20/40/64/92.
    ///
    /// # Brief
    /// 1. Encodes the RFC byte table into a 93-byte buffer (the gaps
    ///    between the four names are zero filler).
    /// 2. Parses each name at its RFC offset: plain labels, a pointer to a
    ///    prior name (offset 20), a pointer to a mid-name label (offset 26,
    ///    sanctioned by the RFC) and the root.
    #[test]
    fn ut_conformance_rfc1035_4_1_4_name_table() {
        let mut buf = vec![0u8; 93];
        buf[20..32].copy_from_slice(&[
            0x01, b'F', 0x03, b'I', b'S', b'I', 0x04, b'A', b'R', b'P', b'A', 0x00,
        ]);
        buf[40..46].copy_from_slice(&[0x03, b'F', b'O', b'O', 0xC0, 0x14]);
        buf[64..66].copy_from_slice(&[0xC0, 0x1A]);
        buf[92] = 0x00;
        let at = |pos: usize| {
            let mut parser = DnsParser { msg: &buf, pos };
            parser.name()
        };
        assert_eq!(at(20).as_deref(), Some("F.ISI.ARPA"));
        assert_eq!(at(40).as_deref(), Some("FOO.F.ISI.ARPA"));
        assert_eq!(at(64).as_deref(), Some("ARPA"));
        assert_eq!(at(92).as_deref(), Some(""));
    }

    /// Conformance vector: the four-name compression sequence asserted by
    /// hickory-proto `test_pointer` (name lengths 10/12/14/18 sharing
    /// suffixes through pointers).
    ///
    /// # Brief
    /// 1. Encodes "ra.rb.rc" verbatim, then three names that compress into
    ///    it, matching hickory's byte counts.
    /// 2. Checks every expansion.
    #[test]
    fn ut_conformance_hickory_pointer_chain() {
        let buf: &[u8] = &[
            0x02, b'r', b'a', 0x02, b'r', b'b', 0x02, b'r', b'c', 0x00, // ra.rb.rc
            0xC0, 0x03, // rb.rc (pointer to "rb" at 3)
            0xC0, 0x06, // rc (pointer to "rc" at 6)
            0x01, b'z', 0xC0, 0x00, // z.ra.rb.rc (pointer to the first name)
        ];
        let at = |pos: usize| {
            let mut parser = DnsParser { msg: buf, pos };
            parser.name()
        };
        assert_eq!(at(0).as_deref(), Some("ra.rb.rc"));
        assert_eq!(at(10).as_deref(), Some("rb.rc"));
        assert_eq!(at(12).as_deref(), Some("rc"));
        assert_eq!(at(14).as_deref(), Some("z.ra.rb.rc"));
    }

    /// Conformance vector: the four rejected malformed names from
    /// hickory-proto `test_recursive_pointer`.
    ///
    /// # Brief
    /// 1. Replays the dangling-pointer, self-loop, label-plus-cycle and
    ///    forward-pointer byte vectors.
    /// 2. All must fail; our parser rejects them via the strict-backward
    ///    pointer rule and the jump-count bound.
    #[test]
    fn ut_conformance_hickory_recursive_pointers() {
        let cases: [&[u8]; 4] = [
            &[0xC0, 0x01],           // pointer into its own low byte
            &[0xC0, 0x00],           // pointer to itself
            &[0x01, 0x41, 0xC0, 0x00], // 'A' + self-referencing pointer cycle
            &[0xC0, 0x02, 0xC0, 0x00], // forward pointer, then back to 0
        ];
        for msg in cases {
            let mut parser = DnsParser { msg, pos: 0 };
            assert!(parser.name().is_none());
        }
    }

    /// Conformance vector: header-rcode decisions (RFC 1035 Section 4.1.1):
    /// NXDOMAIN, SERVFAIL and empty NOERROR.
    #[test]
    fn ut_conformance_header_rcodes() {
        let header = |rcode: u8, ancount: u8| {
            [0x00, 0x00, 0x81, rcode, 0x00, 0x01, 0x00, ancount, 0x00, 0x00, 0x00, 0x00]
        };
        let ParseOutcome::Records(answer) = parse_response(&header(0, 0)) else {
            panic!("empty NOERROR answer must parse");
        };
        assert!(answer.records.is_empty());
        assert!(answer.canon.is_none());
        assert!(matches!(parse_response(&header(3, 0)), ParseOutcome::NxDomain));
        assert!(matches!(parse_response(&header(2, 0)), ParseOutcome::Unusable));
    }

    /// Conformance vector: the classic answer shape every real reply uses —
    /// the owner name compressed to the question name at offset 12 (RFC
    /// 1035 Sections 4.1.2/4.1.3/4.1.4 combined); rdata is a documentation
    /// address (RFC 5737).
    #[test]
    fn ut_conformance_compressed_owner_a() {
        let msg: &[u8] = &[
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x01, b'a', 0x01, b'b', 0x00, // qname at 12
            0x00, 0x01, 0x00, 0x01, // qtype A, qclass IN
            0xC0, 0x0C, // answer owner = pointer to qname
            0x00, 0x01, 0x00, 0x01, // type A, class IN
            0x00, 0x00, 0x00, 0x0A, // ttl 10
            0x00, 0x04, 192, 0, 2, 1, // rdlength 4, 192.0.2.1
        ];
        let ParseOutcome::Records(answer) = parse_response(msg) else {
            panic!("A answer must parse");
        };
        assert_eq!(answer.records, vec![(IpAddr::from([192, 0, 2, 1]), 10)]);
        assert!(answer.canon.is_none());
    }

    /// Conformance vector: CNAME chain (RFC 1035 Section 3.3.1) with the
    /// alias answer's owner compressed into the CNAME rdata.
    #[test]
    fn ut_conformance_cname_chain() {
        let msg: &[u8] = &[
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            // question: www.example.com A IN
            0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03,
            b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
            // answer 1: www.example.com CNAME alias.example.com, ttl 3600
            0xC0, 0x0C,
            0x00, 0x05, 0x00, 0x01,
            0x00, 0x00, 0x0E, 0x10,
            0x00, 0x08, 0x05, b'a', b'l', b'i', b'a', b's', 0xC0, 0x10,
            // answer 2: owner compressed into the CNAME rdata at offset 45
            0xC0, 0x2D,
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x05,
            0x00, 0x04, 192, 0, 2, 2, // 192.0.2.2
        ];
        let ParseOutcome::Records(answer) = parse_response(msg) else {
            panic!("CNAME chain must parse");
        };
        assert_eq!(answer.canon.as_deref(), Some("alias.example.com"));
        assert_eq!(answer.records, vec![(IpAddr::from([192, 0, 2, 2]), 5)]);
    }

    // Boundary vectors modeled on the parse edge cases exercised by
    // c-ares `ares_parse_*` and hickory-proto message tests (both reviewed
    // for behaviors; vectors below are constructed, not excerpted). They
    // pin the musl-shaped leniency: the header rcode decides the verdict,
    // the record walk collects what it can, and short or malformed
    // trailing data never panics.

    /// Boundary: NXDOMAIN carrying answer records — the rcode decides
    /// BEFORE the walk (musl `__dns_parse` returns early on rcode != 0),
    /// so the attached records are NOT collected.
    #[test]
    fn ut_parse_response_nxdomain_with_records() {
        let mut msg = Vec::new();
        msg.extend(0x0102u16.to_be_bytes());
        msg.extend((FLAG_QR | RCODE_NXDOMAIN).to_be_bytes()); // QR, rcode 3
        msg.extend(1u16.to_be_bytes()); // qdcount
        msg.extend(1u16.to_be_bytes()); // ancount (record attached anyway)
        msg.extend([0, 0, 0, 0]);
        encode_name(&mut msg, "missing.example.com").unwrap();
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend([0xC0, 0x0C]);
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        msg.extend(4u16.to_be_bytes());
        msg.extend([10, 0, 0, 1]);
        assert!(matches!(parse_response(&msg), ParseOutcome::NxDomain));
    }

    /// Boundary: only records of class IN are collected; a CH-class
    /// record (the classic CHAOS TXT example) is skipped like musl's
    /// `dns_parse_callback` fallthrough, and the walk continues.
    #[test]
    fn ut_parse_response_non_in_class_skipped() {
        let mut msg = Vec::new();
        msg.extend(0x0102u16.to_be_bytes());
        msg.extend(FLAG_QR.to_be_bytes()); // QR, NOERROR
        msg.extend(1u16.to_be_bytes()); // qdcount
        msg.extend(2u16.to_be_bytes()); // ancount
        msg.extend([0, 0, 0, 0]);
        encode_name(&mut msg, "example.com").unwrap();
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        // answer 1: A, class CH (3) — skipped.
        msg.extend([0xC0, 0x0C]);
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(3u16.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        msg.extend(4u16.to_be_bytes());
        msg.extend([10, 0, 0, 1]);
        // answer 2: A, class IN — collected.
        msg.extend([0xC0, 0x0C]);
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        msg.extend(4u16.to_be_bytes());
        msg.extend([10, 0, 0, 2]);
        match parse_response(&msg) {
            ParseOutcome::Records(parsed) => {
                assert_eq!(parsed.records, vec![(IpAddr::from([10, 0, 0, 2]), 60)]);
            }
            _ => panic!("expected records"),
        }
    }

    /// Boundary: unknown record types (RFC 3597, e.g. the OPT pseudo-record
    /// type 41 or a private type 65280) are skipped without disturbing the
    /// walk; neighboring A records are still collected.
    #[test]
    fn ut_parse_response_unknown_type_skipped() {
        let mut msg = Vec::new();
        msg.extend(0x0102u16.to_be_bytes());
        msg.extend(FLAG_QR.to_be_bytes()); // QR, NOERROR
        msg.extend(1u16.to_be_bytes()); // qdcount
        msg.extend(2u16.to_be_bytes()); // ancount
        msg.extend([0, 0, 0, 0]);
        encode_name(&mut msg, "example.com").unwrap();
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        // answer 1: OPT (41), rdata 1 byte — skipped.
        msg.extend([0xC0, 0x0C]);
        msg.extend(41u16.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(0u32.to_be_bytes());
        msg.extend(1u16.to_be_bytes());
        msg.extend([0]);
        // answer 2: A — collected.
        msg.extend([0xC0, 0x0C]);
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        msg.extend(4u16.to_be_bytes());
        msg.extend([10, 0, 0, 3]);
        match parse_response(&msg) {
            ParseOutcome::Records(parsed) => {
                assert_eq!(parsed.records, vec![(IpAddr::from([10, 0, 0, 3]), 60)]);
            }
            _ => panic!("expected records"),
        }
    }

    /// Boundary: `ancount` claims more records than the message carries —
    /// the walk stops at the end of the message and keeps the records
    /// parsed so far (musl's caller ignores `__dns_parse`'s error).
    #[test]
    fn ut_parse_response_ancount_overrun() {
        let mut msg = Vec::new();
        msg.extend(0x0102u16.to_be_bytes());
        msg.extend(FLAG_QR.to_be_bytes()); // QR, NOERROR
        msg.extend(1u16.to_be_bytes()); // qdcount
        msg.extend(5u16.to_be_bytes()); // ancount: 5 claimed...
        msg.extend([0, 0, 0, 0]);
        encode_name(&mut msg, "example.com").unwrap();
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        // ...only 1 record present, message ends right after it.
        msg.extend([0xC0, 0x0C]);
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        msg.extend(4u16.to_be_bytes());
        msg.extend([10, 0, 0, 4]);
        match parse_response(&msg) {
            ParseOutcome::Records(parsed) => {
                assert_eq!(parsed.records, vec![(IpAddr::from([10, 0, 0, 4]), 60)]);
            }
            _ => panic!("expected records"),
        }
    }

    /// Boundary: an A record with a malformed rdlength (0 or 3 bytes) is
    /// skipped; the walk continues and later valid records are collected.
    #[test]
    fn ut_parse_response_bad_rdlength_skipped() {
        let mut msg = Vec::new();
        msg.extend(0x0102u16.to_be_bytes());
        msg.extend(FLAG_QR.to_be_bytes()); // QR, NOERROR
        msg.extend(1u16.to_be_bytes()); // qdcount
        msg.extend(3u16.to_be_bytes()); // ancount
        msg.extend([0, 0, 0, 0]);
        encode_name(&mut msg, "example.com").unwrap();
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        // answer 1: A with rdlength 0 — skipped.
        msg.extend([0xC0, 0x0C]);
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        msg.extend(0u16.to_be_bytes());
        // answer 2: A with rdlength 3 — skipped.
        msg.extend([0xC0, 0x0C]);
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        msg.extend(3u16.to_be_bytes());
        msg.extend([10, 0, 0]);
        // answer 3: A with rdlength 4 — collected.
        msg.extend([0xC0, 0x0C]);
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        msg.extend(4u16.to_be_bytes());
        msg.extend([10, 0, 0, 5]);
        match parse_response(&msg) {
            ParseOutcome::Records(parsed) => {
                assert_eq!(parsed.records, vec![(IpAddr::from([10, 0, 0, 5]), 60)]);
            }
            _ => panic!("expected records"),
        }
    }

    /// Boundary: the maximum TTL (u32::MAX) survives parsing unchanged.
    #[test]
    fn ut_parse_response_ttl_max() {
        let mut msg = Vec::new();
        msg.extend(0x0102u16.to_be_bytes());
        msg.extend(FLAG_QR.to_be_bytes()); // QR, NOERROR
        msg.extend(1u16.to_be_bytes()); // qdcount
        msg.extend(1u16.to_be_bytes()); // ancount
        msg.extend([0, 0, 0, 0]);
        encode_name(&mut msg, "example.com").unwrap();
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend([0xC0, 0x0C]);
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(u32::MAX.to_be_bytes());
        msg.extend(4u16.to_be_bytes());
        msg.extend([10, 0, 0, 6]);
        match parse_response(&msg) {
            ParseOutcome::Records(parsed) => {
                assert_eq!(parsed.records, vec![(IpAddr::from([10, 0, 0, 6]), u32::MAX)]);
            }
            _ => panic!("expected records"),
        }
    }

    /// Boundary: wire names are case-preserving (RFC 1035 Section 2.3.3,
    /// RFC 4343) — the parser must not fold the case of addresses or CNAME
    /// targets; matching stays case-sensitive upstream.
    #[test]
    fn ut_parse_response_case_preserved() {
        let mut msg = Vec::new();
        msg.extend(0x0102u16.to_be_bytes());
        msg.extend(FLAG_QR.to_be_bytes()); // QR, NOERROR
        msg.extend(1u16.to_be_bytes()); // qdcount
        msg.extend(1u16.to_be_bytes()); // ancount
        msg.extend([0, 0, 0, 0]);
        // question: WWW.EXAMPLE.COM A
        encode_name(&mut msg, "WWW.EXAMPLE.COM").unwrap();
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        // answer: CNAME WWW.EXAMPLE.COM -> Alias.Example.COM
        msg.extend([0xC0, 0x0C]);
        msg.extend(TYPE_CNAME.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        let mut rdata = Vec::new();
        encode_name(&mut rdata, "Alias.Example.COM").unwrap();
        msg.extend((rdata.len() as u16).to_be_bytes());
        msg.extend(rdata);
        match parse_response(&msg) {
            ParseOutcome::Records(parsed) => {
                assert_eq!(parsed.canon.as_deref(), Some("Alias.Example.COM"));
            }
            _ => panic!("expected records"),
        }
    }

    /// Boundary: QDCOUNT = 0 with the answer section directly after the
    /// header — the walk skips no questions and collects normally.
    #[test]
    fn ut_parse_response_qdcount_zero() {
        let mut msg = Vec::new();
        msg.extend(0x0102u16.to_be_bytes());
        msg.extend(FLAG_QR.to_be_bytes()); // QR, NOERROR
        msg.extend(0u16.to_be_bytes()); // qdcount
        msg.extend(1u16.to_be_bytes()); // ancount
        msg.extend([0, 0, 0, 0]);
        encode_name(&mut msg, "example.com").unwrap();
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        msg.extend(4u16.to_be_bytes());
        msg.extend([10, 0, 0, 7]);
        match parse_response(&msg) {
            ParseOutcome::Records(parsed) => {
                assert_eq!(parsed.records, vec![(IpAddr::from([10, 0, 0, 7]), 60)]);
            }
            _ => panic!("expected records"),
        }
    }

    /// Boundary: trailing bytes after the last record are ignored — the
    /// walk reads exactly `ancount` records.
    #[test]
    fn ut_parse_response_trailing_bytes_ignored() {
        let mut msg = Vec::new();
        msg.extend(0x0102u16.to_be_bytes());
        msg.extend(FLAG_QR.to_be_bytes()); // QR, NOERROR
        msg.extend(1u16.to_be_bytes()); // qdcount
        msg.extend(1u16.to_be_bytes()); // ancount
        msg.extend([0, 0, 0, 0]);
        encode_name(&mut msg, "example.com").unwrap();
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend([0xC0, 0x0C]);
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        msg.extend(4u16.to_be_bytes());
        msg.extend([10, 0, 0, 8]);
        // Trailing garbage of a past reply must not disturb the parse.
        msg.extend([0xDE, 0xAD, 0xBE, 0xEF]);
        match parse_response(&msg) {
            ParseOutcome::Records(parsed) => {
                assert_eq!(parsed.records, vec![(IpAddr::from([10, 0, 0, 8]), 60)]);
            }
            _ => panic!("expected records"),
        }
    }

    /// Boundary: a single-label name ("localhost") and the root name as a
    /// CNAME target — single labels encode and parse; the root is rejected
    /// as a canon target.
    #[test]
    fn ut_parse_response_single_label_and_root() {
        // Single-label answer roundtrip.
        let mut msg = Vec::new();
        msg.extend(0x0102u16.to_be_bytes());
        msg.extend(FLAG_QR.to_be_bytes()); // QR, NOERROR
        msg.extend(1u16.to_be_bytes()); // qdcount
        msg.extend(1u16.to_be_bytes()); // ancount
        msg.extend([0, 0, 0, 0]);
        encode_name(&mut msg, "localhost").unwrap();
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend([0xC0, 0x0C]);
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        msg.extend(4u16.to_be_bytes());
        msg.extend([127, 0, 0, 1]);
        match parse_response(&msg) {
            ParseOutcome::Records(parsed) => {
                assert_eq!(parsed.records, vec![(IpAddr::from([127, 0, 0, 1]), 60)]);
            }
            _ => panic!("expected records"),
        }
        // A CNAME target of the root is rejected: canon stays empty.
        let mut msg = Vec::new();
        msg.extend(0x0103u16.to_be_bytes());
        msg.extend(FLAG_QR.to_be_bytes()); // QR, NOERROR
        msg.extend(1u16.to_be_bytes()); // qdcount
        msg.extend(1u16.to_be_bytes()); // ancount
        msg.extend([0, 0, 0, 0]);
        encode_name(&mut msg, "example.com").unwrap();
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend([0xC0, 0x0C]);
        msg.extend(TYPE_CNAME.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        msg.extend(1u16.to_be_bytes());
        msg.extend([0]); // root rdata
        match parse_response(&msg) {
            ParseOutcome::Records(parsed) => {
                assert!(parsed.canon.is_none());
            }
            _ => panic!("expected records"),
        }
    }

    /// Conformance vector: a two-hop compression chain — a name whose
    /// pointer targets another pointer, each pointing strictly backwards
    /// (the shape hickory-proto's pointer tests exercise). Resolution
    /// follows both hops and reports the final labels.
    #[test]
    fn ut_conformance_two_hop_pointer() {
        let buf: &[u8] = &[
            0x01, b'b', 0x01, b'c', 0x00, // "b.c" at 0
            0xC0, 0x02, // "c" at 5 (pointer to the "c" label at 2)
            0xC0, 0x05, // "c" at 7 (pointer to the pointer at 5)
        ];
        let at = |pos: usize| {
            let mut parser = DnsParser { msg: buf, pos };
            parser.name()
        };
        assert_eq!(at(0).as_deref(), Some("b.c"));
        assert_eq!(at(5).as_deref(), Some("c"));
        assert_eq!(at(7).as_deref(), Some("c"));
    }

    /// Boundary: the parser itself has no textual name-length bound
    /// (mirroring musl `dn_expand`) — a structurally valid wire name whose
    /// textual form is 304 characters parses, but the classic host-name
    /// validity rule (1..=254 bytes) rejects it as a canon target, so
    /// canon stays empty. (The wire name is hand-crafted with legal
    /// 60-byte labels; the encoder caps names at 253.)
    #[test]
    fn ut_parse_response_cname_over_length_target() {
        let mut msg = Vec::new();
        msg.extend(0x0102u16.to_be_bytes());
        msg.extend(FLAG_QR.to_be_bytes()); // QR, NOERROR
        msg.extend(1u16.to_be_bytes()); // qdcount
        msg.extend(1u16.to_be_bytes()); // ancount
        msg.extend([0, 0, 0, 0]);
        encode_name(&mut msg, "example.com").unwrap();
        msg.extend(TYPE_A.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend([0xC0, 0x0C]);
        msg.extend(TYPE_CNAME.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        let mut rdata = Vec::new();
        for _ in 0..5 {
            rdata.push(60u8);
            rdata.extend_from_slice(&[b'x'; 60]);
        }
        rdata.push(0);
        msg.extend((rdata.len() as u16).to_be_bytes());
        msg.extend(rdata);
        match parse_response(&msg) {
            ParseOutcome::Records(parsed) => {
                assert!(parsed.canon.is_none());
            }
            _ => panic!("expected records"),
        }
    }

    /// Boundary: a 63-byte label (the wire maximum) round-trips through
    /// encode and parse.
    #[test]
    fn ut_conformance_max_label_roundtrip() {
        let name = format!("{}.example.com", "m".repeat(63));
        let mut wire = Vec::new();
        encode_name(&mut wire, &name).unwrap();
        let mut parser = DnsParser { msg: &wire, pos: 0 };
        assert_eq!(parser.name().as_deref(), Some(name.as_str()));
        // One byte over the label maximum is rejected on encode.
        let mut out = Vec::new();
        assert!(encode_name(&mut out, &format!("{}.example.com", "m".repeat(64))).is_err());
    }

    /// UT case for `skip_name`: it accepts exactly the byte sequences
    /// `name` accepts, leaves the cursor in the same place, and builds no
    /// text (the allocation-free walk used for question and owner names).
    #[test]
    fn ut_skip_name_matches_name() {
        let mut wire = Vec::new();
        encode_name(&mut wire, "a.b.c").unwrap();
        // A compressed name pointing into the first one ("b.c").
        wire.extend([0xC0, 0x02]);

        let mut parser = DnsParser { msg: &wire, pos: 0 };
        assert_eq!(parser.name().as_deref(), Some("a.b.c"));
        let plain_end = parser.pos;
        let compressed_text = parser.name().unwrap();
        assert_eq!(compressed_text, "b.c");
        let compressed_end = parser.pos;

        let mut parser = DnsParser { msg: &wire, pos: 0 };
        parser.skip_name().unwrap();
        assert_eq!(parser.pos, plain_end);
        parser.skip_name().unwrap();
        assert_eq!(parser.pos, compressed_end);

        // The forward-pointer rejection is shared, too: a pointer at the
        // first byte cannot point backwards.
        let forward: &[u8] = &[0xC0, 0x02, 0x00];
        let mut parser = DnsParser { msg: forward, pos: 0 };
        assert!(parser.skip_name().is_none());
    }

    /// UT case for the transactional `build_query` contract: an unparsable
    /// name leaves the caller's buffer untouched.
    #[test]
    fn ut_build_query_transactional() {
        let mut out = Vec::new();
        out.extend_from_slice(b"prefix");
        assert!(build_query(&mut out, 0x1234, TYPE_A, "a..b").is_err());
        assert_eq!(out, b"prefix");
        // The successful path appends exactly the reserved wire size:
        // 16 fixed bytes plus the 5-byte encoded name.
        assert!(build_query(&mut out, 0x1234, TYPE_A, "a.b").is_ok());
        assert_eq!(out.len(), b"prefix".len() + 16 + 5);
    }
}
