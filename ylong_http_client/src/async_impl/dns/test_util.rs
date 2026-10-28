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

//! Shared test helpers for the DNS modules: a canned response builder and
//! mock-server reply helpers used by both the UT and SDV suites. Compiled
//! only under `cfg(test)` together with the owner-aware resolver gate.

use std::net::IpAddr;

use super::wire::{encode_name, CLASS_IN, FLAG_QR, FLAG_TC, TYPE_CNAME};

/// Fixed question name of the canned [`test_response`] builder.
pub(super) const TEST_NAME: &str = "owner.vpn.test";

/// Builds a well-formed DNS response for tests: question echo followed
/// by one answer record per address, owner names compressed to the
/// question name.
pub(super) fn test_response(
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

/// Builds the response a mock server sends back for one query: echoes
/// the transaction id and the question type of the received query, with
/// the fixed [`TEST_NAME`] question name.
pub(super) fn mock_reply(query: &[u8], addrs: &[IpAddr], truncated: bool, rcode: u16) -> Vec<u8> {
    let id = u16::from_be_bytes([query[0], query[1]]);
    let qtype = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
    test_response(id, TEST_NAME, qtype, addrs, truncated, rcode)
}

/// Decodes the question name of a received query (labels until the root
/// label), for asserting which candidate names hit the wire.
pub(super) fn qname_of(query: &[u8]) -> String {
    let mut labels = Vec::new();
    let mut i = 12; // header
    while i < query.len() && query[i] != 0 {
        let len = query[i] as usize;
        labels.push(String::from_utf8_lossy(&query[i + 1..i + 1 + len]).into_owned());
        i += 1 + len;
    }
    labels.join(".")
}

/// Like [`mock_reply`], but echoes the question name of the received
/// query instead of the fixed `TEST_NAME` (needed for search-expanded
/// candidate names).
pub(super) fn mock_reply_echo(
    query: &[u8],
    addrs: &[IpAddr],
    truncated: bool,
    rcode: u16,
) -> Vec<u8> {
    let id = u16::from_be_bytes([query[0], query[1]]);
    let qtype = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
    let name = qname_of(query);
    test_response(id, &name, qtype, addrs, truncated, rcode)
}

/// Builds a NOERROR reply carrying a single CNAME record from the
/// received query's question name to `target` (no address records), for
/// the bare-name chase test.
pub(super) fn mock_reply_cname(query: &[u8], target: &str) -> Vec<u8> {
    let id = u16::from_be_bytes([query[0], query[1]]);
    let qtype = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
    let name = qname_of(query);
    let mut msg = Vec::new();
    msg.extend(id.to_be_bytes());
    msg.extend(FLAG_QR.to_be_bytes()); // QR, opcode 0, rcode 0
    msg.extend(1u16.to_be_bytes()); // qdcount
    msg.extend(1u16.to_be_bytes()); // ancount
    msg.extend([0, 0, 0, 0]); // nscount/arcount
    encode_name(&mut msg, &name).unwrap();
    msg.extend(qtype.to_be_bytes());
    msg.extend(CLASS_IN.to_be_bytes());
    // Answer: CNAME <name> -> <target>, owner compressed to the question.
    msg.extend([0xC0, 0x0C]);
    msg.extend(TYPE_CNAME.to_be_bytes());
    msg.extend(CLASS_IN.to_be_bytes());
    msg.extend(60u32.to_be_bytes()); // ttl
    let mut rdata = Vec::new();
    encode_name(&mut rdata, target).unwrap();
    msg.extend((rdata.len() as u16).to_be_bytes());
    msg.extend(rdata);
    msg
}
