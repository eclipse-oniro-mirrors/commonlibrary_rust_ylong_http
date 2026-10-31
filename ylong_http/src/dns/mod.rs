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

//! [DNS] wire-format codec: building standard queries and parsing
//! responses on the wire.
//!
//! [DNS]: https://datatracker.ietf.org/doc/html/rfc1035
//!
//! # Introduction
//! The Domain Name System ([RFC 1035]) carries queries and answers in a
//! binary message format: a fixed 12-byte header, a question section and
//! resource records ([RFC 1035]). IPv6 lookups extend the record set with
//! the AAAA type ([RFC 3596]). This module implements the protocol pieces
//! an HTTP client needs to speak DNS directly over UDP or TCP: encoding a
//! standard recursive query for one name and type, and decoding a
//! response into its address records and CNAME chains.
//!
//! The implementation is pure: no I/O, no runtime and no dependencies.
//! The parser is deliberately lenient — the header rcode decides the
//! verdict, and the record walk collects what it can without validating
//! transaction ids, flags or question sections, so a transport layer can
//! apply its own acceptance policy on top (as the `ylong_http_client` DNS
//! exchange does, mirroring the system resolver).
//!
//! [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
//! [RFC 3596]: https://datatracker.ietf.org/doc/html/rfc3596

mod message;

pub use message::{
    build_query, encode_name, parse_response, ParsedAnswer, ParseOutcome, CLASS_IN, FLAG_QR,
    FLAG_RD, FLAG_TC, MAX_ADDRS, RCODE_NOERROR, RCODE_NXDOMAIN, RCODE_SERVFAIL, TYPE_A, TYPE_AAAA,
    TYPE_CNAME,
};
