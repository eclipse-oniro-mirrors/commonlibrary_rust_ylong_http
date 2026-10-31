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

//! Query building for the DNS exchange: the A/AAAA query pair sent for
//! one candidate name, plus the transaction-id generator. The wire-format
//! encoding itself lives in the `ylong_http` DNS codec ([`super::wire`]).

use std::io;

use super::wire::{build_query, TYPE_A, TYPE_AAAA};

/// Prebuilt A and AAAA queries for one candidate name. The two transaction
/// IDs always differ (musl ensures the same, `lookup_name.c` L357-359).
pub(super) struct DualQuery {
    pub(super) id_aaaa: u16,
    pub(super) id_a: u16,
    pub(super) query_aaaa: Vec<u8>,
    pub(super) query_a: Vec<u8>,
}

impl DualQuery {
    pub(super) fn build(name: &str) -> io::Result<Self> {
        let id_aaaa = random_txid();
        let mut id_a = random_txid();
        while id_a == id_aaaa {
            id_a = random_txid();
        }
        // Exact wire size, so the builder never reallocates: 16 fixed
        // bytes (header, qtype, qclass) plus the encoded name — one
        // length byte per label (one per dot) plus the root terminator.
        let capacity = name.len() + name.matches('.').count() + 18;
        let mut query_aaaa = Vec::with_capacity(capacity);
        build_query(&mut query_aaaa, id_aaaa, TYPE_AAAA, name)?;
        let mut query_a = Vec::with_capacity(capacity);
        build_query(&mut query_a, id_a, TYPE_A, name)?;
        Ok(DualQuery {
            id_aaaa,
            id_a,
            query_aaaa,
            query_a,
        })
    }
}

/// Generates a random 16-bit transaction ID from per-instance hash seeds.
/// Combined with the fresh OS-assigned source port of every attempt this
/// matches the (weak but practical) randomization of system resolvers.
fn random_txid() -> u16 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    (RandomState::new().build_hasher().finish() & 0xFFFF) as u16
}

#[cfg(test)]
mod ut_test {
    use super::super::wire::FLAG_RD;
    use super::*;

    /// UT case for `DualQuery::build`: both families carry the
    /// recursion-desired flag (musl `__res_mkquery` sets RD,
    /// `res_mkquery.c` L23) and two distinct transaction IDs (musl ensures
    /// the same, `lookup_name.c` L357-359).
    ///
    /// # Brief
    /// 1. Builds the A/AAAA pair for "example.com".
    /// 2. Verifies RD on both queries, distinct ids and the question tails.
    #[test]
    fn ut_build_dual_query() {
        let query = DualQuery::build("example.com").unwrap();
        assert_eq!(&query.query_aaaa[2..4], &FLAG_RD.to_be_bytes());
        assert_eq!(&query.query_a[2..4], &FLAG_RD.to_be_bytes());
        assert_ne!(query.id_aaaa, query.id_a);
        // Question tail: qtype then qclass.
        let qtype =
            |q: &[u8]| u16::from_be_bytes([q[q.len() - 4], q[q.len() - 3]]);
        assert_eq!(qtype(&query.query_aaaa), TYPE_AAAA);
        assert_eq!(qtype(&query.query_a), TYPE_A);
    }

    /// UT case for `random_txid`: two consecutive ids are independent
    /// (collision is possible but astronomically unlikely to repeat the
    /// full 16 bits in a short sequence).
    #[test]
    fn ut_random_txid() {
        let first = random_txid();
        let mut differs = false;
        for _ in 0..16 {
            if random_txid() != first {
                differs = true;
                break;
            }
        }
        assert!(differs);
    }
}
