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

//! Destination address selection [RFC 6724, Section 6] (obsoleting
//! RFC 3484), ported line-by-line from musl `lookup_name.c` (`addrsort`):
//! policy table, scope/label/prefix rules and the per-address UDP connect
//! probe.
//!
//! [RFC 6724, Section 6]: https://datatracker.ietf.org/doc/html/rfc6724#section-6

use std::net::IpAddr;

use crate::async_impl::dns::wire::MAX_ADDRS;


/// Destination address selection [RFC 6724, Section 6], ported line-by-line
/// from musl `lookup_name.c` so the resolver hands out addresses in the
/// same preference order as system `getaddrinfo`. The policy table
/// [RFC 6724, Section 2.1], the address-property mappings (scope
/// [RFC 6724, Section 3.1]) and the pair-wise rules (musl keeps a subset:
/// rules 3/4/7 omitted for cost) all live in this module:
///
/// - `defpolicy` table: musl L524-540 (the entries musl keeps under `#if 0`
///   are omitted; the last rule matches every address).
/// - `policyof`/`scopeof`/`prefixmatch`: musl L542-578.
/// - Per-address probe: musl L713-730 — one UDP `socket()`/`connect()`/
///   `getsockname()` sequence on the destination. The connect on a datagram
///   socket only fixes the peer and selects a source address; it sends no
///   packet, so the probe is a handful of syscalls with no network I/O.
/// - 31-bit sort key and descending `qsort`: musl L580-592, L679-737. The
///   `MAXADDRS-i` order component makes keys unique, which keeps the
///   collection order on ties; rules 3/4/7 are omitted by musl for cost
///   reasons and stay omitted here.
///
/// Sorting runs only for lists of two or more addresses containing at least
/// one IPv6 address (musl L665-669); an all-IPv4 list keeps collection
/// order, and the combined list is capped at `MAX_ADDRS` the way musl fills
/// its fixed `MAXADDRS` buffer.
///
/// [RFC 6724, Section 2.1]: https://datatracker.ietf.org/doc/html/rfc6724#section-2.1
/// [RFC 6724, Section 3.1]: https://datatracker.ietf.org/doc/html/rfc6724#section-3.1
/// [RFC 6724, Section 6]: https://datatracker.ietf.org/doc/html/rfc6724#section-6
mod addrsort {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::fd::AsRawFd;

    /// Stability component base, aligned with musl `MAXADDRS` (lookup.h)
    /// and this module's `MAX_ADDRS`.
    use super::MAX_ADDRS as MAXADDRS;

    /// Probe outcome, mirroring the three-step musl sequence (L713-730):
    /// `socket()` or `connect()` failure, `getsockname()` failure, success.
    pub(super) enum Probe {
        /// No usable socket for this destination (`DAS_USABLE` unset).
        Unusable,
        /// Connected but no source address read back: usable, without
        /// scope/label/prefix information (musl L717-727).
        UsableNoSource,
        /// Connected, with the kernel-selected source address.
        Usable(IpAddr),
    }

    /// Real probe used at runtime: bind an ephemeral UDP socket in the
    /// destination's family, connect to it (port 65535 mirrors musl L685),
    /// read the source address back.
    ///
    /// `owner` carries the designated socket owner of the resolution: the
    /// probe socket is chown'ed before `connect` so the kernel route
    /// decision — and therefore the source address read back — happens
    /// under the same uid rules as the resolver's own sockets. Without it
    /// the probe would follow the default routing table and rank
    /// destinations against the wrong source address.
    pub(super) fn probe(dest: IpAddr, owner: Option<(u32, u32)>) -> Probe {
        let bind: IpAddr = match dest {
            IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
            IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
        };
        let Ok(sock) = std::net::UdpSocket::bind(SocketAddr::new(bind, 0)) else {
            return Probe::Unusable;
        };
        if let Some((uid, gid)) = owner {
            // SAFETY: `fchown` on an fd this function just created; failure
            // is reported as `Unusable` instead of panicking.
            if unsafe { libc::fchown(sock.as_raw_fd(), uid, gid) } != 0 {
                return Probe::Unusable;
            }
        }
        match sock.connect(SocketAddr::new(dest, 65535)) {
            Err(_) => Probe::Unusable,
            Ok(()) => match sock.local_addr() {
                Err(_) => Probe::UsableNoSource,
                Ok(local) => Probe::Usable(local.ip()),
            },
        }
    }

    /// One `defpolicy` entry (musl L520-523): `addr` holds the prefix bytes,
    /// `len` the byte length to compare, `mask` masks the first byte past
    /// the prefix, `prec`/`label` the RFC 6724 policy values.
    pub(super) struct Policy {
        addr: [u8; 16],
        len: usize,
        mask: u8,
        pub(super) prec: u8,
        pub(super) label: u8,
    }

    /// musl `defpolicy` (L524-540): ::1/128, ::ffff:0:0/96 (IPv4-mapped),
    /// 2002::/16 (6to4), 2001::/32 (Teredo), fc00::/7 (ULA), catch-all.
    const DEFPOLICY: [Policy; 6] = [
        Policy {
            addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            len: 15,
            mask: 0xff,
            prec: 50,
            label: 0,
        },
        Policy {
            addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0],
            len: 11,
            mask: 0xff,
            prec: 35,
            label: 4,
        },
        Policy {
            addr: [0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            len: 1,
            mask: 0xff,
            prec: 30,
            label: 2,
        },
        Policy {
            addr: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            len: 3,
            mask: 0xff,
            prec: 5,
            label: 5,
        },
        Policy {
            addr: [0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            len: 0,
            mask: 0xfe,
            prec: 3,
            label: 13,
        },
        Policy {
            addr: [0; 16],
            len: 0,
            mask: 0,
            prec: 40,
            label: 1,
        },
    ];

    /// `policyof` (musl L542-553): first table entry whose prefix and mask
    /// match. The catch-all entry terminates the scan.
    pub(super) fn policy_of(a: &[u8; 16]) -> &'static Policy {
        for policy in DEFPOLICY.iter() {
            if a[..policy.len] != policy.addr[..policy.len] {
                continue;
            }
            if (a[policy.len] & policy.mask) != policy.addr[policy.len] {
                continue;
            }
            return policy;
        }
        // Unreachable: the last rule matches every address.
        &DEFPOLICY[DEFPOLICY.len() - 1]
    }

    /// `scopeof` (musl L560-567): multicast scope nibble, link-local 2,
    /// loopback 2, site-local 5, everything else 14 (global).
    pub(super) fn scope_of(a: &[u8; 16]) -> u8 {
        if a[0] == 0xff {
            return a[1] & 0x0f;
        }
        if a[0] == 0xfe && (a[1] & 0xc0) == 0x80 {
            return 2; // link-local fe80::/10
        }
        if a[..15].iter().all(|&byte| byte == 0) && a[15] == 1 {
            return 2; // loopback ::1
        }
        if a[0] == 0xfe && (a[1] & 0xc0) == 0xc0 {
            return 5; // site-local fec0::/10
        }
        14
    }

    /// `prefixmatch` (musl L569-578): number of leading bits shared by the
    /// two addresses, capped at 128.
    pub(super) fn prefix_match(s: &[u8; 16], d: &[u8; 16]) -> u32 {
        let mut i = 0;
        while i < 128 && (s[i / 8] ^ d[i / 8]) & (0x80 >> (i % 8)) == 0 {
            i += 1;
        }
        i as u32
    }

    /// Address in the 16-byte form musl computes policy keys on
    /// (musl L693-706): IPv4 goes in as an IPv4-mapped address.
    pub(super) fn to_v6(ip: IpAddr) -> [u8; 16] {
        match ip {
            IpAddr::V6(v6) => v6.octets(),
            IpAddr::V4(v4) => {
                let mut bytes = [0u8; 16];
                bytes[10] = 0xff;
                bytes[11] = 0xff;
                bytes[12..].copy_from_slice(&v4.octets());
                bytes
            }
        }
    }

    /// Sort key bit layout (musl L580-586).
    const DAS_USABLE: u32 = 0x4000_0000;
    const DAS_MATCHING_SCOPE: u32 = 0x2000_0000;
    const DAS_MATCHING_LABEL: u32 = 0x1000_0000;
    const DAS_PREC_SHIFT: u32 = 20;
    const DAS_SCOPE_SHIFT: u32 = 16;
    const DAS_PREFIX_SHIFT: u32 = 8;

    /// 31-bit sort key for one destination (musl L679-736): usability, then
    /// scope/label matches, precedence, destination scope, shared prefix
    /// length and finally the pre-sort index for stability.
    fn sort_key(dest: IpAddr, probed: &dyn Fn(IpAddr) -> Probe, index: usize) -> u32 {
        let da = to_v6(dest);
        let dpolicy = policy_of(&da);
        let dprec = dpolicy.prec;
        let dlabel = dpolicy.label;
        let dscope = scope_of(&da);
        let mut key = 0u32;
        match probed(dest) {
            Probe::Unusable => {}
            Probe::UsableNoSource => key |= DAS_USABLE,
            Probe::Usable(source) => {
                key |= DAS_USABLE;
                let sa = to_v6(source);
                if dscope == scope_of(&sa) {
                    key |= DAS_MATCHING_SCOPE;
                }
                if dlabel == policy_of(&sa).label {
                    key |= DAS_MATCHING_LABEL;
                }
                key |= prefix_match(&sa, &da) << DAS_PREFIX_SHIFT;
            }
        }
        key |= u32::from(dprec) << DAS_PREC_SHIFT;
        key |= u32::from(15 - dscope) << DAS_SCOPE_SHIFT;
        key |= (MAXADDRS - index) as u32;
        key
    }

    /// Sorts `ips` in place the way musl `getaddrinfo` orders its result
    /// before returning it (musl L665-737).
    pub(super) fn sort(ips: &mut Vec<IpAddr>, probed: &dyn Fn(IpAddr) -> Probe) {
        // musl fills a fixed MAXADDRS-sized buffer across both families; the
        // combined list gets the same hard cap.
        ips.truncate(MAXADDRS);
        // No further processing for fewer than 2 results or an all-IPv4 list
        // (musl L665-669).
        if ips.len() < 2 || ips.iter().all(|ip| ip.is_ipv4()) {
            return;
        }
        let mut keyed: Vec<(u32, IpAddr)> = ips
            .drain(..)
            .enumerate()
            .map(|(index, ip)| (sort_key(ip, probed, index), ip))
            .collect();
        // Descending by key; `sort_by_key` with `Reverse` is stable and the
        // order component makes keys unique, matching musl's qsort result.
        keyed.sort_by_key(|&(key, _)| std::cmp::Reverse(key));
        ips.extend(keyed.into_iter().map(|(_, ip)| ip));
    }
}

/// Sorts a collected address list the way musl `getaddrinfo` does before
/// handing it to the caller; see [`addrsort`] for the algorithm and the
/// musl line references. `owner` makes the source probe run under the
/// designated socket owner (see [`addrsort::probe`]); tests inject their
/// own probe closures instead.
pub(super) fn sort_addrs_like_musl(ips: &mut Vec<IpAddr>, owner: Option<(u32, u32)>) {
    addrsort::sort(ips, &|ip| addrsort::probe(ip, owner));
}

#[cfg(test)]
mod ut_test {
    use std::net::{IpAddr, Ipv6Addr};

    use super::*;

    fn probe_usable(source: IpAddr) -> addrsort::Probe {
        addrsort::Probe::Usable(source)
    }

    fn probe_unusable(_ip: IpAddr) -> addrsort::Probe {
        addrsort::Probe::Unusable
    }

    fn sort_with(
        mut ips: Vec<IpAddr>,
        probed: &dyn Fn(IpAddr) -> addrsort::Probe,
    ) -> Vec<IpAddr> {
        addrsort::sort(&mut ips, probed);
        ips
    }

    /// UT case for the RFC 6724 policy table (musl `defpolicy` parity).
    ///
    /// # Brief
    /// 1. Maps representative addresses to (precedence, label) through the
    ///    musl `defpolicy` table.
    /// 2. Verifies loopback, IPv4-mapped, 6to4, Teredo, ULA and catch-all.
    #[test]
    fn ut_addrsort_policy_of() {
        let of = |ip: IpAddr| {
            let policy = addrsort::policy_of(&addrsort::to_v6(ip));
            (policy.prec, policy.label)
        };
        assert_eq!(of("::1".parse().unwrap()), (50, 0));
        assert_eq!(of(IpAddr::from([8, 8, 8, 8])), (35, 4)); // IPv4-mapped
        assert_eq!(of("2002::1".parse().unwrap()), (30, 2)); // 6to4
        assert_eq!(of("2001::1".parse().unwrap()), (5, 5)); // Teredo
        assert_eq!(of("fc00::1".parse().unwrap()), (3, 13)); // ULA
        assert_eq!(of("fdbb::1".parse().unwrap()), (3, 13)); // ULA (fd00::/8)
        assert_eq!(of("2001:db8::1".parse().unwrap()), (40, 1)); // catch-all
        assert_eq!(of("fe80::1".parse().unwrap()), (40, 1)); // catch-all
    }

    /// UT case for `scopeof` parity: multicast nibble, link-local,
    /// loopback, site-local, global.
    #[test]
    fn ut_addrsort_scope_of() {
        let scope = |ip: IpAddr| addrsort::scope_of(&addrsort::to_v6(ip));
        assert_eq!(scope("ff02::1".parse().unwrap()), 2); // multicast, link scope
        assert_eq!(scope("ff0e::1".parse().unwrap()), 14); // multicast, global
        assert_eq!(scope("fe80::1".parse().unwrap()), 2); // link-local
        assert_eq!(scope("::1".parse().unwrap()), 2); // loopback
        assert_eq!(scope("fec0::1".parse().unwrap()), 5); // site-local
        assert_eq!(scope("2001:db8::1".parse().unwrap()), 14); // global
        assert_eq!(scope(IpAddr::from([8, 8, 8, 8])), 14); // v4-mapped = global
    }

    /// UT case for `prefixmatch` parity, including the IPv4-mapped 96-bit
    /// base.
    #[test]
    fn ut_addrsort_prefix_match() {
        let pm = |s: IpAddr, d: IpAddr| {
            addrsort::prefix_match(&addrsort::to_v6(s), &addrsort::to_v6(d))
        };
        assert_eq!(pm("2001:db8::1".parse().unwrap(), "2001:db8::1".parse().unwrap()), 128);
        // ::1 vs ::0 differ only in the last bit (127); ::1 vs ::2 already
        // diverges at bit 1 (126).
        assert_eq!(pm("2001:db8::1".parse().unwrap(), "2001:db8::".parse().unwrap()), 127);
        assert_eq!(pm("2001:db8::1".parse().unwrap(), "2001:db8::2".parse().unwrap()), 126);
        assert_eq!(pm("2001:db8::1".parse().unwrap(), "2400::1".parse().unwrap()), 5);
        assert_eq!(pm(IpAddr::from([10, 0, 0, 1]), IpAddr::from([10, 0, 0, 9])), 124);
        assert_eq!(pm(IpAddr::from([192, 0, 2, 1]), IpAddr::from([8, 8, 8, 8])), 96);
    }

    /// UT case for the sort short-circuit: fewer than 2 addresses or an
    /// all-IPv4 list keeps collection order even when the probe would
    /// reorder (musl L665-669).
    #[test]
    fn ut_addrsort_short_circuit() {
        let probed = |ip: IpAddr| {
            if ip == IpAddr::from([1, 1, 1, 1]) {
                probe_usable(IpAddr::from([9, 9, 9, 9]))
            } else {
                probe_unusable(ip)
            }
        };
        let one = vec![IpAddr::from([2, 2, 2, 2])];
        assert_eq!(sort_with(one.clone(), &probed), one);
        let all_v4 = vec![IpAddr::from([2, 2, 2, 2]), IpAddr::from([1, 1, 1, 1])];
        assert_eq!(sort_with(all_v4.clone(), &probed), all_v4);
    }

    /// UT case for usability ranking: a usable address outranks an
    /// unusable one regardless of precedence (the DAS_USABLE bit sits
    /// above the precedence field).
    #[test]
    fn ut_addrsort_usable_dominates() {
        let v6 = "2001:db8::1".parse().unwrap();
        let v4 = IpAddr::from([8, 8, 8, 8]);
        let probed = |ip: IpAddr| {
            if ip.is_ipv4() {
                probe_usable(IpAddr::from([192, 168, 1, 2]))
            } else {
                probe_unusable(ip)
            }
        };
        let out = sort_with(vec![v6, v4], &probed);
        assert_eq!(out, vec![v4, v6]);
    }

    /// UT case for precedence ranking with no source information: global
    /// v6 (40) > IPv4-mapped (35) > Teredo (5) > ULA (3).
    #[test]
    fn ut_addrsort_precedence() {
        let v6 = "2001:db8::1".parse().unwrap();
        let v4 = IpAddr::from([8, 8, 8, 8]);
        let teredo = "2001::1".parse().unwrap();
        let ula = "fc00::1".parse().unwrap();
        let out =
            sort_with(vec![ula, teredo, v4, v6], &|_| addrsort::Probe::UsableNoSource);
        assert_eq!(out, vec![v6, v4, teredo, ula]);
    }

    /// UT case for the combined scope/label bits: matching scope and label
    /// (0x3000_0000 combined) outranks the scope-number field — a global
    /// destination with a matching source beats a same-precedence
    /// link-local destination probed blind.
    #[test]
    fn ut_addrsort_scope_and_label_bits() {
        let link_local = "fe80::1".parse().unwrap();
        let global = "2001:db8::1".parse().unwrap();
        let probed = |ip: IpAddr| {
            if ip == link_local {
                addrsort::Probe::UsableNoSource
            } else {
                probe_usable(global)
            }
        };
        let out = sort_with(vec![link_local, global], &probed);
        assert_eq!(out, vec![global, link_local]);
    }

    /// UT case for stability: equal keys keep collection order (via the
    /// MAXADDRS-i order component, matching musl's qsort on unique keys).
    #[test]
    fn ut_addrsort_stable_on_ties() {
        let a = "2001:db8::1".parse().unwrap();
        let b = "2001:db8::2".parse().unwrap();
        let out = sort_with(vec![a, b], &probe_unusable);
        assert_eq!(out, vec![a, b]);
    }

    /// UT case for the real source probe: it reaches v4 loopback; on hosts
    /// with v6 loopback the policy table puts ::1 (precedence 50) ahead of
    /// 127.0.0.1 (35).
    #[test]
    fn ut_addrsort_real_probe_loopback() {
        assert!(matches!(
            addrsort::probe(IpAddr::from([127, 0, 0, 1]), None),
            addrsort::Probe::Usable(_)
        ));
        let out = sort_with(
            vec![Ipv6Addr::LOCALHOST.into(), IpAddr::from([127, 0, 0, 1])],
            &|ip| addrsort::probe(ip, None),
        );
        if matches!(
            addrsort::probe(Ipv6Addr::LOCALHOST.into(), None),
            addrsort::Probe::Usable(_)
        ) {
            assert_eq!(out.first(), Some(&Ipv6Addr::LOCALHOST.into()));
        }
    }

    /// UT case for the owner-aware probe: chown'ing the probe socket to
    /// the current uid/gid (always permitted, root or not) keeps the
    /// kernel source address read back working; an `fchown` failure would
    /// degrade to `Unusable` instead of panicking.
    #[test]
    fn ut_addrsort_probe_with_owner() {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        assert!(matches!(
            addrsort::probe(IpAddr::from([127, 0, 0, 1]), Some((uid, gid))),
            addrsort::Probe::Usable(_)
        ));
    }

    /// Conformance vectors: the RFC 6724 Section 10.2 example policies.
    /// Cases 1-4, 6 and 7 are compatible with the musl subset (rules 3/4/7
    /// omitted); case 5 ("prefer home address") needs rule 4 and is not
    /// reproducible here. Per-destination sources are the RFC-stated
    /// candidates, injected through the synthetic probe.
    ///
    /// # Brief
    /// 1. Encodes each example as (destination, RFC-stated source) pairs.
    /// 2. Sorts the destination list and checks the RFC result order.
    #[test]
    fn ut_conformance_rfc6724_10_2() {
        use std::collections::HashMap;

        let ip = |s: &str| s.parse().unwrap();
        let run = |sources: Vec<(IpAddr, IpAddr)>, list: Vec<IpAddr>| {
            let map: HashMap<IpAddr, IpAddr> = sources.into_iter().collect();
            let probed = |dst: IpAddr| match map.get(&dst) {
                Some(src) => addrsort::Probe::Usable(*src),
                None => addrsort::Probe::UsableNoSource,
            };
            sort_with(list, &probed)
        };

        // Case 1 (prefer matching scope): 198.51.100.121's source is
        // link-local, so its scope bit is unset and 2001:db8:1::1 wins.
        let out = run(
            vec![
                (ip("2001:db8:1::1"), ip("2001:db8:1::2")),
                (ip("198.51.100.121"), ip("169.254.13.78")),
            ],
            vec![ip("2001:db8:1::1"), ip("198.51.100.121")],
        );
        assert_eq!(out, vec![ip("2001:db8:1::1"), ip("198.51.100.121")]);

        // Case 2 (prefer matching scope): 2001:db8:1::1's only v6 candidate
        // source is link-local, so 198.51.100.121 (scope-matched) wins.
        let out = run(
            vec![
                (ip("2001:db8:1::1"), ip("fe80::1")),
                (ip("198.51.100.121"), ip("198.51.100.117")),
            ],
            vec![ip("2001:db8:1::1"), ip("198.51.100.121")],
        );
        assert_eq!(out, vec![ip("198.51.100.121"), ip("2001:db8:1::1")]);

        // Case 3 (prefer higher precedence): both scope/label match; the
        // catch-all precedence 40 beats the IPv4-mapped 35.
        let out = run(
            vec![
                (ip("2001:db8:1::1"), ip("2001:db8:1::2")),
                (ip("10.1.2.3"), ip("10.1.2.4")),
            ],
            vec![ip("2001:db8:1::1"), ip("10.1.2.3")],
        );
        assert_eq!(out, vec![ip("2001:db8:1::1"), ip("10.1.2.3")]);

        // Case 4 (prefer smaller scope): link-local destination outranks the
        // global one through the scope-number field.
        let out = run(
            vec![
                (ip("2001:db8:1::1"), ip("2001:db8:1::2")),
                (ip("fe80::1"), ip("fe80::2")),
            ],
            vec![ip("2001:db8:1::1"), ip("fe80::1")],
        );
        assert_eq!(out, vec![ip("fe80::1"), ip("2001:db8:1::1")]);

        // Case 6 (longest matching prefix): both scope/label match with
        // equal precedence; the /64 shared prefix beats the /40 one.
        let out = run(
            vec![
                (ip("2001:db8:1::1"), ip("2001:db8:1::2")),
                (ip("2001:db8:3ffe::1"), ip("2001:db8:3f44::2")),
            ],
            vec![ip("2001:db8:1::1"), ip("2001:db8:3ffe::1")],
        );
        assert_eq!(out, vec![ip("2001:db8:1::1"), ip("2001:db8:3ffe::1")]);

        // Case 7 (prefer matching label): the 6to4 destination's label match
        // (rule 5) outranks the catch-all destination's higher precedence
        // (rule 6) — proves the label bit sits above the precedence field.
        let out = run(
            vec![
                (ip("2002:c633:6401::1"), ip("2002:c633:6401::2")),
                (ip("2001:db8:1::1"), ip("2002:c633:6401::2")),
            ],
            vec![ip("2002:c633:6401::1"), ip("2001:db8:1::1")],
        );
        assert_eq!(out, vec![ip("2002:c633:6401::1"), ip("2001:db8:1::1")]);
    }
}
