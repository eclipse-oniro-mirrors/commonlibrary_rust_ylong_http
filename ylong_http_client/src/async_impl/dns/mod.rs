// Copyright (c) 2023 Huawei Device Co., Ltd.
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

//! HTTP dns resolver module.
//!
//! This module defines the dns resolver trait accepted by http clients and
//! provides a default dns resolver implementation.
//!
//! - [`Resolver`]: The dns resolver trait, which users can implement to provide
//!   a custom dns resolver.
//!
//! - [`DefaultDnsResolver`]: Default dns resolver.
//!
//! # Documentation sources
//!
//! Two tiers of citations are used across this module. Protocol semantics
//! cite the DNS specs as rustdoc reference links ([RFC1035] / [RFC 3596],
//! anchor URLs defined at the end of each doc block). Behavioral parity
//! with the system resolver cites musl source files and line ranges as
//! plain text — resolver behavior beyond the wire format (resolv.conf
//! grammar, retry schedules, address sorting) is ported from the musl
//! reference rather than specified by RFC. The pure wire-format codec
//! (query building, response parsing) lives in the `ylong_http` crate
//! (`ylong_http::dns`) and is re-exported here as `wire`; its own docs
//! cite the RFC sections it implements.
//!
//! [RFC1035]: https://datatracker.ietf.org/doc/html/rfc1035
//! [RFC 3596]: https://datatracker.ietf.org/doc/html/rfc3596

mod default;
#[cfg(feature = "__c_openssl")]
mod doh;
mod happy_eyeballs;
#[cfg(all(target_os = "linux", feature = "ylong_base", feature = "__tls"))]
mod config;
#[cfg(all(target_os = "linux", feature = "ylong_base", feature = "__tls"))]
mod error;
#[cfg(all(target_os = "linux", feature = "ylong_base", feature = "__tls"))]
mod exchange;
#[cfg(all(target_os = "linux", feature = "ylong_base", feature = "__tls"))]
mod hosts;
// Pure DNS wire-format codec (query building, response parsing), shared
// with the sync implementation path: implemented once in the `ylong_http`
// crate and re-exported here under a shorter alias.
#[cfg(all(target_os = "linux", feature = "ylong_base", feature = "__tls"))]
pub(crate) use ylong_http::dns as wire;
#[cfg(all(target_os = "linux", feature = "ylong_base", feature = "__tls"))]
mod owner_resolver;
#[cfg(all(target_os = "linux", feature = "ylong_base", feature = "__tls"))]
mod query;
mod resolver;
#[cfg(all(target_os = "linux", feature = "ylong_base", feature = "__tls"))]
mod sort;
#[cfg(all(test, target_os = "linux", feature = "ylong_base", feature = "__tls"))]
mod test_util;

pub use default::DefaultDnsResolver;
#[cfg(feature = "__c_openssl")]
pub use doh::DohResolver;
pub(crate) use happy_eyeballs::{EyeBallConfig, HappyEyeballs};
#[cfg(all(target_os = "linux", feature = "ylong_base", feature = "__tls"))]
pub(crate) use owner_resolver::OwnerAwareResolver;
pub use resolver::{Addrs, Resolver, SocketFuture, StdError};
