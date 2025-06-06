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

#![cfg(all(
    feature = "sync",
    feature = "http1_1",
    feature = "__tls",
    feature = "tokio_base"
))]

use std::path::PathBuf;

use ylong_http_client::sync_impl::Body;

use crate::common::init_test_work_runtime;

#[macro_use]
mod common;

#[test]
fn sdv_synchronized_client_send_request() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let mut path = PathBuf::from(dir);
    path.push("tests/file/root-ca.pem");

    // `PUT` request.
    sync_client_test_case!(
        HTTPS;
        Tls: path.to_str().unwrap(),
        RuntimeThreads: 2,
        Request: {
            Method: "PUT",
            Host: "https://127.0.0.1",
            Header: "Content-Length", "6",
            Body: "Hello!",
        },
        Response: {
            Status: 200,
            Version: "HTTP/1.1",
            Header: "Content-Length", "3",
            Body: "Hi!",
        },
    );
}

#[test]
fn sdv_synchronized_client_send_request_repeatedly() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let mut path = PathBuf::from(dir);
    path.push("tests/file/root-ca.pem");

    sync_client_test_case!(
        HTTPS;
        Tls: path.to_str().unwrap(),
        RuntimeThreads: 2,
        Request: {
            Method: "GET",
            Host: "https://127.0.0.1",
            Header: "Content-Length", "6",
            Body: "Hello!",
        },
        Response: {
            Status: 201,
            Version: "HTTP/1.1",
            Header: "Content-Length", "11",
            Body: "METHOD GET!",
        },
        Request: {
            Method: "POST",
            Host: "https://127.0.0.1",
            Header: "Content-Length", "6",
            Body: "Hello!",
        },
        Response: {
            Status: 201,
            Version: "HTTP/1.1",
            Header: "Content-Length", "12",
            Body: "METHOD POST!",
        },
    );
}
