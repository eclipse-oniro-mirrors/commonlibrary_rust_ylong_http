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

//! This is a simple asynchronous HTTP2 client example using the ylong_http_client crate.
//! It demonstrates creating a client, making a request, and reading the response asynchronously.

use ylong_http_client::async_impl::{Body, ClientBuilder};
use ylong_http_client::{RequestBuilder, StatusCode, TextBody, Version};

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("Build runtime failed.");

    let client = ClientBuilder::new()
        .http2_prior_knowledge()
        .build()
        .unwrap();

    let request = RequestBuilder::new()
        .version("HTTP/2.0")
        .url("127.0.0.1:5678")
        .method("GET")
        .header("host", "127.0.0.1")
        .body(TextBody::from_bytes("Hi".as_bytes()))
        .unwrap();

    rt.block_on(async move {
        let mut response = client.request(request).await.unwrap();
        assert_eq!(response.version(), &Version::HTTP2);
        assert_eq!(response.status(), &StatusCode::OK);

        let mut buf = [0u8; 4096];
        let mut size = 0;

        loop {
            let read = response
                .body_mut()
                .data(&mut buf[size..])
                .await
                .expect("Response body read failed");
            if read == 0 {
                break;
            }
            size += read;
        }
        assert_eq!(
            &buf[..size],
            "hello world".as_bytes(),
            "Assert response body failed"
        );
    });
}
