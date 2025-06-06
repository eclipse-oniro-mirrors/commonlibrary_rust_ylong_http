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

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum QpackError {
    ConnectionError(ErrorCode),
    InternalError(NotClassified),
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum ErrorCode {
    DecompressionFailed = 0x0200,

    EncoderStreamError = 0x0201,

    DecoderStreamError = 0x0202,

    H3SettingsError = 0x0109,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum NotClassified {
    DynamicTableInsufficient,
    StreamBlocked,
}
