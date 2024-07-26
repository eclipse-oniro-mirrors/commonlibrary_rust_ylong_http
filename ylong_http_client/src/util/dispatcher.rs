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

pub(crate) trait Dispatcher {
    type Handle;

    fn dispatch(&self) -> Option<Self::Handle>;

    fn is_shutdown(&self) -> bool;
}

pub(crate) enum ConnDispatcher<S> {
    #[cfg(feature = "http1_1")]
    Http1(http1::Http1Dispatcher<S>),

    #[cfg(feature = "http2")]
    Http2(http2::Http2Dispatcher<S>),
}

impl<S> Dispatcher for ConnDispatcher<S> {
    type Handle = Conn<S>;

    fn dispatch(&self) -> Option<Self::Handle> {
        match self {
            #[cfg(feature = "http1_1")]
            Self::Http1(h1) => h1.dispatch().map(Conn::Http1),

            #[cfg(feature = "http2")]
            Self::Http2(h2) => h2.dispatch().map(Conn::Http2),
        }
    }

    fn is_shutdown(&self) -> bool {
        match self {
            #[cfg(feature = "http1_1")]
            Self::Http1(h1) => h1.is_shutdown(),

            #[cfg(feature = "http2")]
            Self::Http2(h2) => h2.is_shutdown(),
        }
    }
}

pub(crate) enum Conn<S> {
    #[cfg(feature = "http1_1")]
    Http1(http1::Http1Conn<S>),

    #[cfg(feature = "http2")]
    Http2(http2::Http2Conn<S>),
}

#[cfg(feature = "http1_1")]
pub(crate) mod http1 {
    use std::cell::UnsafeCell;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use super::{ConnDispatcher, Dispatcher};

    impl<S> ConnDispatcher<S> {
        pub(crate) fn http1(io: S) -> Self {
            Self::Http1(Http1Dispatcher::new(io))
        }
    }

    /// HTTP1-based connection manager, which can dispatch connections to other
    /// threads according to HTTP1 syntax.
    pub(crate) struct Http1Dispatcher<S> {
        inner: Arc<Inner<S>>,
    }

    pub(crate) struct Inner<S> {
        pub(crate) io: UnsafeCell<S>,
        // `occupied` indicates that the connection is occupied. Only one coroutine
        // can get the handle at the same time. Once the handle is fetched, the flag
        // position is true.
        pub(crate) occupied: AtomicBool,
        // `shutdown` indicates that the connection need to be shut down.
        pub(crate) shutdown: AtomicBool,
    }

    unsafe impl<S> Sync for Inner<S> {}

    impl<S> Http1Dispatcher<S> {
        pub(crate) fn new(io: S) -> Self {
            Self {
                inner: Arc::new(Inner {
                    io: UnsafeCell::new(io),
                    occupied: AtomicBool::new(false),
                    shutdown: AtomicBool::new(false),
                }),
            }
        }
    }

    impl<S> Dispatcher for Http1Dispatcher<S> {
        type Handle = Http1Conn<S>;

        fn dispatch(&self) -> Option<Self::Handle> {
            self.inner
                .occupied
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .ok()
                .map(|_| Http1Conn {
                    inner: self.inner.clone(),
                })
        }

        fn is_shutdown(&self) -> bool {
            self.inner.shutdown.load(Ordering::Relaxed)
        }
    }

    /// Handle returned to other threads for I/O operations.
    pub(crate) struct Http1Conn<S> {
        pub(crate) inner: Arc<Inner<S>>,
    }

    impl<S> Http1Conn<S> {
        pub(crate) fn raw_mut(&mut self) -> &mut S {
            // SAFETY: In the case of `HTTP1`, only one coroutine gets the handle
            // at the same time.
            unsafe { &mut *self.inner.io.get() }
        }

        pub(crate) fn shutdown(&self) {
            self.inner.shutdown.store(true, Ordering::Release);
        }
    }

    impl<S> Drop for Http1Conn<S> {
        fn drop(&mut self) {
            self.inner.occupied.store(false, Ordering::Release)
        }
    }
}

#[cfg(feature = "http2")]
pub(crate) mod http2 {
    use std::collections::HashMap;
    use std::future::Future;
    use std::marker::PhantomData;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    use ylong_http::error::HttpError;
    use ylong_http::h2::{
        ErrorCode, Frame, FrameDecoder, FrameEncoder, FrameFlags, Goaway, H2Error, Payload,
        RstStream, Settings, SettingsBuilder,
    };

    use crate::runtime::{
        bounded_channel, unbounded_channel, AsyncRead, AsyncWrite, AsyncWriteExt, BoundedReceiver,
        BoundedSender, SendError, UnboundedReceiver, UnboundedSender, WriteHalf,
    };
    use crate::util::config::H2Config;
    use crate::util::dispatcher::{ConnDispatcher, Dispatcher};
    use crate::util::h2::{
        ConnManager, FlowControl, H2StreamState, RecvData, RequestWrapper, SendData,
        StreamEndState, Streams,
    };
    use crate::ErrorKind::Request;
    use crate::{ErrorKind, HttpClientError};

    const DEFAULT_MAX_STREAM_ID: u32 = u32::MAX >> 1;
    const DEFAULT_MAX_FRAME_SIZE: usize = 2 << 13;
    const DEFAULT_MAX_HEADER_LIST_SIZE: usize = 16 << 20;
    const DEFAULT_WINDOW_SIZE: u32 = 65535;

    pub(crate) type ManagerSendFut =
        Pin<Box<dyn Future<Output = Result<(), SendError<RespMessage>>> + Send + Sync>>;

    pub(crate) enum RespMessage {
        Output(Frame),
        OutputExit(DispatchErrorKind),
    }

    pub(crate) enum OutputMessage {
        Output(Frame),
        OutputExit(DispatchErrorKind),
    }

    pub(crate) struct ReqMessage {
        pub(crate) id: u32,
        pub(crate) sender: BoundedSender<RespMessage>,
        pub(crate) request: RequestWrapper,
    }

    #[derive(Debug, Eq, PartialEq, Copy, Clone)]
    pub(crate) enum DispatchErrorKind {
        H2(H2Error),
        Io(std::io::ErrorKind),
        ChannelClosed,
        Disconnect,
    }

    // HTTP2-based connection manager, which can dispatch connections to other
    // threads according to HTTP2 syntax.
    pub(crate) struct Http2Dispatcher<S> {
        pub(crate) next_stream_id: StreamId,
        pub(crate) allow_cached_frames: usize,
        pub(crate) sender: UnboundedSender<ReqMessage>,
        pub(crate) io_shutdown: Arc<AtomicBool>,
        pub(crate) handles: Vec<crate::runtime::JoinHandle<()>>,
        pub(crate) _mark: PhantomData<S>,
    }

    pub(crate) struct Http2Conn<S> {
        // Handle id
        pub(crate) id: u32,
        pub(crate) allow_cached_frames: usize,
        // Sends frame to StreamController
        pub(crate) sender: UnboundedSender<ReqMessage>,
        pub(crate) receiver: RespReceiver,
        pub(crate) io_shutdown: Arc<AtomicBool>,
        pub(crate) _mark: PhantomData<S>,
    }

    pub(crate) struct StreamController {
        // The connection close flag organizes new stream commits to the current connection when
        // closed.
        pub(crate) io_shutdown: Arc<AtomicBool>,
        // The senders of all connected stream channels of response.
        pub(crate) senders: HashMap<u32, BoundedSender<RespMessage>>,
        pub(crate) curr_message: HashMap<u32, ManagerSendFut>,
        // Stream information on the connection.
        pub(crate) streams: Streams,
        // Received GO_AWAY frame.
        pub(crate) recved_go_away: Option<u32>,
        // The last GO_AWAY frame sent by the client.
        pub(crate) go_away_sync: GoAwaySync,
    }

    #[derive(Default)]
    pub(crate) struct GoAwaySync {
        pub(crate) going_away: Option<Goaway>,
    }

    #[derive(Default)]
    pub(crate) struct SettingsSync {
        pub(crate) settings: SettingsState,
    }

    #[derive(Default, Clone)]
    pub(crate) enum SettingsState {
        Acknowledging(Settings),
        #[default]
        Synced,
    }

    pub(crate) struct StreamId {
        // TODO Determine the maximum value of id.
        id: AtomicU32,
    }

    #[derive(Default)]
    pub(crate) struct RespReceiver {
        receiver: Option<BoundedReceiver<RespMessage>>,
    }

    impl<S> ConnDispatcher<S>
    where
        S: AsyncRead + AsyncWrite + Sync + Send + Unpin + 'static,
    {
        pub(crate) fn http2(config: H2Config, io: S) -> Self {
            Self::Http2(Http2Dispatcher::new(config, io))
        }
    }

    impl<S> Http2Dispatcher<S>
    where
        S: AsyncRead + AsyncWrite + Sync + Send + Unpin + 'static,
    {
        pub(crate) fn new(config: H2Config, io: S) -> Self {
            let settings = create_initial_settings(&config);

            let mut flow = FlowControl::new(DEFAULT_WINDOW_SIZE, DEFAULT_WINDOW_SIZE);
            flow.setup_recv_window(config.conn_window_size());

            let streams = Streams::new(config.stream_window_size(), DEFAULT_WINDOW_SIZE, flow);
            let shutdown_flag = Arc::new(AtomicBool::new(false));
            let controller = StreamController::new(streams, shutdown_flag.clone());

            // The id of the client stream, starting from 1
            let next_stream_id = StreamId {
                id: AtomicU32::new(1),
            };
            let (input_tx, input_rx) = unbounded_channel();
            let (req_tx, req_rx) = unbounded_channel();

            // Error is not possible, so it is not handled for the time
            // being.
            let mut handles = Vec::with_capacity(3);
            if input_tx.send(settings).is_ok() {
                Self::launch(
                    config.allow_cached_frame_num(),
                    controller,
                    req_rx,
                    input_tx,
                    input_rx,
                    &mut handles,
                    io,
                );
            }
            Self {
                next_stream_id,
                allow_cached_frames: config.allow_cached_frame_num(),
                sender: req_tx,
                io_shutdown: shutdown_flag,
                handles,
                _mark: PhantomData,
            }
        }

        fn launch(
            allow_num: usize,
            controller: StreamController,
            req_rx: UnboundedReceiver<ReqMessage>,
            input_tx: UnboundedSender<Frame>,
            input_rx: UnboundedReceiver<Frame>,
            handles: &mut Vec<crate::runtime::JoinHandle<()>>,
            io: S,
        ) {
            let (resp_tx, resp_rx) = bounded_channel(allow_num);
            let (read, write) = crate::runtime::split(io);
            let settings_sync = Arc::new(Mutex::new(SettingsSync::default()));
            let send_settings_sync = settings_sync.clone();
            let send = crate::runtime::spawn(async move {
                let mut writer = write;
                if async_send_preface(&mut writer).await.is_ok() {
                    let encoder =
                        FrameEncoder::new(DEFAULT_MAX_FRAME_SIZE, DEFAULT_MAX_HEADER_LIST_SIZE);
                    let mut send = SendData::new(encoder, send_settings_sync, writer, input_rx);
                    let _ = Pin::new(&mut send).await;
                }
            });
            handles.push(send);

            let recv_settings_sync = settings_sync.clone();
            let recv = crate::runtime::spawn(async move {
                let decoder = FrameDecoder::new();
                let mut recv = RecvData::new(decoder, recv_settings_sync, read, resp_tx);
                let _ = Pin::new(&mut recv).await;
            });
            handles.push(recv);

            let manager = crate::runtime::spawn(async move {
                let mut conn_manager =
                    ConnManager::new(settings_sync, input_tx, resp_rx, req_rx, controller);
                let _ = Pin::new(&mut conn_manager).await;
            });
            handles.push(manager);
        }
    }

    impl<S> Dispatcher for Http2Dispatcher<S> {
        type Handle = Http2Conn<S>;

        fn dispatch(&self) -> Option<Self::Handle> {
            let id = self.next_stream_id.generate_id();
            if id > DEFAULT_MAX_STREAM_ID {
                return None;
            }
            let sender = self.sender.clone();
            let handle = Http2Conn::new(
                id,
                self.allow_cached_frames,
                self.io_shutdown.clone(),
                sender,
            );
            Some(handle)
        }

        fn is_shutdown(&self) -> bool {
            self.io_shutdown.load(Ordering::Relaxed)
        }
    }

    impl<S> Drop for Http2Dispatcher<S> {
        fn drop(&mut self) {
            for handle in &self.handles {
                #[cfg(feature = "ylong_base")]
                handle.cancel();
                #[cfg(feature = "tokio_base")]
                handle.abort();
            }
        }
    }

    impl<S> Http2Conn<S> {
        pub(crate) fn new(
            id: u32,
            allow_cached_num: usize,
            io_shutdown: Arc<AtomicBool>,
            sender: UnboundedSender<ReqMessage>,
        ) -> Self {
            Self {
                id,
                allow_cached_frames: allow_cached_num,
                sender,
                receiver: RespReceiver::default(),
                io_shutdown,
                _mark: PhantomData,
            }
        }

        pub(crate) fn send_frame_to_controller(
            &mut self,
            request: RequestWrapper,
        ) -> Result<(), HttpClientError> {
            let (tx, rx) = bounded_channel::<RespMessage>(self.allow_cached_frames);
            self.receiver.set_receiver(rx);
            self.sender
                .send(ReqMessage {
                    id: self.id,
                    sender: tx,
                    request,
                })
                .map_err(|_| {
                    HttpClientError::from_str(ErrorKind::Request, "Request Sender Closed !")
                })
        }
    }

    impl StreamId {
        fn generate_id(&self) -> u32 {
            self.id.fetch_add(2, Ordering::Relaxed)
        }
    }

    impl StreamController {
        pub(crate) fn new(streams: Streams, shutdown: Arc<AtomicBool>) -> Self {
            Self {
                io_shutdown: shutdown,
                senders: HashMap::new(),
                curr_message: HashMap::new(),
                streams,
                recved_go_away: None,
                go_away_sync: GoAwaySync::default(),
            }
        }

        pub(crate) fn shutdown(&self) {
            self.io_shutdown.store(true, Ordering::Release);
        }

        pub(crate) fn get_unsent_streams(
            &mut self,
            last_stream_id: u32,
        ) -> Result<Vec<u32>, H2Error> {
            // The last-stream-id in the subsequent GO_AWAY frame
            // cannot be greater than the last-stream-id in the previous GO_AWAY frame.
            if self.streams.max_send_id < last_stream_id {
                return Err(H2Error::ConnectionError(ErrorCode::ProtocolError));
            }
            self.streams.max_send_id = last_stream_id;
            Ok(self.streams.get_go_away_streams(last_stream_id))
        }

        pub(crate) fn send_message_to_stream(
            &mut self,
            cx: &mut Context<'_>,
            stream_id: u32,
            message: RespMessage,
        ) -> Poll<Result<(), H2Error>> {
            if let Some(sender) = self.senders.get(&stream_id) {
                // If the client coroutine has exited, this frame is skipped.
                let mut tx = {
                    let sender = sender.clone();
                    let ft = async move { sender.send(message).await };
                    Box::pin(ft)
                };

                match tx.as_mut().poll(cx) {
                    Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
                    // The current coroutine sending the request exited prematurely.
                    Poll::Ready(Err(_)) => {
                        self.senders.remove(&stream_id);
                        Poll::Ready(Err(H2Error::StreamError(stream_id, ErrorCode::NoError)))
                    }
                    Poll::Pending => {
                        self.curr_message.insert(stream_id, tx);
                        Poll::Pending
                    }
                }
            } else {
                Poll::Ready(Err(H2Error::StreamError(stream_id, ErrorCode::NoError)))
            }
        }

        pub(crate) fn poll_blocked_message(
            &mut self,
            cx: &mut Context<'_>,
            input_tx: &UnboundedSender<Frame>,
        ) -> Poll<()> {
            let keys: Vec<u32> = self.curr_message.keys().cloned().collect();
            let mut blocked = false;

            for key in keys {
                if let Some(mut task) = self.curr_message.remove(&key) {
                    match task.as_mut().poll(cx) {
                        Poll::Ready(Ok(_)) => {}
                        // The current coroutine sending the request exited prematurely.
                        Poll::Ready(Err(_)) => {
                            self.senders.remove(&key);
                            if let Some(state) = self.streams.stream_state(key) {
                                if !matches!(state, H2StreamState::Closed(_)) {
                                    if let StreamEndState::OK = self.streams.send_local_reset(key) {
                                        let rest_payload =
                                            RstStream::new(ErrorCode::NoError.into_code());
                                        let frame = Frame::new(
                                            key as usize,
                                            FrameFlags::empty(),
                                            Payload::RstStream(rest_payload),
                                        );
                                        // ignore the send error occurs here in order to finish all
                                        // tasks.
                                        let _ = input_tx.send(frame);
                                    }
                                }
                            }
                        }
                        Poll::Pending => {
                            self.curr_message.insert(key, task);
                            blocked = true;
                        }
                    }
                }
            }
            if blocked {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        }
    }

    impl RespReceiver {
        pub(crate) fn set_receiver(&mut self, receiver: BoundedReceiver<RespMessage>) {
            self.receiver = Some(receiver);
        }

        pub(crate) async fn recv(&mut self) -> Result<Frame, HttpClientError> {
            match self.receiver {
                Some(ref mut receiver) => {
                    #[cfg(feature = "tokio_base")]
                    match receiver.recv().await {
                        None => err_from_msg!(Request, "Response Receiver Closed !"),
                        Some(message) => match message {
                            RespMessage::Output(frame) => Ok(frame),
                            RespMessage::OutputExit(e) => Err(dispatch_client_error(e)),
                        },
                    }

                    #[cfg(feature = "ylong_base")]
                    match receiver.recv().await {
                        Err(err) => Err(HttpClientError::from_error(ErrorKind::Request, err)),
                        Ok(message) => match message {
                            RespMessage::Output(frame) => Ok(frame),
                            RespMessage::OutputExit(e) => Err(dispatch_client_error(e)),
                        },
                    }
                }
                // this will not happen.
                None => Err(HttpClientError::from_str(
                    ErrorKind::Request,
                    "Invalid Frame Receiver !",
                )),
            }
        }

        pub(crate) fn poll_recv(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<Frame, HttpClientError>> {
            if let Some(ref mut receiver) = self.receiver {
                #[cfg(feature = "tokio_base")]
                match receiver.poll_recv(cx) {
                    Poll::Ready(None) => {
                        Poll::Ready(err_from_msg!(Request, "Error receive response !"))
                    }
                    Poll::Ready(Some(message)) => match message {
                        RespMessage::Output(frame) => Poll::Ready(Ok(frame)),
                        RespMessage::OutputExit(e) => Poll::Ready(Err(dispatch_client_error(e))),
                    },
                    Poll::Pending => Poll::Pending,
                }

                #[cfg(feature = "ylong_base")]
                match receiver.poll_recv(cx) {
                    Poll::Ready(Err(e)) => {
                        Poll::Ready(Err(HttpClientError::from_error(ErrorKind::Request, e)))
                    }
                    Poll::Ready(Ok(message)) => match message {
                        RespMessage::Output(frame) => Poll::Ready(Ok(frame)),
                        RespMessage::OutputExit(e) => Poll::Ready(Err(dispatch_client_error(e))),
                    },
                    Poll::Pending => Poll::Pending,
                }
            } else {
                Poll::Ready(err_from_msg!(Request, "Invalid Frame Receiver !"))
            }
        }
    }

    async fn async_send_preface<S>(writer: &mut WriteHalf<S>) -> Result<(), DispatchErrorKind>
    where
        S: AsyncWrite + Unpin,
    {
        const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        writer
            .write_all(PREFACE)
            .await
            .map_err(|e| DispatchErrorKind::Io(e.kind()))
    }

    pub(crate) fn create_initial_settings(config: &H2Config) -> Frame {
        let settings = SettingsBuilder::new()
            .max_header_list_size(config.max_header_list_size())
            .max_frame_size(config.max_frame_size())
            .header_table_size(config.header_table_size())
            .enable_push(config.enable_push())
            .initial_window_size(config.stream_window_size())
            .build();

        Frame::new(0, FrameFlags::new(0), Payload::Settings(settings))
    }

    impl From<std::io::Error> for DispatchErrorKind {
        fn from(value: std::io::Error) -> Self {
            DispatchErrorKind::Io(value.kind())
        }
    }

    impl From<H2Error> for DispatchErrorKind {
        fn from(err: H2Error) -> Self {
            DispatchErrorKind::H2(err)
        }
    }

    pub(crate) fn dispatch_client_error(dispatch_error: DispatchErrorKind) -> HttpClientError {
        match dispatch_error {
            DispatchErrorKind::H2(e) => HttpClientError::from_error(Request, HttpError::from(e)),
            DispatchErrorKind::Io(e) => {
                HttpClientError::from_io_error(Request, std::io::Error::from(e))
            }
            DispatchErrorKind::ChannelClosed => {
                HttpClientError::from_str(Request, "Coroutine channel closed.")
            }
            DispatchErrorKind::Disconnect => {
                HttpClientError::from_str(Request, "remote peer closed.")
            }
        }
    }
}

#[cfg(test)]
mod ut_dispatch {
    use crate::dispatcher::{ConnDispatcher, Dispatcher};

    /// UT test cases for `ConnDispatcher::is_shutdown`.
    ///
    /// # Brief
    /// 1. Creates a `ConnDispatcher`.
    /// 2. Calls `ConnDispatcher::is_shutdown` to get the result.
    /// 3. Calls `ConnDispatcher::dispatch` to get the result.
    /// 4. Checks if the result is false.
    #[test]
    fn ut_is_shutdown() {
        let conn = ConnDispatcher::http1(b"Data");
        let res = conn.is_shutdown();
        assert!(!res);
        let res = conn.dispatch();
        assert!(res.is_some());
    }
}
