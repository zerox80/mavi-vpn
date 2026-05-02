//! QUIC Transport implementation with Quinn
//!
//! This module implements QUIC traits with Quinn.
#![allow(missing_docs)]

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{self, ready, Poll},
};

use bytes::Buf;

use futures_util::{stream as futures_stream, Stream, StreamExt};

pub use quinn::{self, AcceptBi, AcceptUni, OpenBi, OpenUni, VarInt};

use h3::{
    error::Code,
    quic::{self, ConnectionErrorIncoming, StreamErrorIncoming},
};

#[cfg(feature = "tracing")]
use tracing::instrument;

// Note: We don't use the h3-datagram crate integration here.
// VPN datagrams are handled directly via quinn::Connection with Quarter Stream ID prefix.

mod stream;

pub use stream::{BidiStream, RecvStream, SendStream};

/// `BoxStream` with Sync trait
type BoxStreamSync<'a, T> = Pin<Box<dyn Stream<Item = T> + Sync + Send + 'a>>;

/// A QUIC connection backed by Quinn
///
/// Implements a [`quic::Connection`] backed by a [`quinn::Connection`].
pub struct Connection {
    conn: quinn::Connection,
    incoming_bi: BoxStreamSync<'static, <AcceptBi<'static> as Future>::Output>,
    opening_bi: Option<BoxStreamSync<'static, <OpenBi<'static> as Future>::Output>>,
    incoming_uni: BoxStreamSync<'static, <AcceptUni<'static> as Future>::Output>,
    opening_uni: Option<BoxStreamSync<'static, <OpenUni<'static> as Future>::Output>>,
}

impl Connection {
    pub fn with_pre_streams(
        conn: quinn::Connection,
        pre_bi: Option<(quinn::SendStream, quinn::RecvStream)>,
        pre_uni: Option<quinn::RecvStream>,
    ) -> Self {
        Self {
            conn: conn.clone(),
            incoming_bi: incoming_bi_stream(conn.clone(), pre_bi),
            opening_bi: None,
            incoming_uni: incoming_uni_stream(conn, pre_uni),
            opening_uni: None,
        }
    }

    /// Create a [`Connection`] from a [`quinn::Connection`] and a pre-accepted uni stream.
    #[allow(dead_code)]
    pub fn with_pre_uni(conn: quinn::Connection, pre_uni: quinn::RecvStream) -> Self {
        Self::with_pre_streams(conn, None, Some(pre_uni))
    }
}

fn incoming_bi_stream(
    conn: quinn::Connection,
    pre_bi: Option<(quinn::SendStream, quinn::RecvStream)>,
) -> BoxStreamSync<'static, <AcceptBi<'static> as Future>::Output> {
    let mut first = pre_bi;
    Box::pin(futures_stream::unfold(conn, move |conn| {
        let first = first.take();
        async move {
            if let Some(streams) = first {
                Some((Ok(streams), conn))
            } else {
                Some((conn.accept_bi().await, conn))
            }
        }
    }))
}

fn incoming_uni_stream(
    conn: quinn::Connection,
    pre_uni: Option<quinn::RecvStream>,
) -> BoxStreamSync<'static, <AcceptUni<'static> as Future>::Output> {
    let mut first = pre_uni;
    Box::pin(futures_stream::unfold(conn, move |conn| {
        let first = first.take();
        async move {
            if let Some(stream) = first {
                Some((Ok(stream), conn))
            } else {
                Some((conn.accept_uni().await, conn))
            }
        }
    }))
}

impl<B> quic::Connection<B> for Connection
where
    B: Buf,
{
    type RecvStream = RecvStream;
    type OpenStreams = OpenStreams;

    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    fn poll_accept_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        let (send, recv) = ready!(self.incoming_bi.poll_next_unpin(cx))
            .expect("self.incoming_bi BoxStream never returns None")
            .map_err(convert_connection_error)?;
        Poll::Ready(Ok(Self::BidiStream {
            send: Self::SendStream::new(send),
            recv: Self::RecvStream::new(recv),
        }))
    }

    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    fn poll_accept_recv(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        let recv = ready!(self.incoming_uni.poll_next_unpin(cx))
            .expect("self.incoming_uni BoxStream never returns None")
            .map_err(convert_connection_error)?;
        Poll::Ready(Ok(Self::RecvStream::new(recv)))
    }

    fn opener(&self) -> Self::OpenStreams {
        OpenStreams {
            conn: self.conn.clone(),
            opening_bi: None,
            opening_uni: None,
        }
    }
}

pub(super) fn convert_connection_error(
    e: quinn::ConnectionError,
) -> h3::quic::ConnectionErrorIncoming {
    match e {
        quinn::ConnectionError::ApplicationClosed(application_close) => {
            ConnectionErrorIncoming::ApplicationClose {
                error_code: application_close.error_code.into(),
            }
        }
        quinn::ConnectionError::TimedOut => ConnectionErrorIncoming::Timeout,

        error @ (quinn::ConnectionError::VersionMismatch
        | quinn::ConnectionError::Reset
        | quinn::ConnectionError::LocallyClosed
        | quinn::ConnectionError::CidsExhausted
        | quinn::ConnectionError::TransportError(_)
        | quinn::ConnectionError::ConnectionClosed(_)) => {
            ConnectionErrorIncoming::Undefined(Arc::new(error))
        }
    }
}

impl<B> quic::OpenStreams<B> for Connection
where
    B: Buf,
{
    type SendStream = SendStream<B>;
    type BidiStream = BidiStream<B>;

    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    fn poll_open_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        let bi = self.opening_bi.get_or_insert_with(|| {
            Box::pin(futures_stream::unfold(self.conn.clone(), |conn| async {
                Some((conn.open_bi().await, conn))
            }))
        });
        let (send, recv) = ready!(bi.poll_next_unpin(cx))
            .expect("BoxStream does not return None")
            .map_err(|e| StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: convert_connection_error(e),
            })?;
        Poll::Ready(Ok(Self::BidiStream {
            send: Self::SendStream::new(send),
            recv: RecvStream::new(recv),
        }))
    }

    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    fn poll_open_send(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        let uni = self.opening_uni.get_or_insert_with(|| {
            Box::pin(futures_stream::unfold(self.conn.clone(), |conn| async {
                Some((conn.open_uni().await, conn))
            }))
        });

        let send = ready!(uni.poll_next_unpin(cx))
            .expect("BoxStream does not return None")
            .map_err(|e| StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: convert_connection_error(e),
            })?;
        Poll::Ready(Ok(Self::SendStream::new(send)))
    }

    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    fn close(&mut self, code: Code, reason: &[u8]) {
        self.conn.close(
            VarInt::from_u64(code.value()).expect("error code VarInt"),
            reason,
        );
    }
}

/// Stream opener backed by a Quinn connection
///
/// Implements [`quic::OpenStreams`] using [`quinn::Connection`],
/// [`quinn::OpenBi`], [`quinn::OpenUni`].
pub struct OpenStreams {
    conn: quinn::Connection,
    opening_bi: Option<BoxStreamSync<'static, <OpenBi<'static> as Future>::Output>>,
    opening_uni: Option<BoxStreamSync<'static, <OpenUni<'static> as Future>::Output>>,
}

impl<B> quic::OpenStreams<B> for OpenStreams
where
    B: Buf,
{
    type SendStream = SendStream<B>;
    type BidiStream = BidiStream<B>;

    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    fn poll_open_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        let bi = self.opening_bi.get_or_insert_with(|| {
            Box::pin(futures_stream::unfold(self.conn.clone(), |conn| async {
                Some((conn.open_bi().await, conn))
            }))
        });

        let (send, recv) = ready!(bi.poll_next_unpin(cx))
            .expect("BoxStream does not return None")
            .map_err(|e| StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: convert_connection_error(e),
            })?;
        Poll::Ready(Ok(Self::BidiStream {
            send: Self::SendStream::new(send),
            recv: RecvStream::new(recv),
        }))
    }

    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    fn poll_open_send(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        let uni = self.opening_uni.get_or_insert_with(|| {
            Box::pin(futures_stream::unfold(self.conn.clone(), |conn| async {
                Some((conn.open_uni().await, conn))
            }))
        });

        let send = ready!(uni.poll_next_unpin(cx))
            .expect("BoxStream does not return None")
            .map_err(|e| StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: convert_connection_error(e),
            })?;
        Poll::Ready(Ok(Self::SendStream::new(send)))
    }

    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    fn close(&mut self, code: Code, reason: &[u8]) {
        self.conn.close(
            VarInt::from_u64(code.value()).expect("error code VarInt"),
            reason,
        );
    }
}

impl Clone for OpenStreams {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn.clone(),
            opening_bi: None,
            opening_uni: None,
        }
    }
}
