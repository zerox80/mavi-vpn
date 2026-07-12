//! Shared HTTP/2 transport tuning.

/// Initial receive window advertised by clients for the CONNECT-IP stream.
///
/// HTTP/2 defaults to 65,535 bytes, which is far below the bandwidth-delay
/// product of typical mobile links and throttles server-to-client traffic.
pub const CLIENT_INITIAL_STREAM_WINDOW_SIZE: u32 = 4 * 1024 * 1024;

/// Initial receive window advertised by clients for the entire connection.
///
/// CONNECT-IP currently uses one long-lived stream, so the connection window
/// must be at least as large as the stream window or it remains the bottleneck.
pub const CLIENT_INITIAL_CONNECTION_WINDOW_SIZE: u32 = CLIENT_INITIAL_STREAM_WINDOW_SIZE;

const _: () = assert!(CLIENT_INITIAL_STREAM_WINDOW_SIZE > 65_535);
const _: () = assert!(CLIENT_INITIAL_CONNECTION_WINDOW_SIZE >= CLIENT_INITIAL_STREAM_WINDOW_SIZE);
