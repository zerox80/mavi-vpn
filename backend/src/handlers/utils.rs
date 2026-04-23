use std::{net::{Ipv4Addr, Ipv6Addr}, sync::Arc, time::Duration};
use anyhow::Result;
use tracing::info;
use crate::state::AppState;

/// Convert an IPv4 dotted-decimal netmask to a CIDR prefix length in bits.
/// Non-contiguous masks (not realistic on a VPN subnet) fall back to `/32`.
pub fn prefix_len_from_mask(mask: Ipv4Addr) -> u8 {
    let bits = u32::from(mask);
    let ones = bits.count_ones() as u8;
    // Require the mask to be contiguous: all ones followed by all zeros.
    if bits.leading_ones() + bits.trailing_zeros() == 32 {
        ones
    } else {
        32
    }
}

pub struct IpGuard {
    pub state: Arc<AppState>,
    pub ip4: Ipv4Addr,
    pub ip6: Ipv6Addr,
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        self.state.release_ips(self.ip4, self.ip6);
        info!("Released IPs for dropped connection: {} / {}", self.ip4, self.ip6);
    }
}

pub fn negotiated_alpn(connection: &quinn::Connection) -> Option<Vec<u8>> {
    let handshake_data = connection.handshake_data()?;
    let handshake_data = handshake_data
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?;
    handshake_data.protocol.clone()
}

/// Extract the SNI (Server Name Indication) that the client presented during
/// the TLS handshake.  Returns `None` when the client omitted the SNI
/// extension (uncommon but valid) or when the handshake data is unavailable.
pub fn negotiated_sni(connection: &quinn::Connection) -> Option<String> {
    let handshake_data = connection.handshake_data()?;
    let handshake_data = handshake_data
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?;
    handshake_data.server_name.clone()
}

pub async fn emulate_http3(conn: &quinn::Connection, stream: &mut quinn::SendStream) -> Result<()> {
    if let Ok(mut ctrl) = conn.open_uni().await {
        let _ = ctrl.write_all(&[0x00, 0x04, 0x00]).await;
        let _ = ctrl.finish();
    }
    let mut resp = vec![0x01, 0x19];
    resp.extend_from_slice(&[0x00, 0x00, 0xd9, 0x5f, 0x4d, 0x84, 0xaa, 0x63, 0x55, 0xe7, 0x5f, 0x1d, 0x87, 0x49, 0x7c, 0xa5, 0x89, 0xd3, 0x4d, 0x1f, 0x54, 0x03, 0x31, 0x37, 0x33]);
    let body = b"<html><body><h1>Welcome</h1></body></html>";
    resp.push(0x00); resp.push(body.len() as u8);
    resp.extend_from_slice(body);
    let _ = stream.write_all(&resp).await;
    let _ = stream.finish();
    tokio::time::sleep(Duration::from_millis(50)).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_len_slash_24() {
        assert_eq!(prefix_len_from_mask(Ipv4Addr::new(255, 255, 255, 0)), 24);
    }

    #[test]
    fn prefix_len_slash_16() {
        assert_eq!(prefix_len_from_mask(Ipv4Addr::new(255, 255, 0, 0)), 16);
    }

    #[test]
    fn prefix_len_slash_8() {
        assert_eq!(prefix_len_from_mask(Ipv4Addr::new(255, 0, 0, 0)), 8);
    }

    #[test]
    fn prefix_len_slash_32() {
        assert_eq!(prefix_len_from_mask(Ipv4Addr::new(255, 255, 255, 255)), 32);
    }

    #[test]
    fn prefix_len_slash_0() {
        assert_eq!(prefix_len_from_mask(Ipv4Addr::new(0, 0, 0, 0)), 0);
    }

    #[test]
    fn prefix_len_slash_25() {
        assert_eq!(prefix_len_from_mask(Ipv4Addr::new(255, 255, 255, 128)), 25);
    }

    #[test]
    fn prefix_len_non_contiguous_fallback() {
        // Non-contiguous mask like 255.0.255.0 should fall back to /32
        assert_eq!(prefix_len_from_mask(Ipv4Addr::new(255, 0, 255, 0)), 32);
    }
}
