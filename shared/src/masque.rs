//! MASQUE connect-ip (RFC 9484) capsule protocol + datagram framing helpers.
//!
//! This module implements the wire-format pieces needed for HTTP/3 connect-ip
//! (IETF MASQUE IP-level tunneling):
//! - QUIC variable-length integer encoding (RFC 9000 §16)
//! - Capsule Protocol framing (RFC 9297 §3.2)
//! - ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT capsules (RFC 9484 §4)
//! - HTTP/3 Datagram framing with Quarter Stream ID + Context ID (RFC 9484 §5)
//!
//! Mavi also emits a vendor-specific `MAVI_CONFIG` capsule (type 0x4D56 =
//! "MV") that carries the full bincode-encoded `ControlMessage::Config`
//! alongside the IETF capsules, so the client can receive DNS servers,
//! whitelist domains, MTU, etc. External MASQUE clients simply ignore unknown
//! capsules (RFC 9297 §3.2 requires it), so emitting this capsule does not
//! compromise the DPI-resistance of the connect-ip wire format.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// RFC 9484 – ADDRESS_ASSIGN (IP address(es) assigned to the client).
pub const CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;
/// RFC 9484 – ADDRESS_REQUEST (client → server request for addresses).
pub const CAPSULE_ADDRESS_REQUEST: u64 = 0x02;
/// RFC 9484 – ROUTE_ADVERTISEMENT (IP ranges the tunnel can reach).
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;
/// Vendor-specific capsule carrying `ControlMessage::Config` (bincode).
/// Value "MV" (0x4D56). Unknown capsule types MUST be ignored per RFC 9297.
pub const CAPSULE_MAVI_CONFIG: u64 = 0x4D56;

/// HTTP/3 datagram framing for connect-ip on the first request stream:
/// `[Quarter Stream ID (varint)] [Context ID (varint)] [IP Packet]`.
///
/// For stream ID 0 the Quarter Stream ID is 0, and for uncompressed IP
/// payloads the Context ID is 0 – both encode to a single `0x00` byte,
/// giving a 2-byte prefix. We hard-code this for the hot path; the
/// `unwrap_datagram` helper still accepts any varint-encoded values.
///
/// This hard-coding relies on the invariant that Mavi sends exactly one
/// extended CONNECT request per H3 connection and that it lands on the
/// first client-initiated bidirectional stream (ID 0), whose Quarter
/// Stream ID is `0 >> 2 == 0`. If that ever changes (multiple CONNECT-IP
/// requests, or h3-quinn opening other bidi streams first), this prefix
/// must be derived dynamically from the actual stream ID.
pub const DATAGRAM_PREFIX: [u8; 2] = [0x00, 0x00];

/// Hard upper bound on how many unparsed capsule bytes a client will
/// accumulate before bailing out. This exists to prevent a misbehaving or
/// hostile server from pushing the client into unbounded memory growth
/// while it waits for the vendor `MAVI_CONFIG` capsule. 64 KiB comfortably
/// fits several ADDRESS_ASSIGN / ROUTE_ADVERTISEMENT entries plus a full
/// bincode-serialized `ControlMessage::Config`.
pub const MAX_CAPSULE_BUF: usize = 64 * 1024;

// --------------------------------------------------------------------------
// QUIC varints (RFC 9000 §16)
// --------------------------------------------------------------------------

/// Writes a QUIC varint (RFC 9000 §16) to `buf`.
///
/// Panics if `value >= 2^62`.
pub fn write_varint(value: u64, buf: &mut Vec<u8>) {
    if value < (1 << 6) {
        buf.push(value as u8);
    } else if value < (1 << 14) {
        let v = (value as u16) | 0x4000;
        buf.extend_from_slice(&v.to_be_bytes());
    } else if value < (1 << 30) {
        let v = (value as u32) | 0x8000_0000;
        buf.extend_from_slice(&v.to_be_bytes());
    } else if value < (1 << 62) {
        let v = value | 0xC000_0000_0000_0000;
        buf.extend_from_slice(&v.to_be_bytes());
    } else {
        panic!("varint out of range: {}", value);
    }
}

/// Number of bytes `value` will occupy when encoded as a varint.
pub fn varint_len(value: u64) -> usize {
    if value < (1 << 6) {
        1
    } else if value < (1 << 14) {
        2
    } else if value < (1 << 30) {
        4
    } else if value < (1 << 62) {
        8
    } else {
        panic!("varint out of range: {}", value)
    }
}

/// Reads a varint from the head of `buf`. Returns `(value, bytes_consumed)`
/// or `None` if the buffer is truncated.
pub fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let len = 1usize << (buf[0] >> 6);
    if buf.len() < len {
        return None;
    }
    let mut v = (buf[0] & 0x3F) as u64;
    for byte in &buf[1..len] {
        v = (v << 8) | (*byte as u64);
    }
    Some((v, len))
}

// --------------------------------------------------------------------------
// Capsule framing (RFC 9297 §3.2)
// --------------------------------------------------------------------------

/// Appends a complete capsule frame `[Type (varint)] [Length (varint)] [Payload]`
/// to `out`.
pub fn encode_capsule(capsule_type: u64, payload: &[u8], out: &mut Vec<u8>) {
    write_varint(capsule_type, out);
    write_varint(payload.len() as u64, out);
    out.extend_from_slice(payload);
}

/// Reads one capsule from the head of `buf`. Returns `(type, payload, total_bytes)`
/// or `None` if the buffer does not yet contain a full capsule.
///
/// Returns `None` (instead of panicking or wrapping) if the advertised
/// capsule length cannot be represented as `usize` on the current target
/// — this matters on 32-bit platforms like armv7 Android where `u64 as
/// usize` would truncate.
pub fn read_capsule(buf: &[u8]) -> Option<(u64, &[u8], usize)> {
    let (ctype, n1) = read_varint(buf)?;
    let rest = &buf[n1..];
    let (clen, n2) = read_varint(rest)?;
    let start = n1 + n2;
    let clen_usize = usize::try_from(clen).ok()?;
    let end = start.checked_add(clen_usize)?;
    if buf.len() < end {
        return None;
    }
    Some((ctype, &buf[start..end], end))
}

// --------------------------------------------------------------------------
// ADDRESS_ASSIGN capsule (RFC 9484 §4.1)
// --------------------------------------------------------------------------

/// A single entry in an `ADDRESS_ASSIGN` capsule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssignedAddress {
    /// Request ID this assignment answers (0 for unsolicited).
    pub request_id: u64,
    /// Assigned IP address (v4 or v6).
    pub ip: IpAddr,
    /// Prefix length in bits.
    pub prefix_len: u8,
}

/// Encodes the payload of an `ADDRESS_ASSIGN` capsule (not the outer frame).
pub fn encode_address_assign(assigns: &[AssignedAddress]) -> Vec<u8> {
    let mut payload = Vec::new();
    for a in assigns {
        write_varint(a.request_id, &mut payload);
        match a.ip {
            IpAddr::V4(v4) => {
                payload.push(4);
                payload.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                payload.push(6);
                payload.extend_from_slice(&v6.octets());
            }
        }
        payload.push(a.prefix_len);
    }
    payload
}

/// Decodes the payload of an `ADDRESS_ASSIGN` capsule.
pub fn decode_address_assign(mut payload: &[u8]) -> Option<Vec<AssignedAddress>> {
    let mut out = Vec::new();
    while !payload.is_empty() {
        let (request_id, n) = read_varint(payload)?;
        payload = &payload[n..];
        if payload.is_empty() {
            return None;
        }
        let ver = payload[0];
        payload = &payload[1..];
        let ip = match ver {
            4 => {
                if payload.len() < 4 {
                    return None;
                }
                let v4 = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
                payload = &payload[4..];
                IpAddr::V4(v4)
            }
            6 => {
                if payload.len() < 16 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&payload[..16]);
                payload = &payload[16..];
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return None,
        };
        if payload.is_empty() {
            return None;
        }
        let prefix_len = payload[0];
        payload = &payload[1..];
        out.push(AssignedAddress {
            request_id,
            ip,
            prefix_len,
        });
    }
    Some(out)
}

// --------------------------------------------------------------------------
// ROUTE_ADVERTISEMENT capsule (RFC 9484 §4.3)
// --------------------------------------------------------------------------

/// A single entry in a `ROUTE_ADVERTISEMENT` capsule.
///
/// `start` and `end` must be the same IP version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpAddressRange {
    pub start: IpAddr,
    pub end: IpAddr,
    /// IP protocol number. `0` means all protocols.
    pub ip_protocol: u8,
}

/// Encodes the payload of a `ROUTE_ADVERTISEMENT` capsule.
pub fn encode_route_advertisement(ranges: &[IpAddressRange]) -> Vec<u8> {
    let mut payload = Vec::new();
    for r in ranges {
        match (r.start, r.end) {
            (IpAddr::V4(s), IpAddr::V4(e)) => {
                payload.push(4);
                payload.extend_from_slice(&s.octets());
                payload.extend_from_slice(&e.octets());
            }
            (IpAddr::V6(s), IpAddr::V6(e)) => {
                payload.push(6);
                payload.extend_from_slice(&s.octets());
                payload.extend_from_slice(&e.octets());
            }
            _ => continue,
        }
        payload.push(r.ip_protocol);
    }
    payload
}

/// Decodes the payload of a `ROUTE_ADVERTISEMENT` capsule.
pub fn decode_route_advertisement(mut payload: &[u8]) -> Option<Vec<IpAddressRange>> {
    let mut out = Vec::new();
    while !payload.is_empty() {
        let ver = payload[0];
        payload = &payload[1..];
        let (start, end) = match ver {
            4 => {
                if payload.len() < 8 {
                    return None;
                }
                let s = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
                let e = Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]);
                payload = &payload[8..];
                (IpAddr::V4(s), IpAddr::V4(e))
            }
            6 => {
                if payload.len() < 32 {
                    return None;
                }
                let mut so = [0u8; 16];
                let mut eo = [0u8; 16];
                so.copy_from_slice(&payload[..16]);
                eo.copy_from_slice(&payload[16..32]);
                payload = &payload[32..];
                (
                    IpAddr::V6(Ipv6Addr::from(so)),
                    IpAddr::V6(Ipv6Addr::from(eo)),
                )
            }
            _ => return None,
        };
        if payload.is_empty() {
            return None;
        }
        let ip_protocol = payload[0];
        payload = &payload[1..];
        out.push(IpAddressRange {
            start,
            end,
            ip_protocol,
        });
    }
    Some(out)
}

// --------------------------------------------------------------------------
// HTTP/3 datagram framing (RFC 9484 §5)
// --------------------------------------------------------------------------

/// Wraps an IP packet in the connect-ip datagram frame.
pub fn wrap_datagram(ip_packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ip_packet.len() + DATAGRAM_PREFIX.len());
    out.extend_from_slice(&DATAGRAM_PREFIX);
    out.extend_from_slice(ip_packet);
    out
}

/// Extracts the IP packet out of a connect-ip datagram frame. Returns `None`
/// if the prefix is truncated.
pub fn unwrap_datagram(datagram: &[u8]) -> Option<&[u8]> {
    // Fast path: both varints encode as a single 0x00 byte.
    if datagram.len() >= 2 && datagram[0] == 0x00 && datagram[1] == 0x00 {
        return Some(&datagram[2..]);
    }
    // General path: handles any varint-encoded Quarter Stream ID / Context ID.
    let (_qsid, n1) = read_varint(datagram)?;
    let rest = &datagram[n1..];
    let (_ctx, n2) = read_varint(rest)?;
    Some(&datagram[n1 + n2..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip_known_boundaries() {
        for v in [
            0u64,
            1,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            (1u64 << 62) - 1,
        ] {
            let mut buf = Vec::new();
            write_varint(v, &mut buf);
            assert_eq!(buf.len(), varint_len(v), "len mismatch for {}", v);
            let (dec, n) = read_varint(&buf).unwrap();
            assert_eq!(dec, v);
            assert_eq!(n, buf.len());
        }
    }

    #[test]
    fn varint_truncated_buffer_returns_none() {
        // 2-byte varint header (0x40..) but only 1 byte provided.
        assert!(read_varint(&[0x40]).is_none());
    }

    #[test]
    fn address_assign_roundtrip_v4_and_v6() {
        let assigns = vec![
            AssignedAddress {
                request_id: 1,
                ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
                prefix_len: 24,
            },
            AssignedAddress {
                request_id: 2,
                ip: IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
                prefix_len: 64,
            },
        ];
        let payload = encode_address_assign(&assigns);
        let decoded = decode_address_assign(&payload).unwrap();
        assert_eq!(decoded, assigns);
    }

    #[test]
    fn route_advertisement_roundtrip() {
        let ranges = vec![
            IpAddressRange {
                start: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                end: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
                ip_protocol: 0,
            },
            IpAddressRange {
                start: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                end: IpAddr::V6(Ipv6Addr::from([0xff; 16])),
                ip_protocol: 0,
            },
        ];
        let payload = encode_route_advertisement(&ranges);
        let decoded = decode_route_advertisement(&payload).unwrap();
        assert_eq!(decoded, ranges);
    }

    #[test]
    fn capsule_frame_roundtrip() {
        let inner = vec![0xaa, 0xbb, 0xcc];
        let mut buf = Vec::new();
        encode_capsule(CAPSULE_ADDRESS_ASSIGN, &inner, &mut buf);
        // Extra trailing bytes must not confuse the parser.
        buf.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let (t, p, n) = read_capsule(&buf).unwrap();
        assert_eq!(t, CAPSULE_ADDRESS_ASSIGN);
        assert_eq!(p, &inner[..]);
        assert_eq!(&buf[n..], &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn datagram_wrap_roundtrip() {
        let packet = b"hello world IP packet";
        let wrapped = wrap_datagram(packet);
        assert_eq!(&wrapped[..2], &DATAGRAM_PREFIX);
        assert_eq!(unwrap_datagram(&wrapped).unwrap(), packet);
    }

    #[test]
    fn unwrap_datagram_rejects_truncation() {
        assert!(unwrap_datagram(&[]).is_none());
        assert!(unwrap_datagram(&[0x00]).is_none());
    }

    #[test]
    fn varint_encode_1_byte_boundary() {
        let mut buf = Vec::new();
        write_varint(0, &mut buf);
        assert_eq!(buf, vec![0x00]);

        let mut buf = Vec::new();
        write_varint(63, &mut buf);
        assert_eq!(buf, vec![0x3F]);
    }

    #[test]
    fn varint_encode_2_byte_boundary() {
        let mut buf = Vec::new();
        write_varint(64, &mut buf);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf[0] >> 6, 1);

        let mut buf = Vec::new();
        write_varint(16383, &mut buf);
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn read_varint_empty_buffer() {
        assert!(read_varint(&[]).is_none());
    }

    #[test]
    fn address_assign_empty() {
        let payload = encode_address_assign(&[]);
        assert!(payload.is_empty());
        let decoded = decode_address_assign(&payload).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn route_advertisement_empty() {
        let payload = encode_route_advertisement(&[]);
        assert!(payload.is_empty());
        let decoded = decode_route_advertisement(&payload).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn decode_route_advertisement_invalid_version() {
        // Version byte 0x05 is not a valid IP version (must be 4 or 6).
        assert!(decode_route_advertisement(&[0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn encode_route_advertisement_skips_mixed_versions() {
        let ranges = vec![IpAddressRange {
            start: IpAddr::V4(Ipv4Addr::LOCALHOST),
            end: IpAddr::V6(Ipv6Addr::LOCALHOST),
            ip_protocol: 6,
        }];
        assert!(encode_route_advertisement(&ranges).is_empty());
    }

    #[test]
    fn capsule_truncated_returns_none() {
        let mut buf = Vec::new();
        encode_capsule(CAPSULE_ADDRESS_ASSIGN, &[0xaa, 0xbb], &mut buf);
        let truncated = &buf[..buf.len() - 1];
        assert!(read_capsule(truncated).is_none());
    }

    #[test]
    fn datagram_wrap_empty_packet() {
        let wrapped = wrap_datagram(&[]);
        assert_eq!(&wrapped[..2], &DATAGRAM_PREFIX);
        let unwrapped = unwrap_datagram(&wrapped).unwrap();
        assert!(unwrapped.is_empty());
    }

    proptest::proptest! {
        #[test]
        fn varint_roundtrip_proptest(v in 0u64..(1u64 << 62)) {
            let mut buf = Vec::new();
            write_varint(v, &mut buf);
            let (decoded, n) = read_varint(&buf).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(n, buf.len());
        }

        #[test]
        fn datagram_roundtrip_proptest(data in proptest::collection::vec(0u8..=255, 0..1500)) {
            let wrapped = wrap_datagram(&data);
            let unwrapped = unwrap_datagram(&wrapped).unwrap();
            assert_eq!(unwrapped, &data[..]);
        }
    }
}
