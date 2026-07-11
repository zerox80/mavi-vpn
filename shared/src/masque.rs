//! MASQUE connect-ip (RFC 9484) capsule protocol + datagram framing helpers.
//!
//! This module implements the wire-format pieces needed for HTTP/3 connect-ip
//! (IETF MASQUE IP-level tunneling):
//! - QUIC variable-length integer encoding (RFC 9000 §16)
//! - Capsule Protocol framing (RFC 9297 §3.2)
//! - `ADDRESS_ASSIGN` and `ROUTE_ADVERTISEMENT` capsules (RFC 9484 §4)
//! - HTTP/3 Datagram framing with Quarter Stream ID + Context ID (RFC 9484 §5)
//!
//! Mavi also emits a vendor-specific `MAVI_CONFIG` capsule (type 0x4D56 =
//! "MV") that carries the full bincode-encoded `ControlMessage::Config`
//! alongside the IETF capsules, so the client can receive DNS servers,
//! whitelist domains, MTU, etc. External MASQUE clients simply ignore unknown
//! capsules (RFC 9297 §3.2 requires it), so emitting this capsule does not
//! compromise the DPI-resistance of the connect-ip wire format.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// RFC 9484 – `ADDRESS_ASSIGN` (IP address(es) assigned to the client).
pub const CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;
/// RFC 9484 – `ADDRESS_REQUEST` (client → server request for addresses).
pub const CAPSULE_ADDRESS_REQUEST: u64 = 0x02;
/// RFC 9484 – `ROUTE_ADVERTISEMENT` (IP ranges the tunnel can reach).
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;
/// RFC 9297 -- reliable HTTP Datagram carried on a Capsule Protocol data stream.
///
/// On HTTP/2 over TCP this is how CONNECT-IP conveys an IP packet. The payload
/// is the normal CONNECT-IP HTTP Datagram payload: Context ID 0 followed by the
/// complete IP packet (RFC 9484 section 6).
pub const CAPSULE_DATAGRAM: u64 = 0x00;
/// Vendor-specific capsule carrying `ControlMessage::Config` (bincode).
/// Value "MV" (0x4D56). Unknown capsule types MUST be ignored per RFC 9297.
pub const CAPSULE_MAVI_CONFIG: u64 = 0x4D56;
/// Vendor-specific capsule carrying `ControlMessage::Reauth` (bincode).
pub const CAPSULE_MAVI_REAUTH: u64 = 0x4D57;
/// Vendor-specific capsule carrying `ControlMessage::ReauthResult` (bincode).
pub const CAPSULE_MAVI_REAUTH_RESULT: u64 = 0x4D58;

/// HTTP/3 datagram framing for connect-ip on the first request stream:
/// `[Quarter Stream ID (varint)] [Context ID (varint)] [IP Packet]`.
///
/// For stream ID 0 the Quarter Stream ID is 0, and for uncompressed IP
/// payloads the Context ID is 0 – both encode to a single `0x00` byte,
/// giving a 2-byte prefix. We hard-code this for the hot path; the
/// `unwrap_datagram` accepts non-canonical encodings of those zero values,
/// but rejects packets for any other request stream or context.
///
/// This hard-coding relies on the invariant that Mavi sends exactly one
/// extended CONNECT request per H3 connection and that it lands on the
/// first client-initiated bidirectional stream (ID 0), whose Quarter
/// Stream ID is `0 >> 2 == 0`. If that ever changes (multiple CONNECT-IP
/// requests, or h3-quinn opening other bidi streams first), this prefix
/// must be derived dynamically from the actual stream ID.
pub const DATAGRAM_PREFIX: [u8; 2] = [0x00, 0x00];

/// Hard upper bound on how many unparsed capsule bytes a client will
/// accumulate before bailing out.
///
/// This exists to prevent a misbehaving or hostile server from pushing the
/// client into unbounded memory growth while it waits for the vendor
/// `MAVI_CONFIG` capsule. 64 KiB comfortably fits several `ADDRESS_ASSIGN` /
/// `ROUTE_ADVERTISEMENT` entries plus a full bincode-serialized
/// `ControlMessage::Config`.
pub const MAX_CAPSULE_BUF: usize = 64 * 1024;

// --------------------------------------------------------------------------
// QUIC varints (RFC 9000 §16)
// --------------------------------------------------------------------------

/// Writes a QUIC varint (RFC 9000 §16) to `buf`.
///
/// # Panics
/// Panics if `value >= 2^62`. Every call site in this crate passes a
/// locally-known, compile-time-bounded value (a capsule type constant or a
/// local buffer length) — never an attacker- or network-supplied value
/// directly. Keep it that way: validate any externally-derived length
/// before it reaches this function.
#[allow(clippy::cast_possible_truncation)]
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
        panic!("varint out of range: {value}");
    }
}

/// Number of bytes `value` will occupy when encoded as a varint.
///
/// # Panics
/// Panics if `value >= 2^62`. See [`write_varint`]'s panics note — the same
/// call-site invariant applies here.
#[must_use]
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
        panic!("varint out of range: {value}")
    }
}

/// Reads a varint from the head of `buf`. Returns `(value, bytes_consumed)`
/// or `None` if the buffer is truncated.
#[must_use]
pub fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let len = 1usize << (buf[0] >> 6);
    if buf.len() < len {
        return None;
    }
    let mut v = u64::from(buf[0] & 0x3F);
    for byte in &buf[1..len] {
        v = (v << 8) | u64::from(*byte);
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
#[must_use]
pub fn read_capsule(buf: &[u8]) -> Option<(u64, &[u8], usize)> {
    let (capsule_type, n1) = read_varint(buf)?;
    let rest = &buf[n1..];
    let (payload_len, n2) = read_varint(rest)?;
    let start = n1 + n2;
    let payload_len_usize = usize::try_from(payload_len).ok()?;
    let end = start.checked_add(payload_len_usize)?;
    if buf.len() < end {
        return None;
    }
    Some((capsule_type, &buf[start..end], end))
}

/// Encodes one reliable HTTP Datagram capsule for a CONNECT-IP packet.
///
/// The Context ID is zero because Mavi creates no additional IP contexts.
#[must_use]
pub fn encode_connect_ip_datagram_capsule(ip_packet: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(ip_packet.len() + 1);
    write_varint(0, &mut payload);
    payload.extend_from_slice(ip_packet);

    let mut capsule = Vec::with_capacity(payload.len() + 2);
    encode_capsule(CAPSULE_DATAGRAM, &payload, &mut capsule);
    capsule
}

/// Decodes a CONNECT-IP HTTP Datagram payload from a DATAGRAM capsule.
///
/// Returns `None` for malformed payloads, an empty IP packet, or an unknown
/// context ID. RFC 9484 reserves Context ID zero for complete IP packets;
/// Mavi does not negotiate any additional contexts.
#[must_use]
pub fn decode_connect_ip_datagram_payload(payload: &[u8]) -> Option<&[u8]> {
    let (context_id, context_len) = read_varint(payload)?;
    if context_id != 0 {
        return None;
    }
    let packet = &payload[context_len..];
    (!packet.is_empty()).then_some(packet)
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
#[must_use]
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
#[must_use]
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
#[must_use]
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
#[must_use]
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
#[must_use]
pub fn wrap_datagram(ip_packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ip_packet.len() + DATAGRAM_PREFIX.len());
    out.extend_from_slice(&DATAGRAM_PREFIX);
    out.extend_from_slice(ip_packet);
    out
}

/// Extracts the IP packet out of a connect-ip datagram frame. Returns `None`
/// if the prefix is truncated or identifies another request stream or context.
#[must_use]
pub fn unwrap_datagram(datagram: &[u8]) -> Option<&[u8]> {
    // Fast path: both varints encode as a single 0x00 byte.
    if datagram.len() >= 2 && datagram[0] == 0x00 && datagram[1] == 0x00 {
        return Some(&datagram[2..]);
    }
    // General path: accepts non-canonical encodings for Mavi's single stream
    // and context, but never maps another CONNECT request into this tunnel.
    let (qsid, n1) = read_varint(datagram)?;
    let rest = &datagram[n1..];
    let (context_id, n2) = read_varint(rest)?;
    (qsid == 0 && context_id == 0).then_some(&datagram[n1 + n2..])
}

#[cfg(test)]
mod tests;
