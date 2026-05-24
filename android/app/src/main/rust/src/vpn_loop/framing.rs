use shared::masque;

pub(crate) fn tun_payload_for_quic(framed: bytes::Bytes, http3_framing: bool) -> bytes::Bytes {
    if http3_framing {
        framed
    } else {
        framed.slice(masque::DATAGRAM_PREFIX.len()..)
    }
}

pub(crate) fn quic_datagram_to_tun_packet(
    datagram: bytes::Bytes,
    http3_framing: bool,
) -> Option<bytes::Bytes> {
    if http3_framing {
        masque::unwrap_datagram(&datagram).map(|inner| {
            let prefix = datagram.len() - inner.len();
            datagram.slice(prefix..)
        })
    } else if datagram.is_empty() {
        None
    } else {
        Some(datagram)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_payload_preserves_masque_prefix_for_h3() {
        let framed = masque::wrap_datagram(&bytes::Bytes::from_static(b"abc"));

        let payload = tun_payload_for_quic(framed.clone().into(), true);

        assert_eq!(payload, framed);
        assert!(payload.starts_with(&masque::DATAGRAM_PREFIX));
    }

    #[test]
    fn tun_payload_strips_masque_prefix_for_raw_quic() {
        let framed = masque::wrap_datagram(&bytes::Bytes::from_static(b"abc"));

        let payload = tun_payload_for_quic(framed.into(), false);

        assert_eq!(&payload[..], b"abc");
    }

    #[test]
    fn quic_datagram_unwraps_h3_and_drops_invalid_packets() {
        let framed = masque::wrap_datagram(&bytes::Bytes::from_static(b"abc"));

        let packet = quic_datagram_to_tun_packet(framed.into(), true).unwrap();
        let invalid = quic_datagram_to_tun_packet(bytes::Bytes::from_static(b"abc"), true);

        assert_eq!(&packet[..], b"abc");
        assert!(invalid.is_none());
    }

    #[test]
    fn quic_datagram_drops_empty_raw_packet() {
        assert!(quic_datagram_to_tun_packet(bytes::Bytes::new(), false).is_none());
    }
}
