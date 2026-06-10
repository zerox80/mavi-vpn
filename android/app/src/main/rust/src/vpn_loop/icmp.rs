// Called only from the cfg(target_os = "android") vpn loop; on other hosts it
// is exercised solely by the unit tests below.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn packet_too_big_feedback(
    packet: &[u8],
    tunnel_mtu: u16,
    max_datagram: Option<usize>,
    h3_prefix: usize,
    gateway_v4: std::net::Ipv4Addr,
    gateway_v6: Option<std::net::Ipv6Addr>,
) -> Option<Vec<u8>> {
    if packet.is_empty() {
        return None;
    }

    let version = (packet[0] >> 4) & 0xF;
    let gateway = match version {
        4 => Some(std::net::IpAddr::V4(gateway_v4)),
        6 => gateway_v6.map(std::net::IpAddr::V6),
        _ => None,
    };
    // Report the QUIC-transportable inner-packet size (max_datagram minus any
    // H3 prefix), not the configured TUN MTU, so PMTUD actually converges.
    let reported_mtu = shared::effective_ptb_mtu(tunnel_mtu, max_datagram, h3_prefix, version == 6);

    shared::icmp::generate_packet_too_big(packet, reported_mtu, gateway)
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{Ipv4Header, Ipv6Header};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ipv4_packet() -> Vec<u8> {
        let header = Ipv4Header::new(
            8,
            64,
            etherparse::IpNumber::TCP,
            Ipv4Addr::new(10, 0, 0, 2).octets(),
            Ipv4Addr::new(8, 8, 8, 8).octets(),
        )
        .unwrap();
        let mut packet = Vec::new();
        header.write(&mut packet).unwrap();
        packet.extend_from_slice(b"payload!");
        packet
    }

    fn ipv6_packet() -> Vec<u8> {
        let header = Ipv6Header {
            traffic_class: 0,
            flow_label: etherparse::Ipv6FlowLabel::ZERO,
            payload_length: 8,
            next_header: etherparse::IpNumber::TCP,
            hop_limit: 64,
            source: Ipv6Addr::LOCALHOST.octets(),
            destination: Ipv6Addr::LOCALHOST.octets(),
        };
        let mut packet = Vec::new();
        header.write(&mut packet).unwrap();
        packet.extend_from_slice(b"payload!");
        packet
    }

    #[test]
    fn too_large_ipv4_packet_generates_feedback() {
        let feedback = packet_too_big_feedback(
            &ipv4_packet(),
            1280,
            Some(1330),
            0,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
        );

        assert!(feedback.is_some());
    }

    #[test]
    fn too_large_ipv6_packet_reports_minimum_ipv6_mtu() {
        let feedback = packet_too_big_feedback(
            &ipv6_packet(),
            1200,
            Some(1000),
            0,
            Ipv4Addr::new(10, 0, 0, 1),
            Some(Ipv6Addr::LOCALHOST),
        )
        .unwrap();

        assert!(feedback.len() >= 48);
    }

    #[test]
    fn too_large_feedback_ignores_empty_packet() {
        let feedback =
            packet_too_big_feedback(&[], 1280, Some(1330), 0, Ipv4Addr::new(10, 0, 0, 1), None);

        assert!(feedback.is_none());
    }
}
