use etherparse::{Icmpv4Type, Icmpv6Type, Ipv4HeaderSlice, Ipv6HeaderSlice, PacketBuilder};

/// Generates an ICMP "Packet Too Big" (PTB) error message to be sent back to
/// a VPN client when a packet exceeds the QUIC path MTU and cannot be forwarded.
///
/// This is used to implement Path MTU Discovery (PMTUD) from the VPN's perspective:
/// when the kernel/QUIC layer rejects a datagram as too large, we synthesise an
/// appropriate ICMP signal so the client's TCP/IP stack can adjust its segment size.
///
/// # Arguments
/// - `dropped_packet` – The original raw IP packet (IPv4 or IPv6) that was too large.
/// - `mtu` – The MTU value to report in the error (i.e. the maximum size the path supports).
/// - `source_ip_override` – Optional source IP for the generated ICMP packet.
///   When `Some`, the ICMP reply appears to come from that address (e.g. the VPN
///   gateway `10.8.0.1`). When `None`, the destination IP of the dropped packet
///   is used as the source (i.e. it appears to come from the remote internet host).
///
/// # Returns
/// - `Some(bytes)` – A fully-formed raw IP+ICMP packet ready to inject into the TUN device.
/// - `None` – If the dropped packet is empty, malformed, or has an unsupported IP version.
///
/// # Standards
/// - ICMPv4 "Fragmentation Needed" (Type 3 Code 4): RFC 792 / RFC 1191
/// - ICMPv6 "Packet Too Big"  (Type 2):             RFC 4443 / RFC 8201
pub fn generate_packet_too_big(
    dropped_packet: &[u8],
    mtu: u16,
    source_ip_override: Option<std::net::IpAddr>,
) -> Option<Vec<u8>> {
    if dropped_packet.is_empty() {
        return None;
    }

    let version = (dropped_packet[0] >> 4) & 0xF;

    match version {
        // --- IPv4: ICMPv4 "Destination Unreachable / Fragmentation Needed" ---
        4 => {
            let header_slice = Ipv4HeaderSlice::from_slice(dropped_packet).ok()?;
            let client_ip = header_slice.source_addr();
            let internet_ip = header_slice.destination_addr();

            // Determine the source address for the ICMP reply.
            // If an override is supplied (e.g. the VPN gateway), use it so the
            // error appears to originate from a known address within the VPN.
            let icmp_src = if let Some(std::net::IpAddr::V4(v4)) = source_ip_override {
                v4
            } else {
                internet_ip
            };

            // RFC 792: include the IP header + first 8 bytes of the original payload
            // so the client can identify which connection triggered the error.
            let ip_header_len = (header_slice.ihl() * 4) as usize;
            let bytes_to_include = std::cmp::min(dropped_packet.len(), ip_header_len + 8);
            let payload_slice = &dropped_packet[..bytes_to_include];

            let builder = PacketBuilder::ipv4(
                icmp_src.octets(),  // Source: gateway or remote host
                client_ip.octets(), // Destination: the VPN client
                64,                 // TTL
            )
            .icmpv4(Icmpv4Type::DestinationUnreachable(
                etherparse::icmpv4::DestUnreachableHeader::FragmentationNeeded {
                    next_hop_mtu: mtu,
                },
            ));

            let mut result = Vec::with_capacity(builder.size(payload_slice.len()));
            builder.write(&mut result, payload_slice).ok()?;
            Some(result)
        }

        // --- IPv6: ICMPv6 "Packet Too Big" (Type 2) ---
        6 => {
            let header_slice = Ipv6HeaderSlice::from_slice(dropped_packet).ok()?;
            let client_ip = header_slice.source_addr();
            let internet_ip = header_slice.destination_addr();

            let icmp_src = if let Some(std::net::IpAddr::V6(v6)) = source_ip_override {
                v6
            } else {
                internet_ip
            };

            // RFC 4443 §2.4: An ICMPv6 error message must not exceed 1280 bytes
            // (the IPv6 minimum MTU). The invoking packet is truncated to fit.
            // 1232 = 1280 - 40 (IPv6 header) - 8 (ICMPv6 header)
            let max_payload = 1232;
            let bytes_to_include = std::cmp::min(dropped_packet.len(), max_payload);
            let payload_slice = &dropped_packet[..bytes_to_include];

            let builder = PacketBuilder::ipv6(
                icmp_src.octets(),  // Source: gateway or remote host
                client_ip.octets(), // Destination: the VPN client
                64,                 // Hop Limit (equiv. of TTL)
            )
            .icmpv6(Icmpv6Type::PacketTooBig { mtu: mtu as u32 });

            let mut result = Vec::with_capacity(builder.size(payload_slice.len()));
            builder.write(&mut result, payload_slice).ok()?;
            Some(result)
        }

        // Unknown IP version — silently drop
        _ => None,
    }
}
