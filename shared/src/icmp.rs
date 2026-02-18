use etherparse::{Icmpv4Type, Icmpv6Type, Ipv4HeaderSlice, Ipv6HeaderSlice, PacketBuilder};

/// Generates an ICMP "Packet Too Big" message in response to a dropped packet.
/// 
/// - `dropped_packet`: The full raw packet that was too large.
/// - `mtu`: The MTU that the sender *should* have respected (e.g., 1220).
/// 
/// Returns `Some(Vec<u8>)` containing the raw IP+ICMP packet to send back to the source,
/// or `None` if the dropped packet was not a valid IP packet or shouldn't trigger an ICMP error.
/// Generates an ICMP "Packet Too Big" message in response to a dropped packet.
/// 
/// - `dropped_packet`: The full raw packet that was too large.
/// - `mtu`: The MTU that the sender *should* have respected (e.g., 1220).
/// - `source_ip_override`: Optional Source IP for the ICMP packet (e.g. the Gateway 10.0.0.1).
/// 
/// Returns `Some(Vec<u8>)` containing the raw IP+ICMP packet to send back to the source,
/// or `None` if the dropped packet was not a valid IP packet or shouldn't trigger an ICMP error.
pub fn generate_packet_too_big(dropped_packet: &[u8], mtu: u16, source_ip_override: Option<std::net::IpAddr>) -> Option<Vec<u8>> {
    if dropped_packet.is_empty() {
        return None;
    }

    let version = (dropped_packet[0] >> 4) & 0xF;

    match version {
        4 => {
            let header_slice = Ipv4HeaderSlice::from_slice(dropped_packet).ok()?;
            let client_ip = header_slice.source_addr();
            let internet_ip = header_slice.destination_addr();
            
            // Use override or spoof the destination
            let icmp_src = if let Some(std::net::IpAddr::V4(v4)) = source_ip_override {
                v4
            } else {
                internet_ip
            };

            let ip_header_len = (header_slice.ihl() * 4) as usize;
            let bytes_to_include = std::cmp::min(dropped_packet.len(), ip_header_len + 8);
            let payload_slice = &dropped_packet[..bytes_to_include];

            // Build Packet: (Source, Destination, TTL)
            let builder = PacketBuilder::ipv4(
                icmp_src.octets(),
                client_ip.octets(),
                64,
            )
            .icmpv4(Icmpv4Type::DestinationUnreachable(
                etherparse::icmpv4::DestUnreachableHeader::FragmentationNeeded { next_hop_mtu: mtu },
            ));

            let mut result = Vec::with_capacity(builder.size(payload_slice.len()));
            builder.write(&mut result, payload_slice).ok()?;
            Some(result)
        },
        6 => {
            let header_slice = Ipv6HeaderSlice::from_slice(dropped_packet).ok()?;
            let client_ip = header_slice.source_addr();
            let internet_ip = header_slice.destination_addr();

            // Use override or spoof
            let icmp_src = if let Some(std::net::IpAddr::V6(v6)) = source_ip_override {
                v6
            } else {
                internet_ip
            };

            let max_len = 1232; 
            let bytes_to_include = std::cmp::min(dropped_packet.len(), max_len);
            let payload_slice = &dropped_packet[..bytes_to_include];

            // Build Packet: (Source, Destination, TTL)
            let builder = PacketBuilder::ipv6(
                icmp_src.octets(),
                client_ip.octets(),
                64,
            )
            .icmpv6(Icmpv6Type::PacketTooBig { mtu: mtu as u32 });

            let mut result = Vec::with_capacity(builder.size(payload_slice.len()));
            builder.write(&mut result, payload_slice).ok()?;
            Some(result)
        },
        _ => None,
    }
}
