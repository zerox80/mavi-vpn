use etherparse::PacketBuilder;
use std::net::{Ipv4Addr, Ipv6Addr};

pub fn make_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let builder = PacketBuilder::ipv4(src.octets(), dst.octets(), 64).udp(12345, 80);
    let payload = b"hello!!!";
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, payload).unwrap();
    buf
}

pub fn make_ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
    let builder = PacketBuilder::ipv6(src.octets(), dst.octets(), 64).udp(12345, 80);
    let payload = b"hello!!!";
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, payload).unwrap();
    buf
}
