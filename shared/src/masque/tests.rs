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
        assert_eq!(buf.len(), varint_len(v), "len mismatch for {v}");
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
            start: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            end: IpAddr::V4(Ipv4Addr::BROADCAST),
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
