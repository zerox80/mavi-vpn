# Quinn Changes

This project vendors Quinn under `external/quinn` and applies local fixes that are important for VPN-style QUIC datagram traffic.

## 2026-04-27

- `quinn-proto/src/connection/datagrams.rs`: keep queued DATAGRAM payloads whose size is exactly the current payload limit. The previous strict comparison dropped packets at the limit.
- `quinn-proto/src/congestion/bbr/mod.rs`: compare BBR startup growth against the congestion window in bytes, not the floating-point `cwnd_gain` multiplier.
- `quinn-proto/src/connection/mtud.rs`: use saturating arithmetic when a failed MTU probe lowers the search upper bound.
- `quinn-proto/src/connection/mtud.rs`: clamp peer `max_udp_payload_size` handling to QUIC's 1200-byte minimum as a defensive invariant.
- `quinn-proto/src/connection/mod.rs`: reset the PTO backoff only when an ACK newly acknowledges an ack-eliciting packet, not merely any newly tracked packet.

## Fork State

- `external/quinn` is currently vendored as normal files in the `mavi-vpn` repository, not as a nested Git clone or submodule.
- The GitHub fork `https://github.com/zerox80/quinn` exists and can be used for a later migration if we want Quinn versioning independent from `mavi-vpn`.
- `h3`, `h3-quinn`, and `h3-datagram` are pinned to hyperium/h3 commit `704b37a2e82cf4c8de379ec779dbc2a23bfcb9a1` in the root `Cargo.toml`; no h3 fork change was made here.
