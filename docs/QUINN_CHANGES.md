# Quinn Changes

This project resolves Quinn through the `zerox80/quinn` fork and `h3` through the `zerox80/h3` fork, both tracked on `main`. The root `Cargo.toml` applies those patches so `h3-quinn` uses Quinn 0.12 instead of pulling a second Quinn 0.11 dependency from crates.io.

## 2026-04-27

- `quinn-proto/src/connection/datagrams.rs`: keep queued DATAGRAM payloads whose size is exactly the current payload limit. The previous strict comparison dropped packets at the limit.
- `quinn-proto/src/congestion/bbr/mod.rs`: compare BBR startup growth against the congestion window in bytes, not the floating-point `cwnd_gain` multiplier.
- `quinn-proto/src/connection/mtud.rs`: use saturating arithmetic when a failed MTU probe lowers the search upper bound.
- `quinn-proto/src/connection/mtud.rs`: clamp peer `max_udp_payload_size` handling to QUIC's 1200-byte minimum as a defensive invariant.
- `quinn-proto/src/connection/mod.rs`: reset the PTO backoff only when an ACK newly acknowledges an ack-eliciting packet, not merely any newly tracked packet.
- `quinn-proto/src/connection/mod.rs`: avoid `Instant` and duration overflow panics while detecting packet loss and persistent congestion.
- `quinn-proto/src/connection/mtud.rs`: treat loss at exactly the minimum/previously-acked MTU as non-suspicious so black-hole detection does not overreact.
- `quinn-proto/src/connection/mtud.rs`: allow peer MTU parameters after early black-hole recovery while still asserting that active probing has not started.
- `quinn-proto/src/connection/datagrams.rs`: report when oversized queued DATAGRAMs are dropped after an MTU reduction.
- `quinn-proto/src/connection/mod.rs`: emit `DatagramsUnblocked` when dropping oversized queued DATAGRAMs frees send-buffer space.

## Fork State

- `quinn`, `quinn-proto`, and `quinn-udp` are patched to `https://github.com/zerox80/quinn`, branch `main`.
- `h3`, `h3-quinn`, and `h3-datagram` are patched to `https://github.com/zerox80/h3`, branch `main`.
- The h3 fork updates `h3-quinn` to accept Quinn 0.12, preventing a fallback to the crates.io Quinn 0.11 line.
- `Cargo.lock` pins these fork revisions for reproducible builds.
- `external/quinn` was removed from this repository to avoid keeping an unused second Quinn source tree beside the fork patches.
