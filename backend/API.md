# Mavi VPN Backend API Documentation

This document describes the public backend protocol exposed by the Mavi VPN server. The backend is not a classical REST API. It exposes a QUIC-based VPN control plane and a QUIC datagram data plane, with two supported client-facing modes:

1. **Raw Mavi QUIC protocol** using ALPN `mavivpn`
2. **HTTP/3 CONNECT-IP / MASQUE mode** using ALPN `h3`

Source overview:

- `backend/src/main.rs` starts the QUIC server, configures state, authentication and TUN routing.
- `backend/src/server/quic.rs` configures TLS, QUIC transport, ALPN and datagrams.
- `backend/src/handlers/connection.rs` handles raw QUIC authentication and protocol detection.
- `backend/src/handlers/h3.rs` handles HTTP/3 CONNECT-IP authentication and MASQUE capsules.
- `backend/src/handlers/tunnel.rs` handles IP packet transfer via QUIC datagrams.
- `shared/src/lib.rs` defines the bincode control messages.
- `shared/src/masque.rs` defines CONNECT-IP capsule and datagram framing helpers.

---

## 1. Server endpoint

### Transport

| Property | Value |
|---|---|
| Transport | QUIC over UDP |
| TLS | TLS 1.3 through rustls/quinn |
| Default bind address | `0.0.0.0:4433` |
| Config option | `--bind-addr` / `VPN_BIND_ADDR` |
| QUIC idle timeout | 60 seconds |
| Keepalive interval | 15 seconds |
| QUIC datagrams | Enabled |
| Congestion control | BBR |

The server listens on the configured UDP address and accepts QUIC connections. Client IP traffic is sent after authentication using QUIC datagrams.

### ALPN negotiation

| Server mode | Advertised ALPN protocols |
|---|---|
| Standard mode | `mavivpn`, `h3` |
| Censorship-resistant mode | `h3` only |

Configuration:

```bash
VPN_CENSORSHIP_RESISTANT=false  # standard mode
VPN_CENSORSHIP_RESISTANT=true   # HTTP/3 camouflage mode
```

---

## 2. Authentication

The backend supports two authentication modes.

### Static token authentication

Default mode. The client must provide exactly the configured token.

Server configuration:

```bash
VPN_AUTH_TOKEN="change-me-to-a-long-random-secret"
```

Raw QUIC clients send the token inside `ControlMessage::Auth`.

HTTP/3 clients send the token as a bearer token:

```http
Authorization: Bearer <token>
```

### Keycloak JWT authentication

When Keycloak mode is enabled, the token is validated as a Keycloak JWT instead of being compared with `VPN_AUTH_TOKEN`.

Server configuration:

```bash
VPN_KEYCLOAK_ENABLED=true
VPN_KEYCLOAK_URL="https://auth.example.com"
VPN_KEYCLOAK_REALM="mavi-vpn"
VPN_KEYCLOAK_CLIENT_ID="mavi-client"
# Optional fail-closed authorization policy:
VPN_KEYCLOAK_REQUIRED_ROLE="vpn-user"
VPN_KEYCLOAK_REQUIRED_SCOPE="vpn:connect"
```

Startup behavior:

- The server fetches the Keycloak JWKS during startup.
- It retries with exponential backoff.
- If JWKS loading fails, startup aborts instead of falling back to the static token.
- If `VPN_KEYCLOAK_REQUIRED_ROLE` or `VPN_KEYCLOAK_REQUIRED_SCOPE` is set, tokens must contain that role or scope in addition to the existing issuer, expiry, `nbf`, and `azp` checks.

Authentication failures return protocol-specific responses. In censorship-resistant mode, unauthorized or invalid HTTP/3-looking traffic is camouflaged as a normal web response.

---

## 3. Raw Mavi QUIC protocol

### When it is used

Raw mode is selected when:

- The client negotiates ALPN `mavivpn`, or
- No recognized ALPN is present and the backend falls back to raw mode.

### Connection flow

1. Client opens a QUIC connection.
2. Client opens a bidirectional stream.
3. Client sends a length-prefixed `ControlMessage::Auth`.
4. Server validates the token.
5. Server replies with either `ControlMessage::Config` or `ControlMessage::Error`.
6. The control stream is closed.
7. VPN traffic is exchanged via QUIC datagrams.

### Raw control frame format

Every raw control message is framed as:

```text
[u32 little-endian payload_length][bincode payload]
```

Limits:

| Field | Limit |
|---|---:|
| Maximum auth payload length | 16,384 bytes |
| Authentication read timeout | 5 seconds |

### Request: `ControlMessage::Auth`

Direction: client to server

```rust
ControlMessage::Auth {
    token: String,
}
```

Example logical payload:

```json
{
  "type": "Auth",
  "token": "client-secret-token"
}
```

Note: the actual wire format is bincode, not JSON.

### Success response: `ControlMessage::Config`

Direction: server to client

```rust
ControlMessage::Config {
    assigned_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
    dns_server: Ipv4Addr,
    mtu: u16,
    assigned_ipv6: Option<Ipv6Addr>,
    netmask_v6: Option<u8>,
    gateway_v6: Option<Ipv6Addr>,
    dns_server_v6: Option<Ipv6Addr>,
    whitelist_domains: Option<Vec<String>>,
}
```

Example logical payload:

```json
{
  "type": "Config",
  "assigned_ip": "10.8.0.2",
  "netmask": "255.255.255.0",
  "gateway": "10.8.0.1",
  "dns_server": "1.1.1.1",
  "mtu": 1280,
  "assigned_ipv6": "fd00::2",
  "netmask_v6": 64,
  "gateway_v6": "fd00::1",
  "dns_server_v6": "2606:4700:4700::1111",
  "whitelist_domains": []
}
```

### Error response: `ControlMessage::Error`

Direction: server to client

```rust
ControlMessage::Error {
    message: String,
}
```

Example logical payload:

```json
{
  "type": "Error",
  "message": "Unauthorized: Access Denied: Invalid Token"
}
```

### Raw data plane

After successful authentication, raw mode uses QUIC datagrams containing the raw IP packet directly.

```text
[IPv4 or IPv6 packet bytes]
```

Client-to-server packets are accepted only if the packet source address matches the IPv4 or IPv6 address assigned during authentication. Packets with spoofed source addresses are dropped.

---

## 4. HTTP/3 CONNECT-IP / MASQUE protocol

### When it is used

HTTP/3 mode is selected when the client negotiates ALPN `h3`.

### Connection flow

1. Client opens a QUIC connection with ALPN `h3`.
2. Client performs the HTTP/3 handshake.
3. Client sends one extended CONNECT request using CONNECT-IP.
4. Client includes `Authorization: Bearer <token>`.
5. Server validates the token.
6. Server sends `200 OK` plus a capsule stream.
7. VPN traffic is exchanged via HTTP/3 QUIC datagrams.

### Request

The server checks that the HTTP/3 request has the extended CONNECT protocol `CONNECT_IP`.

Required header:

```http
Authorization: Bearer <token>
```

The backend does not currently route based on URI path. The important protocol signal is the HTTP/3 extended CONNECT-IP marker.

### Success response

```http
HTTP/3 200 OK
```

The response body starts with a capsule stream containing:

| Capsule | Type | Purpose |
|---|---:|---|
| `ADDRESS_ASSIGN` | `0x01` | Assigns IPv4 and optionally IPv6 addresses to the client |
| `ROUTE_ADVERTISEMENT` | `0x03` | Advertises reachable IP ranges through the tunnel |
| `MAVI_CONFIG` | `0x4D56` | Vendor-specific bincode `ControlMessage::Config` |

Unknown capsule types are safe for generic MASQUE clients to ignore.

### `ADDRESS_ASSIGN` capsule

The server sends at least one address assignment:

```text
request_id = 0
ip = assigned IPv4 address
prefix_len = IPv4 network prefix length
```

If IPv6 is enabled, the server also sends:

```text
request_id = 0
ip = assigned IPv6 address
prefix_len = 64
```

### `ROUTE_ADVERTISEMENT` capsule

The server advertises default routes through the tunnel.

IPv4 route:

```text
start = 0.0.0.0
end = 255.255.255.255
ip_protocol = 0
```

IPv6 route, when IPv6 is enabled:

```text
start = ::
end = ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
ip_protocol = 0
```

`ip_protocol = 0` means all protocols.

### `MAVI_CONFIG` capsule

Capsule type:

```text
0x4D56
```

Payload:

```text
bincode(ControlMessage::Config)
```

This vendor-specific capsule carries Mavi-specific settings such as DNS, MTU and split-tunnel whitelist domains.

### Unauthorized response

If authentication fails:

| Mode | Response |
|---|---|
| Standard HTTP/3 mode | `401 Unauthorized` with body `Unauthorized` |
| Censorship-resistant mode | Fake `200 OK` HTML page with `server: nginx` |

### Non-CONNECT-IP request response

If an HTTP/3 request is not CONNECT-IP:

| Mode | Response |
|---|---|
| Standard mode | `404 Not Found` |
| Censorship-resistant mode | Fake `200 OK` HTML page with `server: nginx` |

---

## 5. HTTP/3 datagram format

CONNECT-IP datagrams are framed as:

```text
[Quarter Stream ID varint][Context ID varint][IPv4 or IPv6 packet bytes]
```

For Mavi's current single CONNECT-IP request model, the common prefix is:

```text
0x00 0x00
```

Therefore the hot-path datagram format is:

```text
[0x00][0x00][IPv4 or IPv6 packet bytes]
```

The shared parser also accepts general QUIC varint-encoded Quarter Stream ID and Context ID values.

---

## 6. Capsule wire format

Capsules use the Capsule Protocol frame format:

```text
[Capsule Type varint][Payload Length varint][Payload bytes]
```

The backend uses QUIC variable-length integers as defined by QUIC. Supported integer lengths are 1, 2, 4 and 8 bytes.

---

## 7. Address assignment rules

IPv4 addresses are assigned from `VPN_NETWORK`.

Default:

```bash
VPN_NETWORK="10.8.0.0/24"
```

Rules:

- The network address is not assigned.
- The gateway address is the second address in the network, usually `.1`.
- The broadcast address is not assigned.
- Client addresses start from the next usable address, usually `.2`.
- Prefixes smaller than `/8` are rejected to avoid excessive memory allocation.
- Prefixes larger than `/30` are rejected because they leave too few usable addresses.

IPv6 uses the internal ULA network:

```text
fd00::/64
```

IPv6 gateway:

```text
fd00::1
```

IPv6 client assignment starts at:

```text
fd00::2
```

Released IPv4 and IPv6 addresses are returned to their pools when the connection ends.

---

## 8. MTU contract

The server pushes the inner tunnel MTU to clients in `ControlMessage::Config.mtu`.

Default:

```text
1280
```

Allowed range:

```text
1280..=1360
```

Configuration:

```bash
VPN_MTU=1280
```

The QUIC payload MTU is derived internally as:

```text
QUIC payload MTU = VPN_MTU + 80
```

Clients should configure their virtual network interface with exactly the `mtu` value received from the server.

---

## 9. DNS and split tunneling

### IPv4 DNS

Configured by:

```bash
VPN_DNS="1.1.1.1"
```

Sent to clients as:

```rust
dns_server: Ipv4Addr
```

### IPv6 DNS

Configured by:

```bash
VPN_DNS_V6="2001:4860:4860::8888"
```

If IPv6 is active and `VPN_DNS_V6` is not set, the backend sends the default:

```text
2606:4700:4700::1111
```

### Split-tunnel whitelist domains

Configured by:

```bash
VPN_WHITELIST_DOMAINS="example.com,internal.test"
```

Sent to clients as:

```rust
whitelist_domains: Option<Vec<String>>
```

An empty list means no domains are excluded by this backend config.

---

## 10. Censorship-resistant behavior

Enable with:

```bash
VPN_CENSORSHIP_RESISTANT=true
```

Effects:

- Server advertises only ALPN `h3`.
- Unauthorized HTTP/3 requests receive a fake nginx-like `200 OK` page.
- Non-CONNECT-IP HTTP/3 requests also receive a fake nginx-like `200 OK` page.
- The configured ECH public name is used as the expected cover SNI.

ECH-related configuration:

```bash
VPN_ECH_PUBLIC_NAME="cloudflare-ech.com"
VPN_ECH_CONFIG="data/ech_config.bin"
VPN_ECH_KEY="data/ech_key.bin"
```

Current note: the server loads or generates ECH artifacts for future wiring and client distribution, but the Rustls server-side ECH decrypt path is not active yet.

---

## 11. Packet validation and error handling

### Source address validation

Client-to-server datagrams are accepted only when the inner packet source address equals the address assigned to the connection.

Accepted:

```text
IPv4 source == assigned_ip
IPv6 source == assigned_ipv6
```

Rejected:

```text
empty packet
invalid IP packet
unsupported IP version
source address spoofing
```

### Too-large datagrams

If server-to-client datagram sending fails because the datagram is too large, the backend attempts to generate an ICMP Packet Too Big response back toward the TUN path.

For IPv6, the reported MTU is never below 1280.

---

## 12. Backend configuration reference

| CLI flag | Environment variable | Default | Description |
|---|---|---|---|
| `--bind-addr` | `VPN_BIND_ADDR` | `0.0.0.0:4433` | UDP address for QUIC server |
| `--auth-token` | `VPN_AUTH_TOKEN` | required | Static authentication token |
| `--network-cidr` | `VPN_NETWORK` | `10.8.0.0/24` | IPv4 VPN address pool |
| `--tun-device-path` | `VPN_TUN_DEVICE` | unset | Optional TUN interface name/path |
| `--dns` | `VPN_DNS` | `1.1.1.1` | IPv4 DNS pushed to clients |
| `--cert-path` | `VPN_CERT` | `data/cert.pem` | TLS certificate path |
| `--key-path` | `VPN_KEY` | `data/key.pem` | TLS private key path |
| `--mtu` | `VPN_MTU` | `1280` | Inner tunnel MTU |
| `--censorship-resistant` | `VPN_CENSORSHIP_RESISTANT` | `false` | Enables HTTP/3 camouflage behavior |
| `--mss-clamping` | `VPN_MSS_CLAMPING` | `false` | Enables TCP MSS clamping |
| `--dns-v6` | `VPN_DNS_V6` | unset | IPv6 DNS pushed to clients |
| `--whitelist-domains` | `VPN_WHITELIST_DOMAINS` | empty | Comma-separated split-tunnel whitelist |
| `--keycloak-enabled` | `VPN_KEYCLOAK_ENABLED` | `false` | Enables Keycloak JWT validation |
| `--keycloak-url` | `VPN_KEYCLOAK_URL` | unset | Keycloak base URL |
| `--keycloak-realm` | `VPN_KEYCLOAK_REALM` | `mavi-vpn` | Keycloak realm |
| `--keycloak-client-id` | `VPN_KEYCLOAK_CLIENT_ID` | `mavi-client` | Keycloak client ID |
| `--keycloak-required-role` | `VPN_KEYCLOAK_REQUIRED_ROLE` | unset | Optional realm/client role required on accepted JWTs |
| `--keycloak-required-scope` | `VPN_KEYCLOAK_REQUIRED_SCOPE` | unset | Optional OAuth scope required on accepted JWTs |
| `--ech-public-name` | `VPN_ECH_PUBLIC_NAME` | `cloudflare-ech.com` | Cover SNI for ECH/camouflage mode |
| `--ech-config-path` | `VPN_ECH_CONFIG` | `data/ech_config.bin` | ECHConfigList path |
| `--ech-key-path` | `VPN_ECH_KEY` | `data/ech_key.bin` | ECH private key path |

---

## 13. Minimal client implementation checklist

A compatible raw QUIC client must:

1. Connect to the server with ALPN `mavivpn`.
2. Open a bidirectional stream.
3. Send `u32_le(length) + bincode(ControlMessage::Auth { token })`.
4. Read `u32_le(length) + bincode(ControlMessage::Config | Error)`.
5. Configure the local TUN interface using the received config.
6. Send raw IP packets as QUIC datagrams.
7. Receive raw IP packets as QUIC datagrams.

A compatible HTTP/3 CONNECT-IP client must:

1. Connect to the server with ALPN `h3`.
2. Create an HTTP/3 extended CONNECT-IP request.
3. Send `Authorization: Bearer <token>`.
4. Read `200 OK` and parse the capsule stream.
5. Use `ADDRESS_ASSIGN`, `ROUTE_ADVERTISEMENT` and `MAVI_CONFIG` to configure the tunnel.
6. Send IP packets as CONNECT-IP datagrams with prefix `0x00 0x00` for the current single-stream model.
7. Strip CONNECT-IP datagram prefixes from incoming datagrams before writing packets to TUN.

---

## 14. Versioning note

There is no explicit protocol version field in the current wire format. Compatibility currently depends on:

- The `ControlMessage` enum shape
- The bincode configuration
- The capsule type constants
- The datagram framing rules
- The negotiated ALPN protocol

If this API evolves, add an explicit protocol version to the control handshake or introduce a versioned vendor capsule for HTTP/3 mode.
