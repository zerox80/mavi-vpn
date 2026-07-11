# Mavi VPN Backend API Documentation

This document describes the public backend protocol exposed by the Mavi VPN
server. The backend is not a classical REST API. It exposes a VPN control plane
and an IP data plane with three supported client-facing protocol profiles:

1. **Raw Mavi QUIC protocol** using ALPN `mavivpn`
2. **HTTP/3 CONNECT-IP / MASQUE protocol** using ALPN `h3`
3. **HTTP/2 CONNECT-IP protocol** using ALPN `h2` over TLS/TCP

The word "API" in this document therefore means the network contract between a
client and the backend: transport parameters, authentication, control messages,
capsules, datagram framing, address assignment, packet validation, and the
configuration values the server exposes to clients during connection setup.

The protocol is intentionally small. Authentication happens once at connection
startup, configuration is delivered once after successful authentication, and
raw and HTTP/3 tunneled traffic then moves through QUIC datagrams. HTTP/2 mode
carries CONNECT-IP datagram capsules inside HTTP/2 DATA frames over TLS/TCP. No
JSON REST endpoint is required for ordinary VPN operation.

Source overview:

- `backend/src/main.rs` starts the QUIC server, loads configuration, prepares
  certificates, initializes Keycloak authentication, creates the TUN interface,
  and accepts incoming QUIC connections.
- `backend/src/config/mod.rs` defines CLI flags, environment variables, defaults,
  and validation rules for server configuration.
- `backend/src/server/quic.rs` configures TLS 1.3, QUIC transport settings,
  ALPN, datagrams, congestion control, keepalive, buffers, and the fixed QUIC
  payload MTU derived from the inner tunnel MTU.
- `backend/src/handlers/connection.rs` detects raw versus HTTP/3 protocol use,
  handles the raw QUIC authentication stream, builds `ControlMessage::Config`,
  and starts the tunnel loop.
- `backend/src/handlers/h3.rs` handles HTTP/3 extended CONNECT-IP requests,
  bearer-token authentication, MASQUE capsules, and camouflage responses.
- `backend/src/server/http2.rs` accepts the optional TLS/TCP HTTP/2 listener,
  validates Extended CONNECT-IP requests, and starts HTTP/2 tunnel sessions.
- `backend/src/handlers/tunnel/http2.rs` carries CONNECT-IP capsules over the
  upgraded HTTP/2 stream, including datagrams and reauthentication.
- `backend/src/handlers/auth.rs` validates either a static token or a Keycloak
  JWT and leases an IPv4/IPv6 address pair.
- `backend/src/handlers/tunnel.rs` moves IP packets between QUIC datagrams and
  the server TUN path, unwraps or preserves MASQUE datagram prefixes depending
  on protocol mode, rejects spoofed client source addresses, and generates
  Packet Too Big feedback when possible.
- `backend/src/routing.rs` routes packets read from TUN to registered clients
  by destination address and prefixes server-to-client packets with the
  CONNECT-IP datagram prefix internally.
- `backend/src/state/mod.rs` manages IPv4 and IPv6 address pools and active peer
  registries.
- `backend/src/keycloak.rs` implements Keycloak JWKS loading, JWT validation,
  key refresh, issuer checks, `azp` checks, optional role checks, and optional
  scope checks.
- `shared/src/lib.rs` defines bincode-serialized control messages and shared
  MTU constants.
- `shared/src/masque.rs` defines QUIC varint helpers, Capsule Protocol framing,
  CONNECT-IP address and route capsules, the vendor-specific Mavi capsules, and
  HTTP/3/HTTP/2 datagram wrapping and unwrapping.

---

## 1. Protocol model

Mavi VPN separates connection setup from packet forwarding.

The setup phase authenticates the client and returns the network configuration
the client needs in order to configure its virtual network interface. In raw
mode this setup phase is a single bincode control exchange on a client-opened
bidirectional QUIC stream. In HTTP/3 mode this setup phase is an extended
CONNECT-IP request followed by a capsule stream containing both standard
CONNECT-IP information and a Mavi-specific configuration capsule. HTTP/2 uses
the same capsule types after an RFC 8441 Extended CONNECT upgrade, but carries
them in HTTP/2 DATA frames.

The forwarding phase uses QUIC datagrams in raw and HTTP/3 modes. A datagram
carries exactly one inner IP packet, either directly in raw mode or wrapped in
HTTP/3 CONNECT-IP datagram framing in `h3` mode. HTTP/2 mode carries the same
CONNECT-IP payload in a `CAPSULE_DATAGRAM` capsule over the upgraded HTTP/2
stream. The server does not expose per-packet REST-like operations, resource
URLs, or persistent JSON sessions; the transport connection is the session.

The server assigns one IPv4 address and one IPv6 address to every authenticated
connection. Whether IPv6 configuration is sent to the client depends on whether
the server successfully configured IPv6 on its TUN path. Address leases are
released when the connection handler exits. The backend keeps active peer
registries keyed by virtual destination address, so packets read from the TUN
interface can be routed to the correct QUIC connection.

Client implementations should treat the protocol as connection-oriented. QUIC
clients must account for unreliable datagrams; HTTP/2 clients receive reliable,
ordered TCP delivery but still carry IP packets in datagram capsules. A client
should authenticate, apply the received configuration, exchange packets while
the transport connection is alive, and discard the assigned addresses after
disconnect.

---

## 2. Server endpoint

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
| Datagram receive buffer | 4 MiB |
| Datagram send buffer | 4 MiB |
| QUIC receive window | 4 MiB |
| QUIC stream receive window | 1 MiB |
| QUIC send window | 4 MiB |
| Congestion control | BBR |
| Segmentation offload | Enabled |
| QUIC MTU discovery | Disabled |

The server listens on the configured UDP address and accepts QUIC connections.
Client IP traffic is sent after authentication using QUIC datagrams. Because
MTU discovery is disabled, the server pins the QUIC transport MTU to a value
derived from `VPN_MTU`. Operators should choose an inner tunnel MTU that fits
their expected outer network path.

### Optional HTTP/2 endpoint

When `VPN_HTTP2_BIND_ADDR` is set, the backend also listens on that TCP address
for HTTP/2 CONNECT-IP sessions. The listener is disabled by default and may use
the same numeric port as `VPN_BIND_ADDR` because one endpoint is UDP and the
other is TCP. It uses the configured certificate and advertises only ALPN `h2`.
HTTP/2 mode does not use QUIC, ECH, QUIC connection migration, or the
censorship-resistant fake nginx responses.

On Linux, the server also attempts to relax kernel-level path MTU discovery
behavior for IPv4 and IPv6 UDP sockets. Those socket options are best-effort:
failure to set them does not stop the server from starting.

### TLS certificate behavior

The server uses the certificate configured by:

```bash
VPN_CERT="data/cert.pem"
VPN_KEY="data/key.pem"
```

or the equivalent CLI flags:

```bash
--cert-path data/cert.pem
--key-path data/key.pem
```

If the certificate path does not exist, the backend creates the parent
directory if necessary and loads or generates certificates through
`backend/src/cert.rs`. Clients are responsible for applying the appropriate
trust strategy for their environment, such as a normal public WebPKI
certificate for production HTTP/3 camouflage deployments or certificate pinning
for private deployments.

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

ALPN is the authoritative protocol signal for modern clients. If the peer
negotiates `h3`, the backend waits for HTTP/3 unidirectional control stream
setup and handles the connection as HTTP/3. If the peer negotiates `mavivpn`,
the backend accepts the first bidirectional stream as the raw Mavi control
stream. If no recognized ALPN is present, the backend keeps a legacy fallback
and treats the first bidirectional stream as raw mode.

Clients should always send an explicit ALPN value. Raw clients should use
`mavivpn`; HTTP/3 CONNECT-IP clients should use `h3`.

---

## 3. Authentication

The backend supports two mutually exclusive authentication modes:

1. Static pre-shared token authentication
2. Keycloak JWT authentication

The same authentication decision is used by both raw QUIC and HTTP/3
CONNECT-IP. The only difference is how the client transports the credential to
the server.

### Static token authentication

Static token authentication is the default mode. The server must be configured
with a non-empty token unless Keycloak authentication is enabled.

Server configuration:

```bash
VPN_AUTH_TOKEN="change-me-to-a-long-random-secret"
```

or:

```bash
--auth-token "change-me-to-a-long-random-secret"
```

Raw QUIC clients send the token inside `ControlMessage::Auth`. HTTP/3 clients
send the token as a bearer token:

```http
Authorization: Bearer <token>
```

The static token comparison is case-sensitive and uses constant-time byte
comparison. Empty tokens are rejected. If the backend is started with Keycloak
disabled and no static token, configuration validation fails and the process
exits with a configuration error.

### Keycloak JWT authentication

When Keycloak mode is enabled, the received token is validated as a Keycloak
JWT instead of being compared with `VPN_AUTH_TOKEN`.

Server configuration:

```bash
VPN_KEYCLOAK_ENABLED=true
VPN_KEYCLOAK_URL="https://auth.example.com"
VPN_KEYCLOAK_REALM="mavi-vpn"
VPN_KEYCLOAK_CLIENT_ID="mavi-client"
```

Optional fail-closed authorization policy:

```bash
VPN_KEYCLOAK_REQUIRED_ROLE="vpn-user"
VPN_KEYCLOAK_REQUIRED_SCOPE="vpn:connect"
```

Startup behavior:

- `VPN_KEYCLOAK_URL` is required when `VPN_KEYCLOAK_ENABLED=true`.
- The server fetches the Keycloak JWKS from
  `{VPN_KEYCLOAK_URL}/realms/{VPN_KEYCLOAK_REALM}/protocol/openid-connect/certs`.
- Startup retries JWKS loading up to five times with exponential backoff of
  1, 2, 4, 8, and 16 seconds between attempts.
- If JWKS loading still fails, startup aborts. The server does not silently
  fall back to static token authentication.
- If `VPN_KEYCLOAK_REQUIRED_ROLE` or `VPN_KEYCLOAK_REQUIRED_SCOPE` is set
  while Keycloak mode is disabled, configuration validation fails.

Runtime token validation:

- The JWT header must contain a `kid`.
- The `kid` must match a key in the cached JWKS.
- If the `kid` is unknown, the server may refresh JWKS, subject to a 10-second
  refresh cooldown.
- Tokens are decoded using RS256.
- Built-in audience validation is disabled because Keycloak access tokens often
  use `aud: "account"`.
- The issuer must match `{VPN_KEYCLOAK_URL}/realms/{VPN_KEYCLOAK_REALM}`.
- The token must contain a valid `exp` claim.
- The optional `nbf` claim is honored.
- A 30-second leeway is used for clock drift.
- The `azp` claim must match `VPN_KEYCLOAK_CLIENT_ID` using constant-time
  comparison.
- If a required role is configured, the token must contain that role either in
  `realm_access.roles` or in `resource_access[client_id].roles`.
- If a required scope is configured, the token's space-delimited `scope` claim
  must include that scope.

Validation failures reject the connection. In standard mode the client receives
a protocol-specific unauthorized response. In censorship-resistant HTTP/3 mode,
unauthorized HTTP/3-looking traffic is camouflaged as a normal nginx-like web
response.

### Address leasing after authentication

Authentication and address leasing happen as one operation. After a token or
JWT is accepted, the server attempts to lease an IPv4/IPv6 pair from
`AppState`. If either address family cannot be leased, the authentication step
returns an error and the connection is rejected. If IPv6 leasing fails after an
IPv4 address was leased, the IPv4 address is returned to the pool before the
error is propagated.

This means a valid token does not guarantee connection success if the address
pool is exhausted. Clients should present address exhaustion as a temporary
server-side capacity problem and retry only with a backoff.

---

## 4. Raw Mavi QUIC protocol

### When raw mode is used

Raw mode is selected when:

- The client negotiates ALPN `mavivpn`, or
- No recognized ALPN is present and the backend falls back to raw mode.

Raw mode is compact and efficient. It is intended for Mavi-native clients that
do not need to look like browser or MASQUE traffic. It does not use HTTP
headers, URLs, methods, or capsules.

### Raw connection flow

1. Client opens a QUIC connection.
2. Client negotiates ALPN `mavivpn`.
3. Client opens a bidirectional stream.
4. Client sends one length-prefixed `ControlMessage::Auth`.
5. Server reads the frame with a 5-second timeout.
6. Server validates the token using static auth or Keycloak auth.
7. Server leases an IPv4/IPv6 address pair.
8. Server replies with either `ControlMessage::Config` or
   `ControlMessage::Error`.
9. Server finishes the control stream.
10. VPN traffic is exchanged via QUIC datagrams.

Clients should not send IP datagrams before receiving a successful config
message. Datagrams sent before the server registers the client are not part of
the supported protocol contract and may be ignored.

### Raw control frame format

Every raw control message is framed as:

```text
[u32 little-endian payload_length][bincode payload]
```

The payload is encoded with:

```rust
bincode::serde::encode_to_vec(message, bincode::config::standard())
```

The receiver decodes with:

```rust
bincode::serde::decode_from_slice(bytes, bincode::config::standard())
```

Limits:

| Field | Limit |
|---|---:|
| Maximum auth payload length | 16,384 bytes |
| Authentication read timeout | 5 seconds |
| Length prefix size | 4 bytes |
| Length prefix byte order | Little-endian |

If the payload length is larger than 16,384 bytes, authentication fails with a
protocol error. If the frame is incomplete or cannot be decoded as a bincode
`ControlMessage::Auth`, authentication fails. If the client sends a different
`ControlMessage` variant as the first raw control payload, authentication also
fails.

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

The JSON above is illustrative only. The actual wire format is bincode. A
client implemented in another language must reproduce the Rust bincode layout
for the `ControlMessage` enum or use the HTTP/3 CONNECT-IP mode instead.

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

Field semantics:

| Field | Meaning |
|---|---|
| `assigned_ip` | IPv4 address the client must configure on its tunnel interface |
| `netmask` | IPv4 netmask for the VPN network |
| `gateway` | Server-side IPv4 tunnel gateway |
| `dns_server` | IPv4 DNS server the client should use while connected |
| `mtu` | Inner TUN MTU the client should configure exactly |
| `assigned_ipv6` | Optional client IPv6 tunnel address |
| `netmask_v6` | Optional IPv6 prefix length |
| `gateway_v6` | Optional server-side IPv6 tunnel gateway |
| `dns_server_v6` | Optional IPv6 DNS server |
| `whitelist_domains` | Optional split-tunnel domain allow-list |

The backend currently sends `whitelist_domains: Some(Vec<String>)` even when
the list is empty. Clients should still handle `None` for forward and backward
compatibility.

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

Clients should treat any `Error` response as a failed connection attempt. The
message is intended for logs or diagnostics; client logic should not depend on
exact English strings because they can change as validation paths evolve.

### Raw data plane

After successful authentication, raw mode uses QUIC datagrams containing the
raw IP packet directly:

```text
[IPv4 or IPv6 packet bytes]
```

Client-to-server datagrams are accepted only if the packet source address
matches the IPv4 or IPv6 address assigned during authentication:

```text
IPv4 source == assigned_ip
IPv6 source == assigned_ipv6
```

The following datagrams are dropped:

- Empty datagrams
- Invalid or truncated IPv4 packets
- Invalid or truncated IPv6 packets
- Packets with an unsupported IP version
- Packets whose source address does not match the address assigned to the
  connection

Server-to-client raw datagrams contain only the IP packet. Internally, packets
read from TUN are stored with the two-byte MASQUE datagram prefix so the same
routing path can serve raw and HTTP/3 clients. Before sending to a raw client,
the tunnel loop strips that prefix and transmits only the packet bytes.

---

## 5. HTTP/3 CONNECT-IP / MASQUE protocol

### When HTTP/3 mode is used

HTTP/3 mode is selected when the client negotiates ALPN `h3`. This mode is
designed for clients that want a standards-aligned CONNECT-IP data plane and
for deployments that need traffic to resemble ordinary HTTP/3 more closely than
the raw `mavivpn` protocol.

When `VPN_CENSORSHIP_RESISTANT=true`, the server advertises only `h3`, making
HTTP/3 mode the only supported client-facing mode.

### HTTP/3 connection flow

1. Client opens a QUIC connection with ALPN `h3`.
2. Client performs the HTTP/3 handshake.
3. Client sends one extended CONNECT request using CONNECT-IP.
4. Client includes `Authorization: Bearer <token>`.
5. Server validates the token using static auth or Keycloak auth.
6. Server leases an IPv4/IPv6 address pair.
7. Server sends `200 OK`.
8. Server sends a capsule stream containing standard CONNECT-IP capsules plus
   the vendor-specific `MAVI_CONFIG` capsule.
9. VPN traffic is exchanged via HTTP/3 QUIC datagrams.

The current backend expects exactly one CONNECT-IP request for the VPN tunnel.
The hot-path datagram prefix assumes the request uses stream ID 0, producing a
Quarter Stream ID value of 0. If a future client or HTTP/3 library opens other
bidirectional streams before the CONNECT-IP request, the datagram prefix must
be derived dynamically from the actual stream ID. The parser already accepts
general QUIC varint-encoded Quarter Stream ID and Context ID values.

### HTTP/3 request contract

The server checks that the HTTP/3 request carries the extended CONNECT protocol
`CONNECT_IP`. The backend does not currently route based on URI path. The
important protocol signal is the HTTP/3 extended CONNECT-IP marker.

Required header:

```http
Authorization: Bearer <token>
```

The bearer prefix must be exactly `Bearer ` with a trailing space. If the
header is missing, malformed, or uses another scheme, the token presented to
the authentication layer is the empty string and authentication fails.

### Success response

```http
HTTP/3 200 OK
```

The response body begins with a capsule stream containing, in order:

| Capsule | Type | Purpose |
|---|---:|---|
| `ADDRESS_ASSIGN` | `0x01` | Assigns IPv4 and optionally IPv6 addresses to the client |
| `ROUTE_ADVERTISEMENT` | `0x03` | Advertises reachable IP ranges through the tunnel |
| `MAVI_CONFIG` | `0x4D56` | Carries bincode `ControlMessage::Config` for Mavi-specific settings |

Unknown capsule types are safe for generic MASQUE clients to ignore. Mavi
clients should parse the standard capsules for address and route information
and should also parse `MAVI_CONFIG` to obtain MTU, DNS, and split-tunnel
configuration.

### `ADDRESS_ASSIGN` capsule

Capsule type:

```text
0x01
```

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
prefix_len = configured IPv6 network prefix length
```

The payload layout implemented by `shared/src/masque.rs` is a sequence of
assigned-address entries:

```text
[Request ID varint][IP version byte][IP bytes][Prefix length byte]...
```

For IPv4, `IP version byte` is `4` and `IP bytes` is four octets. For IPv6,
`IP version byte` is `6` and `IP bytes` is sixteen octets.

### `ROUTE_ADVERTISEMENT` capsule

Capsule type:

```text
0x03
```

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

The payload layout is a sequence of address ranges:

```text
[IP version byte][Start IP bytes][End IP bytes][IP protocol byte]...
```

IPv4 ranges use four bytes for start and four bytes for end. IPv6 ranges use
sixteen bytes for start and sixteen bytes for end. Start and end must use the
same IP version. Encoder code skips mismatched ranges, but normal server output
does not produce mismatched ranges.

### `MAVI_CONFIG` capsule

Capsule type:

```text
0x4D56
```

Payload:

```text
bincode(ControlMessage::Config)
```

This vendor-specific capsule carries the full Mavi configuration object. It is
needed because standard CONNECT-IP capsules assign addresses and advertise
routes, but they do not express all Mavi client settings such as DNS servers,
the inner tunnel MTU, and split-tunnel whitelist domains.

Generic MASQUE clients may ignore this capsule. Mavi clients should require it
unless they have a separate trusted configuration source for DNS, MTU, and
split-tunnel behavior.

### Unauthorized response

If authentication fails:

| Mode | Response |
|---|---|
| Standard HTTP/3 mode | `401 Unauthorized` with body `Unauthorized` |
| Censorship-resistant mode | Fake `200 OK` HTML page with `server: nginx` |

In censorship-resistant mode, the fake response body is a small nginx welcome
page. This makes active probes that send HTTP/3-shaped but unauthorized traffic
receive a plausible web response instead of a protocol-specific VPN error.

### Non-CONNECT-IP request response

If an HTTP/3 request is not CONNECT-IP:

| Mode | Response |
|---|---|
| Standard mode | `404 Not Found` with a small HTML body |
| Censorship-resistant mode | Fake `200 OK` HTML page with `server: nginx` |

Clients should not rely on ordinary HTTP paths for health checks against the
VPN port. In camouflage mode, a successful-looking non-CONNECT response does
not indicate VPN authentication success.

---

## 5A. HTTP/2 CONNECT-IP / Capsules

### When HTTP/2 mode is used

HTTP/2 mode is enabled by setting `VPN_HTTP2_BIND_ADDR` on the server and
`http2_framing: true` in the client configuration. It is a separate TLS/TCP
listener, disabled by default. The UDP QUIC listener may use the same numeric
port. Client transport normalization makes HTTP/2 mutually exclusive with
censorship-resistant mode, HTTP/3 framing, and ECH.

HTTP/2 is a reliable, ordered fallback transport. It is not a QUIC transport and
does not provide QUIC datagrams, QUIC connection migration, ECH, or the fake
nginx probe response used by the QUIC censorship-resistant mode.

### HTTP/2 request contract

The listener negotiates ALPN `h2` and accepts only HTTP/2. A tunnel request must
meet all of these conditions:

```http
CONNECT /.well-known/masque/ip/*/*/ HTTP/2
:protocol: connect-ip
capsule-protocol: ?1
Authorization: Bearer <token>
```

The path, method, `connect-ip` Extended CONNECT protocol, and capsule protocol
marker are all checked. The bearer prefix must be exactly `Bearer ` with a
trailing space. A successful request returns:

```http
:status: 200
capsule-protocol: ?1
cache-control: no-store
```

The server then sends `ADDRESS_ASSIGN`, `ROUTE_ADVERTISEMENT`, and `MAVI_CONFIG`
capsules. The capsule type and payload definitions are the same as in the
HTTP/3 section above; `MAVI_CONFIG` contains the bincode
`ControlMessage::Config` payload.

### HTTP/2 data plane

After the response, both directions carry capsules in HTTP/2 DATA frames. A
`CAPSULE_DATAGRAM` capsule contains a CONNECT-IP datagram payload: a context ID
followed by one IPv4 or IPv6 packet. Mavi currently uses context ID `0`. Unlike
HTTP/3, there is no QUIC Quarter Stream ID prefix. The server validates that
client packets use the assigned source address and fit the configured inner
tunnel MTU; invalid packets are dropped and oversized packets may generate
Packet Too Big feedback.

The Mavi-specific reauthentication capsules are:

| Capsule | Type | Purpose |
|---|---:|---|
| `MAVI_REAUTH` | `0x4D57` | Carries a refreshed bearer token |
| `MAVI_REAUTH_RESULT` | `0x4D58` | Reports whether reauthentication was accepted |

Reauthentication refreshes the authenticated session without reconnecting. A
session still closes when its authentication deadline expires without a
successful refresh.

### HTTP/2 errors and probe behavior

For HTTP/2 requests that fail authentication, the server returns `401
Unauthorized`. Invalid CONNECT-IP requests return `400 Bad Request`; other
requests return `404 Not Found`. The HTTP/2 listener does not return the fake
nginx HTML response, even when the QUIC listener has censorship-resistant mode
enabled.

---

## 6. HTTP/3 datagram format

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

The first `0x00` is the QUIC varint encoding of Quarter Stream ID 0. The second
`0x00` is the QUIC varint encoding of Context ID 0. Context ID 0 means an
uncompressed IP packet payload in the current implementation.

Client-to-server behavior:

- HTTP/3 clients must send CONNECT-IP datagrams, not raw IP packets.
- The server unwraps the Quarter Stream ID and Context ID varints.
- If the datagram prefix is truncated, the datagram is ignored.
- If the unwrapped IP packet is empty, the datagram is ignored.
- After unwrapping, the same source-address validation used in raw mode is
  applied.

Server-to-client behavior:

- The server preserves the CONNECT-IP datagram prefix when sending to HTTP/3
  clients.
- Mavi clients should strip the CONNECT-IP datagram prefix before writing the
  packet to their TUN interface.
- The shared parser accepts general varint-encoded Quarter Stream ID and
  Context ID values, even though server-generated datagrams currently use the
  fixed two-byte `0x00 0x00` prefix.

---

## 7. Capsule wire format

Capsules use the Capsule Protocol frame format:

```text
[Capsule Type varint][Payload Length varint][Payload bytes]
```

The backend uses QUIC variable-length integers as defined by QUIC. Supported
integer lengths are 1, 2, 4, and 8 bytes. Values are encoded with the standard
two high-bit length prefix:

| Encoded length | Value range |
|---:|---:|
| 1 byte | `0..2^6-1` |
| 2 bytes | `0..2^14-1` |
| 4 bytes | `0..2^30-1` |
| 8 bytes | `0..2^62-1` |

The capsule reader returns `None` for truncated capsules and for advertised
payload lengths that cannot be represented on the current platform. This is
important for 32-bit clients, where blindly casting a large `u64` length to
`usize` would truncate.

Clients parsing the HTTP/3 capsule stream should buffer until a complete
capsule is available, process known capsule types, ignore unknown capsule
types, and enforce a reasonable maximum buffer size. The shared client helper
uses `MAX_CAPSULE_BUF = 64 * 1024`, which comfortably fits the current
standard capsules and the Mavi config capsule.

---

## 8. Address assignment rules

### IPv4 network

IPv4 addresses are assigned from `VPN_NETWORK`.

Default:

```bash
VPN_NETWORK="10.8.0.0/24"
```

Equivalent CLI flag:

```bash
--network-cidr "10.8.0.0/24"
```

Rules:

- The network address is not assigned.
- The gateway address is the second address in the network, usually `.1`.
- The broadcast address is not assigned.
- Client addresses start from the next usable address, usually `.2`.
- Prefixes smaller than `/8` are rejected to avoid excessive memory allocation.
- Prefixes larger than `/30` are rejected because they leave too few usable
  addresses.
- Released IPv4 addresses are returned to the pool when the connection ends.

For example, with `10.8.0.0/24`, the gateway is `10.8.0.1` and the first
client receives `10.8.0.2`. A `/24` provides 253 client addresses because the
network address, gateway address, and broadcast address are excluded. A `/30`
is valid but provides only one client address.

### IPv6 network

IPv6 addresses are assigned from `VPN_NETWORK_V6`.

Default:

```bash
VPN_NETWORK_V6="fd00::/64"
```

Equivalent CLI flag:

```bash
--network-cidr-v6 "fd00::/64"
```

Rules:

- The gateway address is the second address in the IPv6 network, usually
  `::1`.
- Client assignment starts from host suffix `2`, usually `::2`.
- Released IPv6 addresses are returned to a recycle pool and reused before
  fresh suffixes are allocated.
- Prefixes larger than `/126` are rejected because they leave no client address
  after reserving the gateway.
- The configured IPv6 prefix length is sent to clients in `netmask_v6` and in
  the HTTP/3 `ADDRESS_ASSIGN` capsule when IPv6 is active.

For example, with `fd12:3456::/64`, the gateway is `fd12:3456::1` and the first
client receives `fd12:3456::2`.

### IPv6 availability

The backend leases IPv6 addresses during authentication, but it only includes
IPv6 fields in `ControlMessage::Config` and CONNECT-IP capsules when the server
TUN setup reports IPv6 as enabled. If IPv6 setup is not active, the IPv6 fields
in `Config` are `None`, and the HTTP/3 capsule stream contains only IPv4
address assignment and IPv4 route advertisement.

Clients must handle both single-stack IPv4 and dual-stack configurations. A
client should configure IPv6 only when `assigned_ipv6`, `netmask_v6`,
`gateway_v6`, and `dns_server_v6` are present.

---

## 9. MTU contract

The server pushes the inner tunnel MTU to clients in
`ControlMessage::Config.mtu`.

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

or:

```bash
--mtu 1280
```

The value is the MTU of the inner virtual network interface, not the outer
UDP/IP path MTU. Clients should configure their TUN interface with exactly the
`mtu` value received from the server. If the client uses a larger MTU than the
server, it may send packets that cannot be forwarded through the QUIC datagram
path. If the client uses a smaller MTU, throughput may be unnecessarily reduced
and route behavior may differ from the server's assumptions.

The QUIC payload MTU is derived internally as:

```text
QUIC payload MTU = VPN_MTU + 80
```

The additional 80 bytes are a fixed overhead budget for QUIC framing and
cryptographic overhead. `VPN_MTU=1280` produces a QUIC payload MTU of 1360.
`VPN_MTU=1360` produces a QUIC payload MTU of 1440.

Approximate outer wire size is then:

```text
IPv4 outer wire size = QUIC payload MTU + 20 + 8
IPv6 outer wire size = QUIC payload MTU + 40 + 8
```

The `20` or `40` bytes represent the outer IP header, and `8` bytes represent
UDP. The backend logs these derived values at startup.

### Why the default is 1280

`1280` is the minimum MTU required for IPv6 and is broadly safe across mobile,
residential, and tunneled networks. The server allows higher values up to
`1360`, but larger values require more confidence in the outer path MTU.
Operators should raise the MTU only after testing realistic client networks.

### Packet Too Big behavior

If server-to-client datagram sending fails because the datagram is too large,
the backend attempts to generate an ICMP Packet Too Big response toward the TUN
path. For IPv6, the reported MTU is never below 1280. This feedback is a best
effort mechanism; clients should still honor the configured tunnel MTU instead
of relying on ICMP to correct oversized packets.

### MSS clamping

MSS clamping can be enabled with:

```bash
VPN_MSS_CLAMPING=true
```

or:

```bash
--mss-clamping
```

This option is intended to help TCP flows fit inside the tunnel MTU by
rewriting TCP Maximum Segment Size values. It is usually not required when the
default MTU of 1280 is used, but it may be useful when operators choose a
higher MTU or serve networks with unusual path constraints.

---

## 10. DNS and split tunneling

### IPv4 DNS

Configured by:

```bash
VPN_DNS="1.1.1.1"
```

or:

```bash
--dns "1.1.1.1"
```

Sent to clients as:

```rust
dns_server: Ipv4Addr
```

The client should apply this DNS server while the tunnel is connected unless
local policy overrides backend-provided DNS.

### IPv6 DNS

Configured by:

```bash
VPN_DNS_V6="2001:4860:4860::8888"
```

or:

```bash
--dns-v6 "2001:4860:4860::8888"
```

If IPv6 is active and `VPN_DNS_V6` is not set, the backend sends:

```text
2606:4700:4700::1111
```

If IPv6 is not active, `dns_server_v6` is `None` and clients should not install
an IPv6 DNS setting from this connection.

### Split-tunnel whitelist domains

Configured by:

```bash
VPN_WHITELIST_DOMAINS="example.com,internal.test"
```

or:

```bash
--whitelist-domains "example.com,internal.test"
```

Sent to clients as:

```rust
whitelist_domains: Option<Vec<String>>
```

The backend treats the value as a comma-delimited list. It does not normalize,
validate, resolve, or enforce the domains on the server side. Enforcement is a
client responsibility. A typical client interpretation is that listed domains
should bypass the VPN tunnel or be resolved using local DNS, depending on the
client platform's split-tunnel implementation.

An empty list means no domains are excluded by backend configuration. Clients
should distinguish an empty allow-list from local user-defined split-tunnel
rules that may exist outside the backend protocol.

---

## 11. Censorship-resistant behavior

Enable with:

```bash
VPN_CENSORSHIP_RESISTANT=true
```

or:

```bash
--censorship-resistant
```

Effects:

- The server advertises only ALPN `h3`.
- Raw `mavivpn` is not advertised.
- Unauthorized HTTP/3 requests receive a fake nginx-like `200 OK` page.
- Non-CONNECT-IP HTTP/3 requests receive a fake nginx-like `200 OK` page.
- The configured ECH public name is used as the expected cover SNI for logging
  and artifact generation.

ECH-related configuration:

```bash
VPN_ECH_PUBLIC_NAME="cloudflare-ech.com"
VPN_ECH_CONFIG="data/ech_config.bin"
VPN_ECH_KEY="data/ech_key.bin"
```

Equivalent CLI flags:

```bash
--ech-public-name "cloudflare-ech.com"
--ech-config-path "data/ech_config.bin"
--ech-key-path "data/ech_key.bin"
```

When censorship-resistant mode is enabled, the server loads or generates ECH
artifacts: an `ECHConfigList` and an HPKE private key. These artifacts are
intended for client distribution alongside other trust material. The server
logs whether the observed SNI matches the configured cover name.

Current implementation note: the server-side Rustls ECH decrypt path is not
active yet. The backend prepares and persists ECH artifacts for future wiring
and for clients that need the public configuration, but the server currently
does not decrypt inner ClientHello values. Operators should treat ECH support
as preparatory rather than complete.

Camouflage is limited to HTTP/3-shaped traffic. A client that negotiates raw
mode cannot use the camouflage behavior because raw mode is not advertised in
censorship-resistant mode.

---

## 12. Packet validation and routing

### Client-to-server validation

Before a client packet is written to the server TUN path, the backend validates
the inner IP source address. This prevents a connected client from sending
traffic that claims to originate from another client's assigned address.

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

Rejected packets are silently dropped unless the TUN path is already closed, in
which case the tunnel loop exits. The server does not send an application-level
error for every invalid datagram because doing so would create a noisy and
abusable feedback channel on the hot packet path.

### Server-to-client routing

Packets read from the TUN interface are routed by destination address:

- IPv4 destination addresses are looked up in `AppState.peers`.
- IPv6 destination addresses are looked up in `AppState.peers_v6`.
- If no peer is registered for the destination address, the packet is counted
  as a no-peer event and dropped.
- If the per-client channel is full, the packet is dropped and rate-limited
  warnings are logged.
- If the per-client channel is closed, the stale peer entry is removed.

The per-client channel capacity is 4096 packets. The global TUN channel used
for client-to-server writes also has capacity 4096. These queues are intended
to absorb short bursts, not to provide reliable delivery. QUIC datagrams are
unreliable by design, and VPN clients must tolerate packet loss just as they
would on an ordinary IP network.

### Statistics and diagnostics

The backend logs periodic QUIC and tunnel statistics, including:

- Application-level server-to-client throughput
- Application-level client-to-server throughput
- QUIC UDP transmit and receive throughput
- RTT
- Congestion window
- Lost packets and lost bytes
- Maximum datagram size
- Datagram send buffer space
- Server-to-client packet counts and queue length
- Send errors and too-large errors
- Client-to-server packet counts
- TUN drops

These logs are operational diagnostics, not part of the client protocol. They
may change without a protocol version change.

---

## 13. Backend configuration reference

| CLI flag | Environment variable | Default | Description |
|---|---|---|---|
| `--bind-addr` | `VPN_BIND_ADDR` | `0.0.0.0:4433` | UDP address for QUIC server |
| `--http2-bind-addr` | `VPN_HTTP2_BIND_ADDR` | unset | Optional TCP address for HTTP/2 CONNECT-IP |
| `--auth-token` | `VPN_AUTH_TOKEN` | required unless Keycloak is enabled | Static authentication token |
| `--network-cidr` | `VPN_NETWORK` | `10.8.0.0/24` | IPv4 VPN address pool |
| `--network-cidr-v6` | `VPN_NETWORK_V6` | `fd00::/64` | IPv6 VPN address pool |
| `--tun-device-path` | `VPN_TUN_DEVICE` | unset | Optional TUN interface name/path |
| `--dns` | `VPN_DNS` | `1.1.1.1` | IPv4 DNS pushed to clients |
| `--cert-path` | `VPN_CERT` | `data/cert.pem` | TLS certificate path |
| `--key-path` | `VPN_KEY` | `data/key.pem` | TLS private key path |
| `--mtu` | `VPN_MTU` | `1280` | Inner tunnel MTU |
| `--censorship-resistant` | `VPN_CENSORSHIP_RESISTANT` | `false` | Enables HTTP/3 camouflage behavior |
| `--mss-clamping` | `VPN_MSS_CLAMPING` | `false` | Enables TCP MSS clamping |
| `--dns-v6` | `VPN_DNS_V6` | unset | IPv6 DNS pushed to clients; defaults internally when IPv6 is active |
| `--whitelist-domains` | `VPN_WHITELIST_DOMAINS` | empty | Comma-separated split-tunnel whitelist |
| `--keycloak-enabled` | `VPN_KEYCLOAK_ENABLED` | `false` | Enables Keycloak JWT validation |
| `--keycloak-url` | `VPN_KEYCLOAK_URL` | unset | Keycloak base URL |
| `--keycloak-realm` | `VPN_KEYCLOAK_REALM` | `mavi-vpn` | Keycloak realm |
| `--keycloak-client-id` | `VPN_KEYCLOAK_CLIENT_ID` | `mavi-client` | Keycloak client ID checked against `azp` |
| `--keycloak-required-role` | `VPN_KEYCLOAK_REQUIRED_ROLE` | unset | Optional realm/client role required on accepted JWTs |
| `--keycloak-required-scope` | `VPN_KEYCLOAK_REQUIRED_SCOPE` | unset | Optional OAuth scope required on accepted JWTs |
| `--ech-public-name` | `VPN_ECH_PUBLIC_NAME` | `cloudflare-ech.com` | Cover SNI for ECH/camouflage mode |
| `--ech-config-path` | `VPN_ECH_CONFIG` | `data/ech_config.bin` | ECHConfigList path |
| `--ech-key-path` | `VPN_ECH_KEY` | `data/ech_key.bin` | ECH private key path |

Configuration is loaded from a `.env` file when present, from environment
variables, and from CLI arguments. CLI parsing and validation are handled by
`clap`. Invalid values for typed fields such as socket addresses, IP addresses,
and MTU values cause startup to fail.

Validation rules that matter for API consumers and operators:

- Static mode requires `VPN_AUTH_TOKEN` or `--auth-token`.
- Keycloak mode requires `VPN_KEYCLOAK_URL`.
- Keycloak role and scope requirements are valid only when Keycloak is enabled.
- Empty Keycloak role or scope requirement values are rejected.
- `VPN_MTU` must be in `1280..=1360`.
- IPv4 CIDR prefixes must be between `/8` and `/30`, inclusive.
- IPv6 CIDR prefixes must be `/126` or larger networks, meaning prefix length
  must not be greater than 126.

---

## 14. Minimal client implementation checklist

### Raw QUIC client checklist

A compatible raw QUIC client must:

1. Connect to the server over QUIC.
2. Negotiate ALPN `mavivpn`.
3. Open a bidirectional stream.
4. Encode `ControlMessage::Auth { token }` with bincode standard config.
5. Prefix the encoded payload with a little-endian `u32` length.
6. Send the framed auth message.
7. Read a little-endian `u32` length and that many payload bytes.
8. Decode the payload as `ControlMessage::Config` or `ControlMessage::Error`.
9. On `Error`, close the connection and surface the failure.
10. On `Config`, configure the local TUN interface with the assigned IPv4
    address, optional IPv6 address, routes, DNS, and exact MTU.
11. Send raw IPv4 and IPv6 packets as QUIC datagrams.
12. Receive raw IP packets as QUIC datagrams and write them to TUN.
13. Close and clean up local routes, DNS, and interface state when the QUIC
    connection ends.

### HTTP/3 CONNECT-IP client checklist

A compatible HTTP/3 CONNECT-IP client must:

1. Connect to the server over QUIC.
2. Negotiate ALPN `h3`.
3. Start an HTTP/3 connection with datagram and extended CONNECT support.
4. Create one HTTP/3 extended CONNECT-IP request.
5. Send `Authorization: Bearer <token>`.
6. Require a `200 OK` response for successful tunnel setup.
7. Parse the response capsule stream.
8. Process `ADDRESS_ASSIGN` to learn assigned IP addresses and prefixes.
9. Process `ROUTE_ADVERTISEMENT` to learn the default routes.
10. Process `MAVI_CONFIG` to learn DNS, MTU, and whitelist domains.
11. Configure the local TUN interface using the received values.
12. Send IP packets as CONNECT-IP datagrams. In the current single-stream model,
    prefix packets with `0x00 0x00`.
13. Strip CONNECT-IP datagram prefixes from incoming datagrams before writing
    packets to TUN.
14. Close and clean up local network state when the QUIC connection ends.

### HTTP/2 CONNECT-IP client checklist

A compatible HTTP/2 CONNECT-IP client must:

1. Connect to the configured TCP endpoint using TLS with certificate pinning.
2. Negotiate ALPN `h2`.
3. Send an HTTP/2 Extended CONNECT request to
   `/.well-known/masque/ip/*/*/` with protocol `connect-ip`.
4. Include `capsule-protocol: ?1` and `Authorization: Bearer <token>`.
5. Require a `200` response before configuring the local TUN interface.
6. Parse `ADDRESS_ASSIGN`, `ROUTE_ADVERTISEMENT`, and `MAVI_CONFIG` capsules.
7. Send and receive one IP packet per `CAPSULE_DATAGRAM` capsule using context
   ID `0`; do not add the HTTP/3 Quarter Stream ID prefix.
8. Process `MAVI_REAUTH_RESULT` and close when the authenticated session ends.
9. Close and clean up local network state when the HTTP/2 stream or TCP
   connection ends.

### Cross-mode client requirements

All clients should:

- Treat the assigned address as valid only for the lifetime of the QUIC
  connection.
- Use the exact MTU provided by the server.
- Avoid sending packets before setup succeeds.
- Avoid spoofing source addresses; the server will drop such packets.
- Handle packet loss and reordering in the datagram data plane.
- Implement reconnect backoff for authentication, capacity, and network
  failures.
- Keep user-visible error messages separate from protocol string matching.
- Handle configurations with no IPv6 fields.
- Handle configurations with an empty split-tunnel whitelist.

---

## 15. Example startup configurations

### Local static-token development

```bash
VPN_BIND_ADDR="0.0.0.0:4433"
VPN_AUTH_TOKEN="dev-secret-change-me"
VPN_NETWORK="10.8.0.0/24"
VPN_NETWORK_V6="fd00::/64"
VPN_DNS="1.1.1.1"
VPN_MTU=1280
```

This mode advertises both `mavivpn` and `h3`, accepts either raw or HTTP/3
clients, and uses a static token.

### HTTP/3-only camouflage deployment

```bash
VPN_BIND_ADDR="0.0.0.0:4433"
VPN_AUTH_TOKEN="long-random-secret"
VPN_CENSORSHIP_RESISTANT=true
VPN_ECH_PUBLIC_NAME="cloudflare-ech.com"
VPN_ECH_CONFIG="data/ech_config.bin"
VPN_ECH_KEY="data/ech_key.bin"
VPN_CERT="data/cert.pem"
VPN_KEY="data/key.pem"
```

This mode advertises only `h3`. Unauthorized and non-CONNECT-IP HTTP/3 requests
receive nginx-like `200 OK` camouflage responses.

### Keycloak deployment with role and scope policy

```bash
VPN_KEYCLOAK_ENABLED=true
VPN_KEYCLOAK_URL="https://auth.example.com"
VPN_KEYCLOAK_REALM="mavi-vpn"
VPN_KEYCLOAK_CLIENT_ID="mavi-client"
VPN_KEYCLOAK_REQUIRED_ROLE="vpn-user"
VPN_KEYCLOAK_REQUIRED_SCOPE="vpn:connect"
VPN_NETWORK="10.8.0.0/24"
VPN_NETWORK_V6="fd12:3456::/64"
VPN_DNS="9.9.9.9"
VPN_DNS_V6="2620:fe::fe"
```

In this mode, the backend rejects tokens that are expired, not yet valid,
issued by the wrong realm, issued to the wrong `azp`, missing the configured
role, or missing the configured scope. Static token fallback is not used.

---

## 16. Error handling contract

The backend intentionally keeps the client-visible error surface small.

Raw mode can return a bincode `ControlMessage::Error` during the authentication
stream. After the control stream has succeeded, packet-level errors are handled
by dropping invalid datagrams or by best-effort ICMP Packet Too Big generation
for oversized server-to-client packets.

HTTP/3 mode can return HTTP status errors before tunnel setup succeeds:

- `401 Unauthorized` for failed authentication in standard mode
- `404 Not Found` for non-CONNECT-IP requests in standard mode
- Fake `200 OK` camouflage responses in censorship-resistant mode

After HTTP/3 tunnel setup succeeds, the data plane is datagram based. Invalid
datagrams are ignored. Connection-level failures are surfaced by the QUIC or
HTTP/3 stack rather than by application JSON errors.

Clients should classify failures broadly:

| Failure | Typical client classification |
|---|---|
| Auth error or `401` | Credentials rejected |
| Missing or malformed config | Protocol incompatibility |
| Address pool exhausted | Temporary server capacity problem |
| QUIC connection closed | Network/session ended |
| Datagram loss | Normal packet loss |
| No IPv6 config | IPv4-only session |
| Camouflage `200 OK` without capsules | Not an authenticated VPN session |

---

## 17. Security considerations

The backend protocol is designed around a small trusted setup exchange and a
restricted packet forwarding loop.

Important security properties:

- TLS 1.3 protects the QUIC connection.
- Static token comparison uses constant-time equality.
- Keycloak `azp`, issuer, expiry, optional `nbf`, optional role, and optional
  scope are validated.
- Keycloak startup fails closed when JWKS cannot be loaded.
- Unknown Keycloak `kid` values can trigger a controlled JWKS refresh.
- Every client-to-server packet is source-address checked against the assigned
  address pair.
- IPv4 pool size is bounded by rejecting overly broad prefixes below `/8`.
- IPv6 prefixes that cannot provide a client address after the gateway are
  rejected.
- Censorship-resistant mode avoids explicit VPN errors for unauthorized
  HTTP/3-shaped probes.

Important limitations:

- Static token authentication is only as strong as token entropy and secret
  handling.
- There is no explicit per-protocol version field in the current handshake.
- Raw bincode clients in other languages must match Rust enum encoding exactly.
- Server-side ECH decrypt support is not active yet.
- The data plane uses unreliable datagrams; reliable delivery is left to inner
  protocols such as TCP.
- Split-tunnel domain enforcement is delegated to clients.

Operators should use long random static tokens or Keycloak JWTs, protect server
private keys, monitor logs for repeated failed authentication, and keep client
and server versions aligned when changing shared wire structures.

---

## 18. Versioning note

There is no explicit protocol version field in the current wire format.
Compatibility currently depends on:

- The `ControlMessage` enum shape
- The bincode configuration
- The capsule type constants
- The CONNECT-IP capsule payload layouts
- The datagram framing rules
- The negotiated ALPN protocol
- The semantics of configuration fields such as `mtu`, DNS, and whitelist
  domains

If this API evolves, prefer one of these strategies:

1. Add an explicit protocol version to the raw control handshake.
2. Add a versioned vendor capsule for HTTP/3 mode.
3. Introduce a capability list in `ControlMessage::Config`.
4. Keep old enum variants and capsule types readable until all supported
   clients have migrated.

Backward-compatible additions are easiest when they are optional fields,
unknown capsules, or client-ignored capabilities. Changes to bincode enum
layout, required capsule ordering, datagram prefix assumptions, or authentication
semantics should be treated as protocol migrations and documented with a clear
compatibility plan.
