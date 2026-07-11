# Mavi VPN Security Review Checklist

This checklist lets maintainers repeat the defensive security review for the
local checkout. Record command output, commit SHA, OS, tool versions, and any
blocked checks in the review notes.

## 1. Scope And Baseline

- [ ] Record repository URL and commit: `git remote -v` and `git rev-parse HEAD`.
- [ ] Record local changes: `git status --short --branch` and `git diff --stat`.
- [ ] Decide whether uncommitted changes are in scope.
- [ ] Record OS, shell, Rust version, Node/npm version, Java/Gradle version, Docker version, and GH CLI auth state.
- [ ] Confirm no real production `.env`, key, keystore, signing, or release credential files are present in the checkout.

## 2. Architecture And Trust Boundaries

- [ ] Map server trust boundaries: QUIC listener, optional HTTP/2 TLS/TCP listener, raw bincode control stream, HTTP/3/HTTP/2 MASQUE `connect-ip`, TUN device, iptables/ip6tables.
- [ ] Map client trust boundaries: GUI/CLI process, privileged Windows service or Linux daemon, local IPC token, TUN/WinTUN, DNS/routing state.
- [ ] Map Android trust boundaries: exported Activity, OAuth deep link, VpnService, JNI handles, native Rust session.
- [ ] Map Tauri trust boundaries: webview, exposed `#[tauri::command]` handlers, capabilities, shell permissions, config storage.
- [ ] Map deployment trust boundaries: Docker host networking, `/dev/net/tun`, mounted data, Traefik Docker socket, Keycloak database.
- [ ] Map CI/CD trust boundaries: Actions token permissions, Dependabot auto-merge, artifacts, release credentials, third-party actions.

## 3. Local Auth And IPC

- [ ] Verify IPC is bound only to loopback and not all interfaces.
- [ ] Verify every IPC request uses `SecureIpcRequest` and constant-time token comparison.
- [ ] Verify request and response sizes are bounded and slow clients time out.
- [ ] Linux: verify `/var/run/mavi-vpn.token` is created with `0600` or `0640` for group `mavivpn`, never world-readable.
- [ ] Linux: verify token file creation uses no-follow semantics and replaces stale weak files.
- [ ] Windows: verify `C:\ProgramData\mavi-vpn\ipc.token` and parent directory ACLs grant only SYSTEM, Administrators, and the active trusted user.
- [ ] Windows: verify ACL re-hardening on session changes.
- [ ] Verify `Start`, `Stop`, and `RepairNetwork` cannot be invoked without the local IPC token.
- [ ] Treat membership in `mavivpn` or read access to the Windows IPC token as privilege to control VPN routing.

## 4. Server Auth, JWT, QUIC, HTTP/2, MASQUE

- [ ] Static token mode: verify empty `VPN_AUTH_TOKEN` refuses startup or rejects auth.
- [ ] Keycloak mode: verify missing URL or JWKS fetch failure aborts startup and does not fall back to static token.
- [ ] JWT: verify algorithm is restricted, issuer is checked, `exp` and `nbf` are enforced with bounded leeway.
- [ ] JWT: verify client binding is enforced through `azp` or documented audience policy.
- [ ] JWT: test unknown `kid`, JWKS refresh cooldown, JWKS outage, and rotation behavior.
- [ ] QUIC raw mode: verify auth frame length limit and handshake timeout.
- [ ] HTTP/3/MASQUE: verify only authenticated `connect-ip` sessions get tunnel config capsules.
- [ ] HTTP/2: verify TLS ALPN is `h2`, the exact Extended CONNECT method/path/protocol/capsule headers are required, and malformed requests cannot reach the tunnel handler.
- [ ] HTTP/2: verify authentication, session expiry, reauthentication capsules, and `CAPSULE_DATAGRAM` parsing have bounded buffers and correct error responses.
- [ ] HTTP/2: verify the optional TCP listener is disabled by default and is not confused with the HTTP reverse proxy/Traefik web listener.
- [ ] Datagrams: verify client-to-server packets are dropped unless source IP matches the assigned IPv4/IPv6 lease.
- [ ] Verify connection limits and queue bounds under unauthenticated connection churn.

## 5. Secrets At Rest

- [ ] Server TLS private key: verify mode `0600` on Unix and no symlink clobbering.
- [ ] Server ECH private key: verify owner-only permissions; if missing, fix to match TLS key handling.
- [ ] Server generated pin/config files: classify `cert_pin.txt` and `ech_config_hex.txt` as public distribution artifacts.
- [ ] Linux CLI config: verify saved config is `0600`.
- [ ] Windows CLI config: verify config path and ACLs protect static tokens and Keycloak access tokens.
- [ ] Tauri GUI config and prefs: verify JSON files do not persist static tokens or use OS secret storage.
- [ ] Android: verify access tokens, refresh tokens, and preshared keys are stored in encrypted storage or Android Keystore-backed storage.
- [ ] Logs: verify tokens, refresh tokens, JWT bodies, private keys, and full token exchange responses are not logged.

## 6. Platform-Specific Privileged Code

- [ ] Windows: verify `wintun.dll` extraction path is not user-writable by an untrusted user before privileged load.
- [ ] Windows: verify DLL loading uses an expected, private path and validates the embedded DLL before loading.
- [ ] Windows: verify MSI service install path is quoted and binary directory ACLs are not user-writable.
- [ ] Windows: verify adding install dir to system `PATH` cannot create binary hijack risk.
- [ ] Windows: verify NRPT, host routes, DNS, and persisted cleanup files in ProgramData are protected by ACLs.
- [ ] Linux: verify systemd unit hardening (`NoNewPrivileges`, capability bounding, protect system/home, private tmp, restricted address families).
- [ ] Linux: verify installer-created group membership is explicit and documented as privileged.
- [ ] Linux: verify DNS restore survives crash, SIGKILL, and partial setup failures.
- [ ] Android: verify exported components are required and protected by appropriate permissions or state validation.
- [ ] Android: verify OAuth callback validates state and PKCE verifier and handles duplicate/concurrent callbacks safely.
- [ ] Android JNI: verify all raw handles are generation-checked, cannot be double-freed, and fail closed on invalid values.

## 7. Docker And Deployment

- [ ] Replace default `VPN_AUTH_TOKEN=change_me` before deployment; fail startup if the default is used.
- [ ] Review whether `privileged: true` is required; prefer `cap_add: [NET_ADMIN]`, `/dev/net/tun`, and least privilege.
- [ ] Review `network_mode: host`; document host firewall impact and alternatives.
- [ ] Verify entrypoint iptables/ip6tables rules are namespaced, idempotent, and cleaned up or clearly owned.
- [ ] Verify persisted `./data` permissions for cert, key, ECH key, pins, and configs.
- [ ] Pin Docker images by digest for production or record image provenance.
- [ ] Remove demo `whoami` profile from production deployments or ensure it is not exposed.
- [ ] Protect Traefik dashboard and understand the read-only Docker socket risk.
- [ ] Replace default Keycloak database/admin passwords before use.

## 8. Supply Chain And CI/CD

- [ ] Review Git dependencies in `Cargo.toml`; branch pins must be replaced with commit/tag pins for reproducible releases.
- [ ] Run Rust dependency checks: `cargo deny check`, `cargo audit`, and optionally `cargo vet`.
- [ ] Run unsafe inventory: `cargo geiger` or manual `rg` review.
- [ ] Review `deny.toml` ignored advisories and require dated justifications.
- [ ] Prefer `npm ci` over `npm install` in CI builds.
- [ ] Run frontend checks in `gui/`: `npm ci`, `npm audit`, `npm run test`, `npm run test:coverage`.
- [ ] Run Android checks in `android/`: `./gradlew testDebugUnitTest jacocoDebugUnitTestReport` and dependency audit.
- [ ] Review GitHub Actions `permissions`; use least privilege at workflow/job scope.
- [ ] Review Dependabot auto-merge; require full green checks and avoid broad write permissions where possible.
- [ ] Review uploaded artifacts for poisoning risk and release signing/provenance.

## 9. Commands

Run from the repository root unless noted.

```powershell
git status --short --branch
git diff --stat
cargo test-core-workspace
cargo clippy --workspace --exclude windows-vpn --all-targets -- -D warnings
rg -n 'unsafe\s*\{|unsafe fn|extern "|no_mangle|Box::from_raw|from_raw_fd|Command::new|subprocess\.run' -S -g "!target/**" -g "!gui/node_modules/**"
rg -n "(?i)(password|secret|token|private.?key|client_secret|refresh_token|access_token|BEGIN .*PRIVATE KEY|change_me)" -S -g "!target/**" -g "!gui/node_modules/**" -g "!android/app/build/**"
gh workflow list --repo zerox80/mavi-vpn
gh run list --repo zerox80/mavi-vpn --limit 20
```

If installed:

```powershell
cargo deny check
cargo audit
cargo geiger
cargo vet
```

Frontend:

```powershell
cd gui
npm ci
npm audit
npm run test
npm run test:coverage
```

Android:

```powershell
cd android
.\gradlew.bat testDebugUnitTest jacocoDebugUnitTestReport
.\gradlew.bat dependencies
```

Docker:

```powershell
docker compose -f backend/docker-compose.yml config
docker compose -f backend/keycloak/docker-compose.yml config
docker scout cves mavi-vpn-server
```

## 10. Evidence And Blocked Checks

For every completed check, save:

- [ ] Command and working directory.
- [ ] Exit code.
- [ ] Key output lines.
- [ ] Date, OS, tool version.
- [ ] Relevant file/line references.

For every blocked check, save:

- [ ] Missing tool or policy that blocked execution.
- [ ] Exact error text.
- [ ] How to reproduce in CI or a prepared dev environment.
- [ ] Whether the blocked check affects release readiness.

## 11. Finding Template

Use this template for each confirmed finding:

```text
Title:
Severity:
Affected files/functions:
Description:
Security relevance:
Defensive scenario:
Review or reproduction steps:
Recommended fix:
Regression test idea:
Confidence:
```

Mark unverified issues as hypotheses and list the exact verification steps.
