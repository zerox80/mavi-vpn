export function escapeHtml(s) {
  return String(s).replace(
    /[&<>"']/g,
    (ch) =>
      ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
      })[ch]
  );
}

export function initials(label) {
  const parts = String(label)
    .split(/[\s·\-_/]+/)
    .filter(Boolean);
  const s = (parts[0]?.[0] || '?') + (parts[1]?.[0] || '');
  return s.toUpperCase();
}

export function bandwidthWalk(n, seed = 42) {
  const out = [];
  let x = seed;
  for (let i = 0; i < n; i++) {
    x = (x * 9301 + 49297) % 233280;
    out.push(0.3 + 0.55 * (x / 233280) + 0.15 * Math.sin(i / 4));
  }
  return out;
}

export function friendlyError(e) {
  const s = String(e);
  if (
    s.includes('10061') ||
    s.includes('connection refused') ||
    s.includes('Verbindung verweigert')
  )
    return 'VPN daemon is not running.';
  if (s.includes('10060') || s.includes('timed out'))
    return 'Connection timed out. Check endpoint and firewall.';
  if (s.includes('cert') || s.includes('certificate'))
    return 'Certificate error. Verify the certificate PIN.';
  return s;
}

export function heroFromVpnStatus(status = {}, currentHero = 'off', disconnecting = false) {
  const serviceAvailable = !!status.service_available;
  const running = !!status.running;
  const vpnState = status.state || (running ? 'Connected' : 'Stopped');

  if (!serviceAvailable || vpnState === 'Failed' || vpnState === 'Stopped') return 'off';
  if (disconnecting || vpnState === 'Stopping') return 'disconnecting';
  if (running || vpnState === 'Connected') return 'on';
  if (vpnState === 'Starting') return 'connecting';
  return currentHero === 'disconnecting' ? 'disconnecting' : 'off';
}

export function toConfig(conn) {
  const kcAuth = !!conn.kc_auth;
  return {
    endpoint: conn.endpoint,
    token: kcAuth ? '' : (conn.token ?? ''),
    cert_pin: conn.cert_pin,
    censorship_resistant: !!conn.censorship_resistant,
    http3_framing: !!conn.http3_framing,
    kc_auth: kcAuth || null,
    kc_url: kcAuth ? (conn.kc_url ?? null) : null,
    kc_realm: kcAuth ? (conn.kc_realm ?? null) : null,
    kc_client_id: kcAuth ? (conn.kc_client_id ?? null) : null,
    ech_config: conn.ech_config ?? null,
    vpn_mtu: conn.vpn_mtu ?? null,
  };
}
