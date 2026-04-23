export function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[ch]));
}

export function initials(label) {
  const parts = String(label).split(/[\s·\-_/]+/).filter(Boolean);
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
  if (s.includes('10061') || s.includes('connection refused') || s.includes('Verbindung verweigerte'))
    return 'VPN daemon is not running.';
  if (s.includes('10060') || s.includes('timed out'))
    return 'Connection timed out. Check endpoint and firewall.';
  if (s.includes('cert') || s.includes('certificate'))
    return 'Certificate error. Verify the certificate PIN.';
  return s;
}

export function toConfig(conn, token) {
  return {
    endpoint: conn.endpoint,
    token,
    cert_pin: conn.cert_pin,
    censorship_resistant: !!conn.censorship_resistant,
    http3_framing: !!conn.http3_framing,
    kc_auth: conn.kc_auth ?? null,
    kc_url: conn.kc_url ?? null,
    kc_realm: conn.kc_realm ?? null,
    kc_client_id: conn.kc_client_id ?? null,
    ech_config: conn.ech_config ?? null,
  };
}
