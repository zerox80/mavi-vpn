import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  escapeHtml,
  initials,
  bandwidthWalk,
  friendlyError,
  heroFromVpnStatus,
  toConfig,
} from '../utils.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

describe('escapeHtml', () => {
  it('returns empty string unchanged', () => {
    expect(escapeHtml('')).toBe('');
  });

  it('escapes ampersand', () => {
    expect(escapeHtml('a&b')).toBe('a&amp;b');
  });

  it('escapes angle brackets', () => {
    expect(escapeHtml('<div>')).toBe('&lt;div&gt;');
  });

  it('escapes quotes', () => {
    expect(escapeHtml('"hello"')).toBe('&quot;hello&quot;');
  });

  it('escapes single quotes', () => {
    expect(escapeHtml("it's")).toBe('it&#39;s');
  });

  it('leaves safe text unchanged', () => {
    expect(escapeHtml('hello world 123')).toBe('hello world 123');
  });

  it('converts non-string input via String()', () => {
    expect(escapeHtml(null)).toBe('null');
    expect(escapeHtml(42)).toBe('42');
  });
});

describe('initials', () => {
  it('returns first char for single word', () => {
    expect(initials('Hello')).toBe('H');
  });

  it('returns first char of first two words', () => {
    expect(initials('My Server')).toBe('MS');
  });

  it('handles underscores, slashes, and ·', () => {
    expect(initials('my_server')).toBe('MS');
    expect(initials('my/server')).toBe('MS');
    expect(initials('my·server')).toBe('MS');
  });

  it('returns ? for empty string but coerces other values', () => {
    expect(initials('')).toBe('?');
    expect(initials(null)).toBe('N'); // from "null"
    expect(initials(undefined)).toBe('U'); // from "undefined"
    expect(initials(42)).toBe('4');
  });
});

describe('bandwidthWalk', () => {
  it('returns correct number of values', () => {
    expect(bandwidthWalk(10)).toHaveLength(10);
    expect(bandwidthWalk(60)).toHaveLength(60);
  });

  it('is deterministic with same seed', () => {
    const a = bandwidthWalk(20, 42);
    const b = bandwidthWalk(20, 42);
    expect(a).toEqual(b);
  });

  it('values are in reasonable range', () => {
    const values = bandwidthWalk(100);
    for (const v of values) {
      expect(v).toBeGreaterThan(0);
      expect(v).toBeLessThanOrEqual(1.1);
    }
  });

  it('different seeds produce different results', () => {
    const a = bandwidthWalk(10, 1);
    const b = bandwidthWalk(10, 2);
    expect(a).not.toEqual(b);
  });

  it('returns empty array for n=0', () => {
    expect(bandwidthWalk(0)).toEqual([]);
  });
});

describe('friendlyError', () => {
  it('detects connection refused', () => {
    expect(friendlyError('connection refused')).toBe('VPN daemon is not running.');
  });

  it('detects timeout', () => {
    expect(friendlyError('connection timed out')).toBe(
      'Connection timed out. Check endpoint and firewall.'
    );
  });

  it('detects certificate error', () => {
    expect(friendlyError('certificate verification failed')).toBe(
      'Certificate error. Verify the certificate PIN.'
    );
  });

  it('returns raw message for unknown errors', () => {
    expect(friendlyError('something else')).toBe('something else');
  });

  it('detects German connection refused', () => {
    expect(friendlyError('Verbindung verweigert')).toBe('VPN daemon is not running.');
  });

  it('detects Windows error code 10061', () => {
    expect(friendlyError('error 10061')).toBe('VPN daemon is not running.');
  });

  it('detects Windows error code 10060', () => {
    expect(friendlyError('error 10060')).toBe('Connection timed out. Check endpoint and firewall.');
  });
});

describe('toConfig', () => {
  it('builds config from connection and token', () => {
    const conn = {
      endpoint: 'vpn.example.com:443',
      token: 'my-token',
      cert_pin: 'abcdef',
      censorship_resistant: true,
      http3_framing: false,
      vpn_mtu: 1340,
    };
    const config = toConfig(conn);
    expect(config.endpoint).toBe('vpn.example.com:443');
    expect(config.token).toBe('my-token');
    expect(config.cert_pin).toBe('abcdef');
    expect(config.censorship_resistant).toBe(true);
    expect(config.http3_framing).toBe(false);
    expect(config.kc_auth).toBeNull();
    expect(config.ech_config).toBeNull();
    expect(config.vpn_mtu).toBe(1340);
  });

  it('includes keycloak fields and leaves runtime token empty', () => {
    const conn = {
      endpoint: 'vpn.example.com:443',
      token: 'stale-jwt-should-not-be-used-as-psk',
      cert_pin: 'pin',
      kc_auth: true,
      kc_url: 'https://auth.example.com',
      kc_realm: 'my-realm',
      kc_client_id: 'my-client',
    };
    const config = toConfig(conn);
    expect(config.token).toBe('');
    expect(config.kc_auth).toBe(true);
    expect(config.kc_url).toBe('https://auth.example.com');
    expect(config.kc_realm).toBe('my-realm');
    expect(config.kc_client_id).toBe('my-client');
  });

  it('defaults missing fields to null for empty connection', () => {
    const conn = {};
    const config = toConfig(conn);
    expect(config.endpoint).toBeUndefined();
    expect(config.token).toBe('');
    expect(config.cert_pin).toBeUndefined();
    expect(config.censorship_resistant).toBe(false);
    expect(config.http3_framing).toBe(false);
    expect(config.kc_auth).toBeNull();
    expect(config.kc_url).toBeNull();
    expect(config.kc_realm).toBeNull();
    expect(config.kc_client_id).toBeNull();
    expect(config.ech_config).toBeNull();
  });

  it('normalizes boolean fields', () => {
    const config = toConfig({ censorship_resistant: 1, http3_framing: 'yes' });
    expect(config.censorship_resistant).toBe(true);
    expect(config.http3_framing).toBe(true);
  });
});

describe('heroFromVpnStatus', () => {
  it('maps stopped to off even when the current hero is connecting', () => {
    expect(
      heroFromVpnStatus(
        { service_available: true, running: false, state: 'Stopped' },
        'connecting',
        false
      )
    ).toBe('off');
  });

  it('maps stopping to disconnecting instead of connecting', () => {
    expect(
      heroFromVpnStatus({ service_available: true, running: false, state: 'Stopping' }, 'on', true)
    ).toBe('disconnecting');
  });

  it('keeps a local disconnect flow out of the yellow connecting state', () => {
    expect(
      heroFromVpnStatus(
        { service_available: true, running: false, state: 'Starting' },
        'disconnecting',
        true
      )
    ).toBe('disconnecting');
  });

  it('maps service unavailable to off', () => {
    expect(heroFromVpnStatus({ service_available: false })).toBe('off');
  });

  it('maps Failed state to off', () => {
    expect(heroFromVpnStatus({ service_available: true, state: 'Failed' })).toBe('off');
  });

  it('maps Starting to connecting', () => {
    expect(heroFromVpnStatus({ service_available: true, state: 'Starting' })).toBe('connecting');
  });

  it('maps Connected or running=true to on', () => {
    expect(heroFromVpnStatus({ service_available: true, state: 'Connected' })).toBe('on');
    expect(heroFromVpnStatus({ service_available: true, running: true })).toBe('on');
  });

  it('maps Stopping or disconnecting=true to disconnecting', () => {
    expect(heroFromVpnStatus({ service_available: true, state: 'Stopping' })).toBe('disconnecting');
    expect(heroFromVpnStatus({ service_available: true, state: 'Starting' }, 'on', true)).toBe(
      'disconnecting'
    );
  });
});

describe('index.html', () => {
  it('loads main.js as an ES module', () => {
    const html = readFileSync(resolve(__dirname, '../index.html'), 'utf8');
    expect(html).toContain('<script type="module" src="main.js"></script>');
  });

  it('does not expose the old settings tab or save credentials button', () => {
    const html = readFileSync(resolve(__dirname, '../index.html'), 'utf8');
    expect(html).not.toContain('data-tab="settings"');
    expect(html).not.toContain('data-panel="settings"');
    expect(html).not.toContain('id="save-btn"');
  });

  it('keeps the pre-shared key in the connection editor', () => {
    const html = readFileSync(resolve(__dirname, '../index.html'), 'utf8');
    expect(html).toContain('id="m-token-field"');
    expect(html).toContain('id="m_token"');
  });
});
