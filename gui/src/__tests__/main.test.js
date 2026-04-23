import { describe, it, expect } from 'vitest';
import { escapeHtml, initials, bandwidthWalk, friendlyError, toConfig } from '../utils.js';

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

  it('handles hyphenated names', () => {
    expect(initials('my-server')).toBe('MS');
  });

  it('returns ? for empty string', () => {
    expect(initials('')).toBe('?');
  });

  it('takes first char of first two words for 3+ words', () => {
    expect(initials('My Test Server')).toBe('MT');
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
    expect(friendlyError('connection timed out')).toBe('Connection timed out. Check endpoint and firewall.');
  });

  it('detects certificate error', () => {
    expect(friendlyError('certificate verification failed')).toBe('Certificate error. Verify the certificate PIN.');
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
      cert_pin: 'abcdef',
      censorship_resistant: true,
      http3_framing: false,
    };
    const config = toConfig(conn, 'my-token');
    expect(config.endpoint).toBe('vpn.example.com:443');
    expect(config.token).toBe('my-token');
    expect(config.cert_pin).toBe('abcdef');
    expect(config.censorship_resistant).toBe(true);
    expect(config.http3_framing).toBe(false);
    expect(config.kc_auth).toBeNull();
    expect(config.ech_config).toBeNull();
  });

  it('includes keycloak fields when present', () => {
    const conn = {
      endpoint: 'vpn.example.com:443',
      cert_pin: 'pin',
      kc_auth: true,
      kc_url: 'https://auth.example.com',
      kc_realm: 'my-realm',
      kc_client_id: 'my-client',
    };
    const config = toConfig(conn, 'tok');
    expect(config.kc_auth).toBe(true);
    expect(config.kc_url).toBe('https://auth.example.com');
    expect(config.kc_realm).toBe('my-realm');
    expect(config.kc_client_id).toBe('my-client');
  });

  it('defaults missing fields to null for empty connection', () => {
    const conn = {};
    const config = toConfig(conn, 'tok');
    expect(config.endpoint).toBeUndefined();
    expect(config.token).toBe('tok');
    expect(config.cert_pin).toBeUndefined();
    expect(config.censorship_resistant).toBe(false);
    expect(config.http3_framing).toBe(false);
    expect(config.kc_auth).toBeNull();
    expect(config.kc_url).toBeNull();
    expect(config.kc_realm).toBeNull();
    expect(config.kc_client_id).toBeNull();
    expect(config.ech_config).toBeNull();
  });
});
