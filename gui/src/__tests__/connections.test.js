import { beforeEach, describe, expect, it, vi } from 'vitest';
import { state } from '../state.js';
import {
  connectionFromLegacyConfig,
  migrateLegacyConfig,
  validMtu,
} from '../connections.js';
import { savePrefs } from '../theme.js';

vi.mock('../theme.js', () => ({
  savePrefs: vi.fn(() => Promise.resolve()),
}));

describe('validMtu', () => {
  it('accepts supported integer MTU bounds', () => {
    expect(validMtu(1280)).toBe(1280);
    expect(validMtu('1360')).toBe(1360);
  });

  it('rejects unsupported, fractional, and missing MTU values', () => {
    expect(validMtu(1279)).toBeNull();
    expect(validMtu(1361)).toBeNull();
    expect(validMtu(1280.5)).toBeNull();
    expect(validMtu(undefined)).toBeNull();
  });
});

describe('connectionFromLegacyConfig', () => {
  it('preserves ECH and MTU fields from legacy config', () => {
    const conn = connectionFromLegacyConfig({
      endpoint: 'vpn.example.com:443',
      token: 'token',
      cert_pin: 'pin',
      ech_config: 'abcdef',
      censorship_resistant: true,
      http3_framing: true,
      vpn_mtu: 1340,
    });

    expect(conn.endpoint).toBe('vpn.example.com:443');
    expect(conn.token).toBe('token');
    expect(conn.ech_config).toBe('abcdef');
    expect(conn.censorship_resistant).toBe(true);
    expect(conn.http3_framing).toBe(true);
    expect(conn.vpn_mtu).toBe(1340);
  });

  it('uses Keycloak mode without preserving stale token', () => {
    const conn = connectionFromLegacyConfig({
      endpoint: 'vpn.example.com:443',
      token: 'stale',
      cert_pin: 'pin',
      kc_auth: true,
      kc_url: 'https://auth.example.com',
      kc_realm: 'realm',
      kc_client_id: 'client',
    });

    expect(conn.token).toBeNull();
    expect(conn.kc_auth).toBe(true);
    expect(conn.kc_url).toBe('https://auth.example.com');
    expect(conn.kc_realm).toBe('realm');
    expect(conn.kc_client_id).toBe('client');
  });

  it('keeps existing identity fields during migration overwrite', () => {
    const conn = connectionFromLegacyConfig(
      {
        endpoint: 'vpn.example.com:443',
        token: 'new-token',
        cert_pin: 'new-pin',
      },
      { id: 'existing-id', label: 'Existing Node' }
    );

    expect(conn.id).toBe('existing-id');
    expect(conn.label).toBe('Existing Node');
    expect(conn.token).toBe('new-token');
    expect(conn.cert_pin).toBe('new-pin');
  });
});

describe('migrateLegacyConfig', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    state.prefs.connections = [];
    state.prefs.active_id = null;
    state.prefs.legacy_config_migrated = false;
  });

  it('creates and selects a connection from legacy config', async () => {
    await migrateLegacyConfig({
      endpoint: 'vpn.example.com:443',
      token: 'token',
      cert_pin: 'pin',
      vpn_mtu: 1280,
    });

    expect(state.prefs.legacy_config_migrated).toBe(true);
    expect(state.prefs.connections).toHaveLength(1);
    expect(state.prefs.active_id).toBe(state.prefs.connections[0].id);
    expect(savePrefs).toHaveBeenCalledOnce();
  });

  it('updates an existing endpoint instead of duplicating it', async () => {
    state.prefs.connections = [
      {
        id: 'existing',
        label: 'Existing',
        endpoint: 'vpn.example.com:443',
        token: 'old',
        cert_pin: 'old',
      },
    ];

    await migrateLegacyConfig({
      endpoint: 'vpn.example.com:443',
      token: 'new',
      cert_pin: 'new-pin',
    });

    expect(state.prefs.connections).toHaveLength(1);
    expect(state.prefs.connections[0].id).toBe('existing');
    expect(state.prefs.connections[0].token).toBe('new');
    expect(state.prefs.connections[0].cert_pin).toBe('new-pin');
  });

  it('does not migrate twice', async () => {
    state.prefs.legacy_config_migrated = true;

    await migrateLegacyConfig({ endpoint: 'vpn.example.com:443' });

    expect(state.prefs.connections).toEqual([]);
    expect(savePrefs).not.toHaveBeenCalled();
  });
});
