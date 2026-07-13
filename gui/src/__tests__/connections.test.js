import { beforeEach, describe, expect, it, vi } from 'vitest';
import { state } from '../state.js';
import {
  connectionFromLegacyConfig,
  migrateLegacyConfig,
  renderConnectionList,
  selectConnection,
  validMtu,
  wireSidebarSearch,
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
    expect(conn.split_tunnel_mode).toBe('disabled');
    expect(conn.split_tunnel_targets).toEqual([]);
  });

  it('preserves desktop split-tunnel fields from legacy config', () => {
    const conn = connectionFromLegacyConfig({
      endpoint: 'vpn.example.com:443',
      split_tunnel_mode: 'exclude',
      split_tunnel_targets: ['updates.example.com'],
    });

    expect(conn.split_tunnel_mode).toBe('exclude');
    expect(conn.split_tunnel_targets).toEqual(['updates.example.com']);
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

  it('selects an overwritten legacy connection when no active id exists', async () => {
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

    expect(state.prefs.active_id).toBe('existing');
  });

  it('marks migration complete even without a legacy endpoint', async () => {
    await migrateLegacyConfig({});

    expect(state.prefs.legacy_config_migrated).toBe(true);
    expect(state.prefs.connections).toEqual([]);
    expect(savePrefs).toHaveBeenCalledOnce();
  });

  it('does not migrate twice', async () => {
    state.prefs.legacy_config_migrated = true;

    await migrateLegacyConfig({ endpoint: 'vpn.example.com:443' });

    expect(state.prefs.connections).toEqual([]);
    expect(savePrefs).not.toHaveBeenCalled();
  });
});

describe('connection list rendering and selection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    document.body.innerHTML = `
      <input id="search" />
      <button id="add-conn-btn"></button>
      <div id="connection-list"></div>
    `;
    state.search = '';
    state.hero = 'off';
    state.prefs.active_id = 'one';
    state.prefs.connections = [
      { id: 'one', label: 'Primary Node', endpoint: 'one.example:443' },
      { id: 'two', label: 'Backup Node', endpoint: 'two.example:443' },
    ];
  });

  it('renders saved connections and selected state', () => {
    renderConnectionList();

    const rows = document.querySelectorAll('.conn-row');
    expect(rows).toHaveLength(2);
    expect(rows[0].classList.contains('selected')).toBe(true);
    expect(rows[0].textContent).toContain('Primary Node');
  });

  it('renders active and connecting selection classes', () => {
    state.hero = 'on';
    renderConnectionList();
    expect(document.querySelector('.conn-row').className).toContain('active');

    state.hero = 'connecting';
    renderConnectionList();
    expect(document.querySelector('.conn-row').className).toContain('connecting');
  });

  it('does nothing when the connection list is not mounted', () => {
    document.getElementById('connection-list').remove();

    expect(() => renderConnectionList()).not.toThrow();
  });

  it('renders empty and no-match states', () => {
    state.prefs.connections = [];
    renderConnectionList();
    expect(document.getElementById('connection-list').textContent).toContain(
      'No saved connections yet'
    );

    state.prefs.connections = [{ id: 'one', label: 'Primary', endpoint: 'one.example:443' }];
    state.search = 'missing';
    renderConnectionList();
    expect(document.getElementById('connection-list').textContent).toContain('No matches.');
  });

  it('selects a connection, persists prefs, and rerenders', async () => {
    const applyHeroForSelection = vi.fn();
    wireSidebarSearch({ openModal: vi.fn(), applyHeroForSelection });

    await selectConnection('two');

    expect(state.prefs.active_id).toBe('two');
    expect(savePrefs).toHaveBeenCalledOnce();
    expect(applyHeroForSelection).toHaveBeenCalledOnce();
  });

  it('wires search and add connection interactions', () => {
    const openModal = vi.fn();
    wireSidebarSearch({ openModal, applyHeroForSelection: vi.fn() });

    const search = document.getElementById('search');
    search.value = 'backup';
    search.dispatchEvent(new Event('input'));
    document.getElementById('add-conn-btn').click();

    expect(state.search).toBe('backup');
    expect(document.querySelectorAll('.conn-row')).toHaveLength(1);
    expect(openModal).toHaveBeenCalledWith(null);
  });

  it('opens editor on double click and context menu', () => {
    const openModal = vi.fn();
    wireSidebarSearch({ openModal, applyHeroForSelection: vi.fn() });
    renderConnectionList();

    const row = document.querySelector('.conn-row');
    row.dispatchEvent(new MouseEvent('dblclick', { bubbles: true }));
    row.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true }));

    expect(openModal).toHaveBeenCalledWith('one');
    expect(openModal).toHaveBeenCalledTimes(2);
  });
});
