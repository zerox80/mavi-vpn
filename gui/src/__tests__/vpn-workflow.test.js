import { beforeEach, describe, expect, it, vi } from 'vitest';
import { state } from '../state.js';
import {
  applyHeroForSelection,
  connect,
  disconnect,
  refreshStatus,
  setHero,
  toggleConnection,
  wireHero,
} from '../vpn.js';
import { invoke } from '../api.js';
import { showToast } from '../toast.js';

vi.mock('../api.js', () => ({
  invoke: vi.fn(),
}));

vi.mock('../toast.js', () => ({
  showToast: vi.fn(),
  hideToast: vi.fn(),
  showServiceOfflineHint: vi.fn(),
  daemonHintText: vi.fn(() => 'offline'),
}));

vi.mock('../connections.js', () => ({
  renderConnectionList: vi.fn(),
}));

function setupVpnDom() {
  document.body.innerHTML = `
    <button id="connect-btn"></button>
    <div id="ip-readout"></div>
    <div id="hero-title"></div>
    <div id="hero-subtitle"></div>
    <div id="hero-node-id"></div>
    <div id="hero-lat"></div>
    <div id="title-state-label"></div>
    <div id="hero-status"></div>
    <div id="core-label"></div>
    <div id="net-node"></div>
    <div id="net-endpoint"></div>
    <div id="net-ip"></div>
    <div id="net-service"></div>
    <div id="toast"></div>
  `;
}

describe('vpn workflows', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setupVpnDom();
    state.hero = 'off';
    state.disconnecting = false;
    state.running = false;
    state.serviceAvailable = true;
    state.sessionStart = null;
    state.prefs.active_id = 'conn-1';
    state.prefs.connections = [
      {
        id: 'conn-1',
        label: 'Primary',
        endpoint: 'vpn.example.com:443',
        token: 'secret',
        cert_pin: 'pin',
      },
    ];
  });

  it('connect saves config before starting the VPN', async () => {
    invoke
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce('Connected')
      .mockResolvedValueOnce({ service_available: true, running: false, state: 'Starting' });

    await connect();

    expect(invoke).toHaveBeenNthCalledWith(
      1,
      'save_config',
      expect.objectContaining({
        config: expect.objectContaining({
          endpoint: 'vpn.example.com:443',
          token: 'secret',
          cert_pin: 'pin',
        }),
      })
    );
    expect(invoke).toHaveBeenNthCalledWith(2, 'vpn_connect', expect.any(Object));
    expect(state.hero).toBe('connecting');
  });

  it('connect refuses missing active connection', async () => {
    state.prefs.active_id = 'missing';
    state.prefs.connections = [];

    await connect();

    expect(invoke).not.toHaveBeenCalled();
    expect(showToast).toHaveBeenCalledWith('Select a saved connection first, or add one.', 'error');
  });

  it('connect refuses a connection without token or Keycloak', async () => {
    state.prefs.connections[0].token = '';

    await connect();

    expect(invoke).not.toHaveBeenCalled();
    expect(showToast).toHaveBeenCalledWith(
      'Edit the saved connection and enter a pre-shared key, or enable Keycloak.',
      'error'
    );
  });

  it('connect reports invoke failures and returns to off', async () => {
    invoke.mockRejectedValueOnce(new Error('connection refused'));

    await connect();

    expect(showToast).toHaveBeenCalledWith('VPN daemon is not running.', 'error');
    expect(state.hero).toBe('off');
  });

  it('disconnect waits for stopped status and refreshes final status', async () => {
    state.hero = 'on';
    invoke
      .mockResolvedValueOnce('Disconnected')
      .mockResolvedValueOnce({ service_available: true, running: false, state: 'Stopped' })
      .mockResolvedValueOnce({ service_available: true, running: false, state: 'Stopped' });

    await disconnect();

    expect(invoke).toHaveBeenNthCalledWith(1, 'vpn_disconnect');
    expect(invoke).toHaveBeenNthCalledWith(2, 'vpn_status');
    expect(invoke).toHaveBeenNthCalledWith(3, 'vpn_status');
    expect(state.disconnecting).toBe(false);
    expect(state.hero).toBe('off');
  });

  it('disconnect reports errors and refreshes status', async () => {
    state.hero = 'on';
    invoke
      .mockRejectedValueOnce(new Error('disconnect failed'))
      .mockResolvedValueOnce({ service_available: true, running: true, state: 'Connected' });

    await disconnect();

    expect(showToast).toHaveBeenCalledWith('Error: disconnect failed', 'error');
    expect(invoke).toHaveBeenNthCalledWith(1, 'vpn_disconnect');
    expect(invoke).toHaveBeenNthCalledWith(2, 'vpn_status');
    expect(state.hero).toBe('on');
  });

  it('refreshStatus applies offline state when status invoke fails', async () => {
    invoke.mockRejectedValueOnce(new Error('offline'));

    await refreshStatus();

    expect(state.serviceAvailable).toBe(false);
    expect(document.getElementById('connect-btn').disabled).toBe(true);
  });

  it('toggleConnection ignores transitional states and routes on/off states', async () => {
    state.hero = 'connecting';
    await toggleConnection();
    expect(invoke).not.toHaveBeenCalled();

    state.vpnState = 'Reconnecting';
    invoke
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce({ service_available: true, running: false, state: 'Stopped' })
      .mockResolvedValueOnce({ service_available: true, running: false, state: 'Stopped' });
    await toggleConnection();
    expect(invoke).toHaveBeenCalledWith('vpn_disconnect');

    vi.clearAllMocks();
    state.vpnState = 'Stopped';
    state.hero = 'off';
    invoke
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce({ service_available: true, running: false, state: 'Starting' });
    await toggleConnection();
    // A manual connect reuses a stored refresh token when available, so it
    // does not force a fresh Keycloak login.
    expect(invoke).toHaveBeenCalledWith(
      'vpn_connect',
      expect.objectContaining({ forceLogin: false }),
    );

    vi.clearAllMocks();
    state.hero = 'on';
    invoke
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce({ service_available: true, running: false, state: 'Stopped' })
      .mockResolvedValueOnce({ service_available: true, running: false, state: 'Stopped' });
    await toggleConnection();
    expect(invoke).toHaveBeenCalledWith('vpn_disconnect');
  });

  it('wireHero connects the button to toggleConnection', () => {
    wireHero();
    invoke.mockResolvedValueOnce(undefined).mockResolvedValueOnce(undefined);

    document.getElementById('connect-btn').click();

    expect(invoke).toHaveBeenCalledWith('save_config', expect.any(Object));
  });

  it('setHero renders each hero state label', () => {
    setHero('connecting');
    expect(document.getElementById('connect-btn').textContent).toBe('CONNECTING...');
    expect(document.getElementById('core-label').textContent).toBe('HANDSHAKE');

    setHero('disconnecting');
    expect(document.getElementById('connect-btn').textContent).toBe('DISCONNECTING...');
    expect(document.getElementById('core-label').textContent).toBe('CLEANUP');

    setHero('on');
    expect(document.getElementById('connect-btn').textContent).toBe('DISCONNECT');
    expect(document.getElementById('title-state-label').textContent).toBe('ENCRYPTED');
  });

  it('selection state disables connect with no active connection', () => {
    state.prefs.active_id = null;
    state.prefs.connections = [];
    state.hero = 'off';

    applyHeroForSelection();

    expect(document.getElementById('connect-btn').disabled).toBe(true);
    expect(document.getElementById('hero-title').textContent).toBe('No node selected');
  });
});
