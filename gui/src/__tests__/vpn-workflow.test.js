import { beforeEach, describe, expect, it, vi } from 'vitest';
import { state } from '../state.js';
import { connect, disconnect, applyHeroForSelection } from '../vpn.js';
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
    invoke.mockResolvedValueOnce(undefined).mockResolvedValueOnce('Connected');

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

  it('selection state disables connect with no active connection', () => {
    state.prefs.active_id = null;
    state.prefs.connections = [];
    state.hero = 'off';

    applyHeroForSelection();

    expect(document.getElementById('connect-btn').disabled).toBe(true);
    expect(document.getElementById('hero-title').textContent).toBe('No node selected');
  });
});
