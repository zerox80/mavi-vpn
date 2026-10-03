import { beforeEach, expect, it, vi } from 'vitest';
import { state } from '../state.js';
import { connect, applyStatus, disconnect, toggleConnection } from '../vpn.js';
import { invoke } from '../api.js';

vi.mock('../api.js', () => ({ invoke: vi.fn() }));
vi.mock('../connections.js', () => ({ renderConnectionList: vi.fn() }));
vi.mock('../toast.js', () => ({
  showToast: vi.fn(), hideToast: vi.fn(), showServiceOfflineHint: vi.fn(),
  daemonHintText: vi.fn(() => 'offline'),
}));

beforeEach(() => {
  vi.resetAllMocks();
  document.body.innerHTML = ['connect-btn', 'ip-readout', 'hero-title',
    'hero-subtitle', 'hero-node-id', 'hero-lat', 'title-state-label',
    'hero-status', 'core-label', 'net-node', 'net-endpoint', 'net-ip',
    'net-service', 'net-protocol', 'net-transport']
    .map(id => `<div id="${id}"></div>`).join('');
  Object.assign(state, { hero: 'off', running: false, serviceAvailable: true,
    vpnState: 'Stopped', disconnecting: false, connectAttempt: 0,
    pendingConnect: false, disconnectPending: false, connectRequestId: null });
  state.prefs.active_id = 'kc';
  state.prefs.connections = [{ id: 'kc', label: 'Keycloak', endpoint: 'vpn:443',
    kc_auth: true, kc_url: 'https://auth.example.com', cert_pin: 'pin' }];
});

it('keeps a pending browser login cancellable through service status updates', async () => {
  let finishLogin;
  invoke.mockImplementation(async command => {
    if (command === 'vpn_connect') return new Promise(resolve => { finishLogin = resolve; });
    if (command === 'vpn_status') return { service_available: true, state: 'Stopped' };
  });
  const pending = connect();
  await vi.waitFor(() => expect(finishLogin).toBeTypeOf('function'));
  for (const status of [
    { service_available: true, state: 'Stopped' },
    { service_available: true, state: 'Failed', last_error: 'previous failure' },
    { service_available: false, state: 'Stopped' },
  ]) {
    applyStatus(status);
    expect(state.hero).toBe('connecting');
    expect(document.getElementById('connect-btn').textContent).toBe('CANCEL');
    expect(document.getElementById('connect-btn').disabled).toBe(false);
  }
  await connect();
  expect(invoke.mock.calls.filter(([command]) => command === 'vpn_connect')).toHaveLength(1);
  const requestId = state.connectRequestId;
  await toggleConnection();
  expect(invoke).toHaveBeenCalledWith('vpn_disconnect', { requestId });
  finishLogin('Connected');
  await pending;
  expect(state.hero).toBe('off');
});

it('does not disconnect a newer session when an older start reply arrives late', async () => {
  let finishOldStart;
  let starts = 0;
  let running = false;
  invoke.mockImplementation(async command => {
    if (command === 'vpn_connect') {
      starts++;
      running = true;
      if (starts === 1) return new Promise(resolve => { finishOldStart = resolve; });
      return 'Connected';
    }
    if (command === 'vpn_disconnect') { running = false; return 'Disconnected'; }
    if (command === 'vpn_status') return { service_available: true, running,
      state: running ? 'Connected' : 'Stopped' };
  });
  const oldStart = connect();
  await vi.waitFor(() => expect(finishOldStart).toBeTypeOf('function'));
  await disconnect();
  await connect();
  expect(running).toBe(true);
  finishOldStart('Connected');
  await oldStart;
  expect(running).toBe(true);
  expect(state.hero).toBe('on');
  expect(invoke.mock.calls.filter(([command]) => command === 'vpn_disconnect')).toHaveLength(1);
});

it('does not allow another connect while a stop command is still pending', async () => {
  let finishStop;
  invoke.mockImplementation(async command => {
    if (command === 'vpn_disconnect') return new Promise(resolve => { finishStop = resolve; });
    if (command === 'vpn_status') return { service_available: true, state: 'Stopped' };
  });
  const stopping = disconnect();
  await vi.waitFor(() => expect(finishStop).toBeTypeOf('function'));
  applyStatus({ service_available: true, state: 'Stopped' });
  expect(state.hero).toBe('disconnecting');
  await toggleConnection();
  await connect();
  expect(invoke).not.toHaveBeenCalledWith('vpn_connect', expect.anything());
  finishStop('Disconnected');
  await stopping;
  expect(state.hero).toBe('off');
});

it('cancelling while config is saving prevents submission of the start', async () => {
  let finishSave;
  invoke.mockImplementation(async command => {
    if (command === 'save_config') return new Promise(resolve => { finishSave = resolve; });
    if (command === 'vpn_status') return { service_available: true, state: 'Stopped' };
  });
  const pending = connect();
  await vi.waitFor(() => expect(finishSave).toBeTypeOf('function'));
  await disconnect();
  finishSave();
  await pending;
  expect(invoke).not.toHaveBeenCalledWith('vpn_connect', expect.anything());
});
