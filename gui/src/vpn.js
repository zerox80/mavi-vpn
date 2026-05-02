import { state, $ } from './state.js';
import { invoke } from './api.js';
import { showToast, hideToast, showServiceOfflineHint, daemonHintText } from './toast.js';
import { renderConnectionList } from './connections.js';
import { heroFromVpnStatus, toConfig, friendlyError } from './utils.js';

export function wireHero() {
  $('connect-btn').addEventListener('click', () => toggleConnection());
}

export function activeConn() {
  return state.prefs.connections.find((c) => c.id === state.prefs.active_id) || null;
}

export async function toggleConnection() {
  if (state.hero === 'connecting' || state.hero === 'disconnecting') return;
  if (state.hero === 'on') return disconnect();
  return connect();
}

export async function connect() {
  state.disconnecting = false;
  const conn = activeConn();
  if (!conn) {
    showToast('Select a saved connection first, or add one.', 'error');
    return;
  }

  const config = toConfig(conn);
  if (!config.token && !config.kc_auth) {
    showToast('Edit the saved connection and enter a pre-shared key, or enable Keycloak.', 'error');
    return;
  }

  setHero('connecting');
  try {
    await invoke('save_config', { config });
    await invoke('vpn_connect', { config });
  } catch (e) {
    showToast(friendlyError(e), 'error');
    setHero('off');
  }
}

export async function disconnect() {
  state.disconnecting = true;
  state.sessionStart = null;
  setHero('disconnecting');
  try {
    await invoke('vpn_disconnect');
    await waitForStopped();
  } catch (e) {
    state.disconnecting = false;
    showToast(friendlyError(e), 'error');
  } finally {
    await refreshStatus();
  }
}

async function waitForStopped() {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const status = await invoke('vpn_status');
    applyStatus(status);
    if (!status.service_available || status.state === 'Stopped' || status.state === 'Failed') {
      return;
    }
    await new Promise((r) => setTimeout(r, 250));
  }
}

export async function refreshStatus() {
  try {
    const s = await invoke('vpn_status');
    applyStatus(s);
  } catch {
    applyStatus({ running: false, endpoint: null, service_available: false });
  }
}

export function applyStatus(status) {
  state.serviceAvailable = !!status.service_available;
  state.running = !!status.running;
  state.activeEndpoint = status.endpoint || null;
  state.vpnState = status.state || (state.running ? 'Connected' : 'Stopped');
  state.lastError = status.last_error || null;

  const btn = $('connect-btn');
  if (!btn) return;

  if (!state.serviceAvailable) {
    state.disconnecting = false;
    setHero('off');
    btn.disabled = true;
    btn.title = daemonHintText();
    showServiceOfflineHint();
    updateNetworkPanel();
    return;
  }

  const nextHero = heroFromVpnStatus(status, state.hero, state.disconnecting);

  if (state.vpnState === 'Failed') {
    state.disconnecting = false;
    setHero('off');
    state.sessionStart = null;
    btn.disabled = !activeConn();
    btn.title = activeConn() ? '' : 'Select or add a saved connection first';
    if (state.lastError) showToast(friendlyError(state.lastError), 'error');
  } else if (nextHero === 'on') {
    state.disconnecting = false;
    // First transition into 'on' stamps sessionStart
    if (state.hero !== 'on') state.sessionStart = Date.now();
    setHero('on');
    btn.disabled = false;
    btn.title = '';
    hideToast('hint');
  } else if (nextHero === 'disconnecting') {
    setHero('disconnecting');
    btn.disabled = true;
    btn.title = 'Disconnecting...';
    hideToast('hint');
  } else if (nextHero === 'connecting') {
    setHero('connecting');
    btn.title = '';
  } else {
    state.disconnecting = false;
    setHero('off');
    state.sessionStart = null;
    btn.disabled = !activeConn();
    btn.title = activeConn() ? '' : 'Select or add a saved connection first';
    hideToast('hint');
  }
  if (status.assigned_ip) {
    $('ip-readout').textContent = status.assigned_ip;
  }
  updateNetworkPanel();
}

export function setHero(s) {
  state.hero = s;
  document.documentElement.setAttribute('data-state', s);

  const btn = $('connect-btn');
  if (!btn) return;

  btn.textContent =
    s === 'on'
      ? 'DISCONNECT'
      : s === 'connecting'
        ? 'CONNECTING...'
        : s === 'disconnecting'
          ? 'DISCONNECTING...'
          : 'CONNECT';
  if (s === 'connecting' || s === 'disconnecting') btn.disabled = true;

  const labels = {
    off: 'NOT CONNECTED',
    connecting: 'ESTABLISHING TUNNEL',
    disconnecting: 'DISCONNECTING',
    on: 'ENCRYPTED',
  };
  $('title-state-label').textContent = labels[s];

  const heroStatus = {
    off: '// NOT CONNECTED',
    connecting: '// ESTABLISHING TUNNEL',
    disconnecting: '// DISCONNECTING',
    on: '// ENCRYPTED',
  };
  $('hero-status').textContent = heroStatus[s];

  $('core-label').textContent =
    s === 'connecting' ? 'HANDSHAKE' : s === 'disconnecting' ? 'CLEANUP' : 'TUNNEL';

  applyHeroForSelection();
  renderConnectionList();
}

export function applyHeroForSelection() {
  const conn = activeConn();
  if (conn) {
    $('hero-title').textContent = conn.label;
    $('hero-subtitle').textContent =
      state.hero === 'on'
        ? 'Your traffic is encrypted through this node'
        : state.hero === 'connecting'
          ? 'Establishing an encrypted tunnel...'
          : state.hero === 'disconnecting'
            ? 'Closing tunnel and cleaning up routes'
            : 'Tunnel your connection through this node';
    $('hero-node-id').textContent = conn.id.slice(0, 8).toUpperCase();
    $('hero-lat').textContent = conn.endpoint.toUpperCase();
  } else {
    $('hero-title').textContent = 'No node selected';
    $('hero-subtitle').textContent = 'Add a saved connection to begin';
    $('hero-node-id').textContent = '—';
    $('hero-lat').textContent = 'NO SELECTION';
  }
  const btn = $('connect-btn');
  if (btn) {
    btn.disabled =
      state.hero === 'connecting' ||
      state.hero === 'disconnecting' ||
      (!state.running && !state.serviceAvailable) ||
      (state.hero === 'off' && !conn);
  }
}

export function updateNetworkPanel() {
  const conn = activeConn();
  $('net-node').textContent = conn ? conn.label : '—';
  $('net-endpoint').textContent = state.activeEndpoint || conn?.endpoint || '—';
  $('net-ip').textContent = $('ip-readout').textContent;
  $('net-service').textContent = state.serviceAvailable ? 'ONLINE' : 'OFFLINE';
}
