// Mavi VPN — frontend controller
// Vanilla JS port of the design in ~/Downloads/Mavi-VPN/, wired to the real
// Tauri backend. IPC Config (sensitive, shared with daemon) is persisted via
// save_config/load_config; UI state (theme, saved connections) via save_prefs.

import { escapeHtml, initials, bandwidthWalk, friendlyError, toConfig } from './utils.js';

// ============================================================================
// Tauri API bootstrap — the API is injected by withGlobalTauri, but can lag
// behind DOMContentLoaded on some builds.
// ============================================================================

let _invoke = null;
let _listen = null;
const invoke = (cmd, args) => {
  if (!_invoke) throw new Error('Tauri invoke not ready');
  return _invoke(cmd, args);
};
const listen = (event, handler) => {
  if (!_listen) throw new Error('Tauri listen not ready');
  return _listen(event, handler);
};

// ============================================================================
// App state
// ============================================================================

const state = {
  // UI state machine: 'off' | 'connecting' | 'on'
  hero: 'off',
  // From vpn_status
  serviceAvailable: false,
  running: false,
  activeEndpoint: null,
  vpnState: 'Stopped',
  lastError: null,
  // Session wall clock
  sessionStart: null,
  // Saved UI prefs
  prefs: { theme: 'light', accent: '#2B44FF', connections: [], active_id: null },
  // Search filter
  search: '',
};

const $ = (id) => document.getElementById(id);

// ============================================================================
// Init
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  // Wait briefly for window.__TAURI__ to populate
  let attempts = 0;
  while ((!window.__TAURI__ || !window.__TAURI__.core) && attempts < 20) {
    await new Promise(r => setTimeout(r, 50));
    attempts++;
  }
  if (window.__TAURI__ && window.__TAURI__.core) {
    _invoke = window.__TAURI__.core.invoke;
    _listen = window.__TAURI__.event.listen;
  } else {
    console.error('Tauri API not available — running in browser preview');
  }

  wireTabs();
  wireSidebarSearch();
  wireSettingsForm();
  wireModal();
  wireHero();
  wireThemeToggle();
  wireShortcuts();

  // Load UI prefs (connections, theme) — tolerate missing backend
  try {
    const prefs = await invoke('load_prefs');
    if (prefs) state.prefs = prefs;
  } catch (e) { console.warn('load_prefs failed:', e); }

  applyTheme(state.prefs.theme);
  renderConnectionList();

  // Hydrate the SETTINGS form from the shared IPC Config (sensitive token lives here)
  try {
    const config = await invoke('load_config');
    if (config) fillSettings(config);
  } catch (e) { /* no saved config yet */ }

  startCoreAnimation();
  renderSparkline();
  startStatsAnimation();
  startSessionClock();

  await refreshStatus();

  try {
    await listen('vpn-status-update', (e) => applyStatus(e.payload));
    await listen('tray-toggle', () => toggleConnection());
  } catch (e) {
    console.warn('event wiring failed:', e);
  }
});

// ============================================================================
// Theme
// ============================================================================

function wireThemeToggle() {
  $('theme-toggle').addEventListener('click', async () => {
    const next = state.prefs.theme === 'light' ? 'dark' : 'light';
    state.prefs.theme = next;
    applyTheme(next);
    await savePrefs();
  });
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const icon = $('theme-icon');
  if (theme === 'dark') {
    icon.innerHTML = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />';
  } else {
    icon.innerHTML =
      '<circle cx="12" cy="12" r="4" />' +
      '<path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />';
  }
}

async function savePrefs() {
  try { await invoke('save_prefs', { prefs: state.prefs }); }
  catch (e) { console.warn('save_prefs failed:', e); }
}

// ============================================================================
// Tabs
// ============================================================================

function wireTabs() {
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      const name = btn.dataset.tab;
      document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t === btn));
      document.querySelectorAll('.tab-panel').forEach(p =>
        p.classList.toggle('active', p.dataset.panel === name));
    });
  });
}

// ============================================================================
// Saved connections — list, search, CRUD via modal
// ============================================================================

function wireSidebarSearch() {
  $('search').addEventListener('input', (e) => {
    state.search = e.target.value.trim().toLowerCase();
    renderConnectionList();
  });
  $('add-conn-btn').addEventListener('click', () => openModal(null));
}

function renderConnectionList() {
  const list = $('connection-list');
  const q = state.search;
  const filtered = state.prefs.connections.filter(c =>
    !q || c.label.toLowerCase().includes(q) || c.endpoint.toLowerCase().includes(q));

  if (state.prefs.connections.length === 0) {
    list.innerHTML = '<div class="conn-empty">No saved connections yet.<br/>Tap + ADD CONNECTION below.</div>';
    return;
  }

  list.innerHTML = '';
  const header = document.createElement('div');
  header.className = 'group-header';
  header.textContent = 'SAVED';
  list.appendChild(header);

  if (filtered.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'conn-empty';
    empty.textContent = 'No matches.';
    list.appendChild(empty);
    return;
  }

  for (const c of filtered) {
    const row = document.createElement('div');
    const isSelected = c.id === state.prefs.active_id;
    const isActive = isSelected && state.hero === 'on';
    const isConnecting = isSelected && state.hero === 'connecting';
    row.className = 'conn-row' +
      (isSelected ? ' selected' : '') +
      (isActive ? ' active' : '') +
      (isConnecting ? ' connecting' : '');
    row.addEventListener('click', () => selectConnection(c.id));
    row.addEventListener('dblclick', () => openModal(c.id));
    row.innerHTML = `
      <div class="badge">${escapeHtml(initials(c.label))}</div>
      <div class="main">
        <div class="label">${escapeHtml(c.label)}</div>
        <div class="endpoint">${escapeHtml(c.endpoint)}</div>
      </div>
      <div class="load"><span></span></div>
    `;
    // Secondary: edit on right-click
    row.addEventListener('contextmenu', (e) => { e.preventDefault(); openModal(c.id); });
    list.appendChild(row);
  }
}

async function selectConnection(id) {
  state.prefs.active_id = id;
  await savePrefs();
  const conn = state.prefs.connections.find(c => c.id === id);
  if (conn) {
    // Sync non-sensitive fields from the saved connection into SETTINGS,
    // but leave token untouched — tokens persist in 0o600 config.json
    $('endpoint').value = conn.endpoint;
    $('cert_pin').value = conn.cert_pin;
    $('ech_config').value = conn.ech_config || '';
    $('cr_mode').checked = !!conn.censorship_resistant;
    $('h3_framing').checked = !!conn.http3_framing;
    $('kc_auth').checked = !!conn.kc_auth;
    $('kc_url').value = conn.kc_url || '';
    $('kc_realm').value = conn.kc_realm || '';
    $('kc_client_id').value = conn.kc_client_id || '';
    $('vpn_mtu').value = conn.vpn_mtu || '';
    $('kc-fields').classList.toggle('hidden', !conn.kc_auth);
    $('token-field').classList.toggle('hidden', !!conn.kc_auth);
  }
  renderConnectionList();
  applyHeroForSelection();
}

// ============================================================================
// Modal (add/edit connection)
// ============================================================================

let _editingId = null;

function wireModal() {
  $('m_kc_auth').addEventListener('change', () => {
    $('m-kc-fields').classList.toggle('hidden', !$('m_kc_auth').checked);
  });
  $('modal-cancel').addEventListener('click', closeModal);
  $('modal-backdrop').addEventListener('click', (e) => {
    if (e.target.id === 'modal-backdrop') closeModal();
  });
  $('modal-save').addEventListener('click', saveModal);
  $('modal-delete').addEventListener('click', deleteModal);
}

function openModal(id) {
  _editingId = id;
  const existing = id ? state.prefs.connections.find(c => c.id === id) : null;
  $('modal-title').textContent = existing ? 'Edit Connection' : 'New Connection';
  $('m_label').value = existing?.label ?? '';
  $('m_endpoint').value = existing?.endpoint ?? '';
  $('m_cert_pin').value = existing?.cert_pin ?? '';
  $('m_ech_config').value = existing?.ech_config ?? '';
  $('m_cr_mode').checked = !!existing?.censorship_resistant;
  $('m_h3_framing').checked = !!existing?.http3_framing;
  $('m_kc_auth').checked = !!existing?.kc_auth;
  $('m_kc_url').value = existing?.kc_url ?? '';
  $('m_kc_realm').value = existing?.kc_realm ?? '';
  $('m_kc_client_id').value = existing?.kc_client_id ?? '';
  $('m_vpn_mtu').value = existing?.vpn_mtu ?? '';
  $('m-kc-fields').classList.toggle('hidden', !$('m_kc_auth').checked);
  $('modal-delete').classList.toggle('hidden', !existing);
  $('modal-backdrop').classList.add('visible');
  setTimeout(() => $('m_label').focus(), 0);
}

function closeModal() {
  $('modal-backdrop').classList.remove('visible');
  _editingId = null;
}

async function saveModal() {
  const label = $('m_label').value.trim();
  const endpoint = $('m_endpoint').value.trim();
  const cert_pin = $('m_cert_pin').value.trim();
  if (!label) return showToast('Label is required.', 'error');
  if (!endpoint) return showToast('Endpoint is required.', 'error');
  if (!cert_pin) return showToast('Certificate PIN is required.', 'error');

  const kc_auth = $('m_kc_auth').checked || null;
  const mtuVal = parseInt($('m_vpn_mtu').value, 10);
  const conn = {
    id: _editingId || (Date.now().toString(36) + Math.random().toString(36).slice(2, 6)),
    label,
    endpoint,
    cert_pin,
    ech_config: $('m_ech_config').value.trim() || null,
    censorship_resistant: $('m_cr_mode').checked,
    http3_framing: $('m_h3_framing').checked,
    kc_auth,
    kc_url: kc_auth ? ($('m_kc_url').value.trim() || null) : null,
    kc_realm: kc_auth ? ($('m_kc_realm').value.trim() || null) : null,
    kc_client_id: kc_auth ? ($('m_kc_client_id').value.trim() || null) : null,
    vpn_mtu: (mtuVal >= 1280 && mtuVal <= 1360) ? mtuVal : null,
  };

  if (_editingId) {
    const idx = state.prefs.connections.findIndex(c => c.id === _editingId);
    if (idx >= 0) state.prefs.connections[idx] = conn;
  } else {
    state.prefs.connections.push(conn);
    state.prefs.active_id = conn.id;
  }
  await savePrefs();
  closeModal();
  renderConnectionList();
  applyHeroForSelection();
  showToast('Connection saved.', 'success');
}

async function deleteModal() {
  if (!_editingId) return;
  state.prefs.connections = state.prefs.connections.filter(c => c.id !== _editingId);
  if (state.prefs.active_id === _editingId) state.prefs.active_id = null;
  await savePrefs();
  closeModal();
  renderConnectionList();
  applyHeroForSelection();
}

// ============================================================================
// Settings form (IPC Config — shared with daemon)
// ============================================================================

function wireSettingsForm() {
  $('kc_auth').addEventListener('change', () => {
    $('kc-fields').classList.toggle('hidden', !$('kc_auth').checked);
    $('token-field').classList.toggle('hidden', $('kc_auth').checked);
  });
  $('save-btn').addEventListener('click', async () => {
    try {
      await invoke('save_config', { config: readSettings() });
      showToast('Credentials saved.', 'success');
    } catch (e) {
      showToast('Failed to save: ' + e, 'error');
    }
  });
}

function readSettings() {
  const kcAuth = $('kc_auth').checked;
  const mtuVal = parseInt($('vpn_mtu').value, 10);
  return {
    endpoint: $('endpoint').value.trim(),
    token: $('token').value.trim(),
    cert_pin: $('cert_pin').value.trim(),
    ech_config: $('ech_config').value.trim() || null,
    censorship_resistant: $('cr_mode').checked,
    http3_framing: $('h3_framing').checked,
    kc_auth: kcAuth || null,
    kc_url: kcAuth ? ($('kc_url').value.trim() || null) : null,
    kc_realm: kcAuth ? ($('kc_realm').value.trim() || null) : null,
    kc_client_id: kcAuth ? ($('kc_client_id').value.trim() || null) : null,
    vpn_mtu: (mtuVal >= 1280 && mtuVal <= 1360) ? mtuVal : null,
  };
}

function fillSettings(config) {
  $('endpoint').value = config.endpoint || '';
  $('token').value = config.token || '';
  $('cert_pin').value = config.cert_pin || '';
  $('ech_config').value = config.ech_config || '';
  $('cr_mode').checked = !!config.censorship_resistant;
  $('h3_framing').checked = !!config.http3_framing;
  $('vpn_mtu').value = config.vpn_mtu || '';
  $('kc_auth').checked = !!config.kc_auth;
  $('kc_url').value = config.kc_url || '';
  $('kc_realm').value = config.kc_realm || '';
  $('kc_client_id').value = config.kc_client_id || '';
  $('kc-fields').classList.toggle('hidden', !config.kc_auth);
  $('token-field').classList.toggle('hidden', !!config.kc_auth);
}

// ============================================================================
// Hero / state machine
// ============================================================================

function wireHero() {
  $('connect-btn').addEventListener('click', () => toggleConnection());
}

function activeConn() {
  return state.prefs.connections.find(c => c.id === state.prefs.active_id) || null;
}

async function toggleConnection() {
  if (state.hero === 'connecting') return;
  if (state.hero === 'on') return disconnect();
  return connect();
}

async function connect() {
  const conn = activeConn();
  if (!conn) {
    showToast('Select a saved connection first, or add one.', 'error');
    return;
  }
  // Merge saved connection with current form (token lives in the form, not in prefs)
  const form = readSettings();
  const config = {
    ...toConfig(conn, form.token),
    // If endpoint/cert_pin differ in the form, prefer the saved one — the form
    // reflects the active connection after selectConnection() copied it over.
    endpoint: conn.endpoint,
    cert_pin: conn.cert_pin,
  };

  if (!config.token && !config.kc_auth) {
    showToast('Pre-shared key required (Settings tab) or enable Keycloak.', 'error');
    return;
  }

  setHero('connecting');
  try {
    await invoke('save_config', { config });
    await invoke('vpn_connect', { config });
    // vpn-status-update event will push us to 'on'
  } catch (e) {
    showToast(friendlyError(e), 'error');
    setHero('off');
  }
}

async function disconnect() {
  try {
    await invoke('vpn_disconnect');
  } catch (e) {
    showToast(friendlyError(e), 'error');
  } finally {
    await refreshStatus();
  }
}

async function refreshStatus() {
  try {
    const s = await invoke('vpn_status');
    applyStatus(s);
  } catch {
    applyStatus({ running: false, endpoint: null, service_available: false });
  }
}

function applyStatus(status) {
  state.serviceAvailable = !!status.service_available;
  state.running = !!status.running;
  state.activeEndpoint = status.endpoint || null;
  state.vpnState = status.state || (state.running ? 'Connected' : 'Stopped');
  state.lastError = status.last_error || null;

  const btn = $('connect-btn');

  if (!state.serviceAvailable) {
    setHero('off');
    btn.disabled = true;
    btn.title = daemonHintText();
    showServiceOfflineHint();
    updateNetworkPanel();
    return;
  }

  if (state.vpnState === 'Failed') {
    setHero('off');
    state.sessionStart = null;
    btn.disabled = !activeConn();
    btn.title = activeConn() ? '' : 'Select or add a saved connection first';
    if (state.lastError) showToast(friendlyError(state.lastError), 'error');
  } else if (state.running || state.vpnState === 'Connected') {
    // First transition into 'on' → stamp sessionStart
    if (state.hero !== 'on') state.sessionStart = Date.now();
    setHero('on');
    btn.disabled = false;
    btn.title = '';
    hideToast('hint');
  } else if (state.vpnState === 'Starting') {
    setHero('connecting');
  } else if (state.hero !== 'connecting') {
    setHero('off');
    state.sessionStart = null;
    btn.disabled = !activeConn();
    btn.title = activeConn() ? '' : 'Select or add a saved connection first';
    hideToast('hint');
  }
  updateNetworkPanel();
}

function setHero(s) {
  state.hero = s;
  document.documentElement.setAttribute('data-state', s);

  const btn = $('connect-btn');
  btn.textContent = s === 'on' ? 'DISCONNECT' :
                    s === 'connecting' ? 'CONNECTING…' : 'CONNECT';
  if (s === 'connecting') btn.disabled = true;

  const labels = {
    off: 'NOT CONNECTED',
    connecting: 'ESTABLISHING TUNNEL',
    on: 'ENCRYPTED',
  };
  $('title-state-label').textContent = labels[s];

  const heroStatus = { off: '// NOT CONNECTED', connecting: '// ESTABLISHING TUNNEL', on: '// ENCRYPTED' };
  $('hero-status').textContent = heroStatus[s];

  $('core-label').textContent = s === 'connecting' ? 'HANDSHAKE' : 'TUNNEL';

  applyHeroForSelection();
  renderConnectionList();
}

function applyHeroForSelection() {
  const conn = activeConn();
  if (conn) {
    $('hero-title').textContent = conn.label;
    $('hero-subtitle').textContent =
      state.hero === 'on' ? 'Your traffic is encrypted through this node' :
      state.hero === 'connecting' ? 'Establishing an encrypted tunnel…' :
      'Tunnel your connection through this node';
    $('hero-node-id').textContent = conn.id.slice(0, 8).toUpperCase();
    $('hero-lat').textContent = conn.endpoint.toUpperCase();
  } else {
    $('hero-title').textContent = 'No node selected';
    $('hero-subtitle').textContent = 'Add a saved connection to begin';
    $('hero-node-id').textContent = '—';
    $('hero-lat').textContent = 'NO SELECTION';
  }
  $('connect-btn').disabled =
    state.hero === 'connecting' ||
    (!state.running && !state.serviceAvailable) ||
    (state.hero === 'off' && !conn);
}

function updateNetworkPanel() {
  const conn = activeConn();
  $('net-node').textContent = conn ? conn.label : '—';
  $('net-endpoint').textContent = state.activeEndpoint || conn?.endpoint || '—';
  $('net-ip').textContent = $('ip-readout').textContent;
  $('net-service').textContent = state.serviceAvailable ? 'ONLINE' : 'OFFLINE';
}

// ============================================================================
// Toast / hints
// ============================================================================

function showToast(msg, kind = 'error', ttl = 6000) {
  const box = $('toast');
  box.className = 'visible ' + kind;
  box.textContent = msg;
  box.dataset.kind = kind;
  if (ttl) {
    clearTimeout(showToast._t);
    showToast._t = setTimeout(() => {
      if (box.dataset.kind === kind) hideToast(kind);
    }, ttl);
  }
}

function hideToast(kind) {
  const box = $('toast');
  if (!kind || box.dataset.kind === kind) {
    box.className = '';
    box.textContent = '';
    box.dataset.kind = '';
  }
}

function showServiceOfflineHint() {
  const box = $('toast');
  // Don't stomp a hard error
  if (box.dataset.kind === 'error') return;
  const isWin = navigator.platform.toLowerCase().includes('win');
  box.className = 'visible hint';
  box.dataset.kind = 'hint';
  box.innerHTML = isWin
    ? 'VPN daemon offline. Run in Admin PowerShell: <code>net start MaviVPNService</code>'
    : 'VPN daemon offline. Run: <code>sudo systemctl start mavi-vpn</code>';
}

function daemonHintText() {
  return navigator.platform.toLowerCase().includes('win')
    ? 'Daemon offline. Run: net start MaviVPNService'
    : 'Daemon offline. Run: sudo systemctl start mavi-vpn';
}

// ============================================================================
// Shortcuts
// ============================================================================

function wireShortcuts() {
  document.addEventListener('keydown', (e) => {
    const mod = e.metaKey || e.ctrlKey;
    if (mod && (e.key === 'k' || e.key === 'K')) {
      e.preventDefault();
      // Ensure CONNECT tab is active then focus search
      document.querySelector('.tab[data-tab="connect"]').click();
      $('search').focus();
      $('search').select();
    }
    if (e.key === 'Escape') {
      if ($('modal-backdrop').classList.contains('visible')) closeModal();
    }
  });
}

// ============================================================================
// MaviCore SVG animation — port of mavi-core.jsx
// ============================================================================

function startCoreAnimation() {
  const svg = $('core');
  const size = 280;
  const R = size / 2;
  const accent = state.prefs.accent || '#2B44FF';
  const accentClean = accent.replace('#', '');

  const ns = 'http://www.w3.org/2000/svg';
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);

  // defs
  svg.innerHTML = `
    <defs>
      <radialGradient id="mcore-${accentClean}" cx="50%" cy="50%" r="50%">
        <stop offset="0%" stop-color="${accent}" stop-opacity="0.9" />
        <stop offset="60%" stop-color="${accent}" stop-opacity="0.35" />
        <stop offset="100%" stop-color="${accent}" stop-opacity="0" />
      </radialGradient>
      <radialGradient id="mhalo-${accentClean}" cx="50%" cy="50%" r="50%">
        <stop offset="0%" stop-color="${accent}" stop-opacity="0.25" />
        <stop offset="100%" stop-color="${accent}" stop-opacity="0" />
      </radialGradient>
      <filter id="mblur"><feGaussianBlur stdDeviation="8" /></filter>
    </defs>
  `;

  // Static-ish layers
  const halo = document.createElementNS(ns, 'circle');
  halo.setAttribute('cx', R); halo.setAttribute('cy', R);
  halo.setAttribute('fill', `url(#mhalo-${accentClean})`);
  svg.appendChild(halo);

  const ringFracs = [0.42, 0.56, 0.72, 0.88];
  const rings = ringFracs.map((f, i) => {
    const c = document.createElementNS(ns, 'circle');
    c.setAttribute('cx', R); c.setAttribute('cy', R);
    c.setAttribute('r', R * f);
    c.setAttribute('fill', 'none');
    c.setAttribute('stroke-width', i === 1 ? '1.5' : '1');
    if (i === 2) c.setAttribute('stroke-dasharray', '2 6');
    if (i === 3) c.setAttribute('stroke-dasharray', '1 5');
    svg.appendChild(c);
    return c;
  });

  // Radial ticks
  const tickGroup = document.createElementNS(ns, 'g');
  const ticks = [];
  for (let i = 0; i < 48; i++) {
    const ln = document.createElementNS(ns, 'line');
    ln.setAttribute('stroke', accent);
    ln.setAttribute('stroke-width', '1');
    tickGroup.appendChild(ln);
    ticks.push(ln);
  }
  svg.appendChild(tickGroup);

  // Core glow + solid + highlight
  const coreGlow = document.createElementNS(ns, 'circle');
  coreGlow.setAttribute('cx', R); coreGlow.setAttribute('cy', R);
  coreGlow.setAttribute('fill', `url(#mcore-${accentClean})`);
  coreGlow.setAttribute('filter', 'url(#mblur)');
  svg.appendChild(coreGlow);

  const coreSolid = document.createElementNS(ns, 'circle');
  coreSolid.setAttribute('cx', R); coreSolid.setAttribute('cy', R);
  svg.appendChild(coreSolid);

  const coreHighlight = document.createElementNS(ns, 'circle');
  coreHighlight.setAttribute('fill', 'white');
  svg.appendChild(coreHighlight);

  // Orbit dots
  const dots = [0, 1, 2, 3, 4].map((i) => {
    const c = document.createElementNS(ns, 'circle');
    c.setAttribute('r', i === 0 ? '4' : '2');
    c.setAttribute('fill', accent);
    svg.appendChild(c);
    return c;
  });

  const t0 = performance.now();
  function loop(now) {
    const t = (now - t0) / 1000;
    const breathe = 0.5 + 0.5 * Math.sin(t * 0.9);
    const pulse = 0.5 + 0.5 * Math.sin(t * 2.4);
    const off = state.hero === 'off';
    const connecting = state.hero === 'connecting';
    const rot = (t * (connecting ? 60 : 18)) % 360;

    const themeIsDark = state.prefs.theme === 'dark';
    const offRing = themeIsDark ? 'rgba(255,255,255,0.07)' : 'rgba(0,0,0,0.08)';
    const ringColor = off ? offRing : accent;

    rings.forEach((c, i) => {
      c.setAttribute('stroke', ringColor);
      const op = off
        ? 0.6
        : 0.18 + 0.12 * (1 - i / rings.length) + 0.08 * pulse;
      c.setAttribute('opacity', op.toFixed(3));
    });

    // ticks — hidden when off
    for (let i = 0; i < ticks.length; i++) {
      if (off) { ticks[i].setAttribute('opacity', '0'); continue; }
      const a = (i * 360 / 48) * Math.PI / 180;
      const r1 = R * 0.91;
      const r2 = R * (0.94 + 0.02 * Math.sin(t * 2 + i));
      ticks[i].setAttribute('x1', (R + Math.cos(a) * r1).toFixed(2));
      ticks[i].setAttribute('y1', (R + Math.sin(a) * r1).toFixed(2));
      ticks[i].setAttribute('x2', (R + Math.cos(a) * r2).toFixed(2));
      ticks[i].setAttribute('y2', (R + Math.sin(a) * r2).toFixed(2));
      const op = 0.15 + 0.35 * ((Math.sin(t * 1.5 + i * 0.4) + 1) / 2);
      ticks[i].setAttribute('opacity', op.toFixed(3));
    }

    // core
    const coreR = R * 0.28 + (off ? 0 : 6 * breathe);
    coreGlow.setAttribute('r', coreR + 20);
    coreGlow.setAttribute('opacity', off ? '0' : '1');
    const coreOffColor = getComputedStyle(document.documentElement).getPropertyValue('--core-off').trim() || '#E8E3D3';
    coreSolid.setAttribute('r', coreR);
    coreSolid.setAttribute('fill', off ? coreOffColor : accent);

    if (off) {
      coreHighlight.setAttribute('opacity', '0');
    } else {
      const hr = coreR * 0.5;
      coreHighlight.setAttribute('cx', R - coreR * 0.3);
      coreHighlight.setAttribute('cy', R - coreR * 0.3);
      coreHighlight.setAttribute('r', hr);
      coreHighlight.setAttribute('opacity', (0.18 + 0.1 * breathe).toFixed(3));
    }

    // orbit dots
    const orbitR = R * 0.56;
    dots.forEach((d, i) => {
      if (off) { d.setAttribute('opacity', '0'); return; }
      const a = (rot + i * 72) * Math.PI / 180;
      d.setAttribute('cx', (R + Math.cos(a) * orbitR).toFixed(2));
      d.setAttribute('cy', (R + Math.sin(a) * orbitR).toFixed(2));
      const op = i === 0 ? 1 : 0.4 + 0.3 * Math.sin(t * 2 + i);
      d.setAttribute('opacity', op.toFixed(3));
    });

    requestAnimationFrame(loop);
  }
  requestAnimationFrame(loop);
}

// ============================================================================
// Sparkline + deterministic bandwidth walk (matches sample's MAVI.band)
// ============================================================================

function renderSparkline() {
  const svg = $('sparkline');
  const W = 200, H = 28;
  const values = bandwidthWalk(60);
  const max = Math.max(...values);
  const points = values.map((v, i) => {
    const x = (i / (values.length - 1)) * W;
    const y = H - (v / max) * H * 0.9 - 2;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  svg.innerHTML = `
    <polyline id="spark-line" points="${points}" fill="none" stroke-width="1.2" />
    <polygon  id="spark-fill" points="0,${H} ${points} ${W},${H}" />
  `;
  updateSparklineColors();
}

function updateSparklineColors() {
  const line = document.getElementById('spark-line');
  const fill = document.getElementById('spark-fill');
  if (!line || !fill) return;
  const style = getComputedStyle(document.documentElement);
  const off = state.hero !== 'on';
  const accent = state.prefs.accent || style.getPropertyValue('--accent').trim() || '#2B44FF';
  const lineColor = off ? style.getPropertyValue('--line').trim() : accent;
  line.setAttribute('stroke', lineColor);
  fill.setAttribute('fill', accent);
  fill.setAttribute('opacity', off ? '0' : '0.08');
}

// Re-tint sparkline when state changes — hook into setHero via MutationObserver
new MutationObserver(updateSparklineColors)
  .observe(document.documentElement, { attributes: true, attributeFilter: ['data-state', 'data-theme'] });

// ============================================================================
// Stats ticker (deterministic fake, matches sample — no real telemetry yet)
// ============================================================================

function startStatsAnimation() {
  let tick = 0;
  setInterval(() => {
    if (state.hero === 'on') {
      tick++;
      $('stat-down').textContent = (42 + (tick % 7) * 3.1).toFixed(1);
      $('stat-up').textContent = (11 + (tick % 5) * 1.4).toFixed(1);
      $('ip-readout').textContent = `185.24.${80 + (tick % 30)}.${11 + (tick % 200)}`;
    } else {
      $('stat-down').textContent = '0.0';
      $('stat-up').textContent = '0.0';
      $('ip-readout').textContent = '—';
    }
    $('net-ip').textContent = $('ip-readout').textContent;
  }, 800);
}

// ============================================================================
// Session clock
// ============================================================================

function startSessionClock() {
  setInterval(() => {
    let s = '00:00:00';
    if (state.sessionStart && state.hero === 'on') {
      const diff = Math.floor((Date.now() - state.sessionStart) / 1000);
      const h = String(Math.floor(diff / 3600)).padStart(2, '0');
      const m = String(Math.floor((diff % 3600) / 60)).padStart(2, '0');
      const sec = String(diff % 60).padStart(2, '0');
      s = `${h}:${m}:${sec}`;
    }
    $('hero-session').textContent = s;
    $('net-session').textContent = s;
  }, 1000);
}
