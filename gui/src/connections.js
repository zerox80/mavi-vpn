import { state, $ } from './state.js';
import { savePrefs } from './theme.js';
import { escapeHtml, initials } from './utils.js';

let _openModal = null;
let _applyHero = null;

export function wireSidebarSearch({ openModal, applyHeroForSelection }) {
  _openModal = openModal;
  _applyHero = applyHeroForSelection;

  $('search').addEventListener('input', (e) => {
    state.search = e.target.value.trim().toLowerCase();
    renderConnectionList();
  });
  $('add-conn-btn').addEventListener('click', () => _openModal(null));
}

export function renderConnectionList() {
  const list = $('connection-list');
  if (!list) return;
  const q = state.search;
  const filtered = state.prefs.connections.filter(
    (c) => !q || c.label.toLowerCase().includes(q) || c.endpoint.toLowerCase().includes(q)
  );

  if (state.prefs.connections.length === 0) {
    list.innerHTML =
      '<div class="conn-empty">No saved connections yet.<br/>Tap + ADD CONNECTION below.</div>';
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
    row.className =
      'conn-row' +
      (isSelected ? ' selected' : '') +
      (isActive ? ' active' : '') +
      (isConnecting ? ' connecting' : '');
    row.addEventListener('click', () => selectConnection(c.id));
    row.addEventListener('dblclick', () => _openModal(c.id));
    row.innerHTML = `
      <div class="badge">${escapeHtml(initials(c.label))}</div>
      <div class="main">
        <div class="label">${escapeHtml(c.label)}</div>
        <div class="endpoint">${escapeHtml(c.endpoint)}</div>
      </div>
      <div class="load"><span></span></div>
    `;
    // Secondary: edit on right-click
    row.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      _openModal(c.id);
    });
    list.appendChild(row);
  }
}

export async function selectConnection(id) {
  state.prefs.active_id = id;
  await savePrefs();
  renderConnectionList();
  if (_applyHero) _applyHero();
}

export function generateConnectionId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

export function validMtu(value) {
  const mtu = Number(value);
  return Number.isInteger(mtu) && mtu >= 1280 && mtu <= 1360 ? mtu : null;
}

export function connectionFromLegacyConfig(config, existing = null) {
  const kcAuth = !!config.kc_auth;
  return {
    id: existing?.id || generateConnectionId(),
    label: existing?.label || config.endpoint,
    endpoint: config.endpoint,
    token: kcAuth ? null : config.token || null,
    cert_pin: config.cert_pin || '',
    ech_config: config.ech_config || null,
    censorship_resistant: !!config.censorship_resistant,
    http3_framing: !!config.http3_framing,
    kc_auth: kcAuth || null,
    kc_url: kcAuth ? config.kc_url || null : null,
    kc_realm: kcAuth ? config.kc_realm || null : null,
    kc_client_id: kcAuth ? config.kc_client_id || null : null,
    vpn_mtu: validMtu(config.vpn_mtu),
  };
}

export async function migrateLegacyConfig(config) {
  if (state.prefs.legacy_config_migrated) return;

  state.prefs.legacy_config_migrated = true;
  if (config?.endpoint) {
    const idx = state.prefs.connections.findIndex((c) => c.endpoint === config.endpoint);
    if (idx >= 0) {
      state.prefs.connections[idx] = connectionFromLegacyConfig(
        config,
        state.prefs.connections[idx]
      );
      if (!state.prefs.active_id) state.prefs.active_id = state.prefs.connections[idx].id;
    } else {
      const conn = connectionFromLegacyConfig(config);
      state.prefs.connections.push(conn);
      state.prefs.active_id = conn.id;
    }
  }

  await savePrefs();
}
