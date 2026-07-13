import { state, $ } from './state.js';
import { savePrefs } from './theme.js';
import { renderConnectionList, generateConnectionId } from './connections.js';
import { showToast } from './toast.js';
import { parseOptionalMtu } from './utils.js';
import { invoke } from './api.js';

let _applyHero = null;
let _editingId = null;
let _splitCatalog = [];
let _splitSupported = false;
let _selectedAppIds = new Set();

export async function initializeSplitTunnel() {
  try {
    const catalog = await invoke('split_tunnel_catalog');
    _splitSupported = !!catalog?.supported;
    _splitCatalog = Array.isArray(catalog?.apps) ? catalog.apps : [];
  } catch (error) {
    console.warn('split tunnel app discovery failed:', error);
    _splitSupported = false;
    _splitCatalog = [];
  }
  $('m-split-section')?.classList.toggle('hidden', !_splitSupported);
  renderSplitTunnelApps();
}

// Light format checks so a typo is caught immediately in the form instead of
// surfacing later as an opaque connection failure. Not a security boundary -
// the service validates these for real before using them.
function isValidEndpoint(value) {
  return /^.+:\d{1,5}$/.test(value);
}

function isValidCertPin(value) {
  return value
    .split(',')
    .map((p) => p.trim())
    .every((p) => /^[0-9a-fA-F]{64}$/.test(p));
}

function isValidKcUrl(value) {
  if (!value) return true;
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

export function wireModal({ applyHeroForSelection }) {
  _applyHero = applyHeroForSelection;

  $('m_kc_auth').addEventListener('change', updateModalAuthFields);
  $('m_split_mode').addEventListener('change', updateSplitTunnelFields);
  $('m_split_search').addEventListener('input', renderSplitTunnelApps);
  $('modal-cancel').addEventListener('click', closeModal);
  $('modal-backdrop').addEventListener('click', (e) => {
    if (e.target.id === 'modal-backdrop') closeModal();
  });
  $('modal-save').addEventListener('click', saveModal);
  $('modal-delete').addEventListener('click', deleteModal);
}

export function updateModalAuthFields() {
  const kcAuth = $('m_kc_auth').checked;
  $('m-kc-fields').classList.toggle('hidden', !kcAuth);
  $('m-token-field').classList.toggle('hidden', kcAuth);
}

export function openModal(id) {
  _editingId = id;
  const existing = id ? state.prefs.connections.find((c) => c.id === id) : null;
  $('modal-title').textContent = existing ? 'Edit Connection' : 'New Connection';
  $('m_label').value = existing?.label ?? '';
  $('m_endpoint').value = existing?.endpoint ?? '';
  $('m_token').value = existing?.token ?? '';
  $('m_cert_pin').value = existing?.cert_pin ?? '';
  $('m_ech_config').value = existing?.ech_config ?? '';
  $('m_cr_mode').checked = !!existing?.censorship_resistant;
  $('m_h3_framing').checked = !!existing?.http3_framing;
  $('m_h2_framing').checked = !!existing?.http2_framing;
  $('m_kc_auth').checked = !!existing?.kc_auth;
  $('m_kc_url').value = existing?.kc_url ?? '';
  $('m_kc_realm').value = existing?.kc_realm ?? '';
  $('m_kc_client_id').value = existing?.kc_client_id ?? '';
  $('m_vpn_mtu').value = existing?.vpn_mtu ?? '';
  const savedApps = Array.isArray(existing?.split_tunnel_apps) ? existing.split_tunnel_apps : [];
  _selectedAppIds = new Set(savedApps.map((app) => app.id));
  $('m_split_mode').value = _splitSupported
    ? existing?.split_tunnel_mode ?? 'disabled'
    : 'disabled';
  $('m_split_search').value = '';
  renderSplitTunnelApps();
  updateSplitTunnelFields();
  updateModalAuthFields();
  $('modal-delete').classList.toggle('hidden', !existing);
  $('modal-backdrop').classList.add('visible');
  setTimeout(() => $('m_label').focus(), 0);
}

export function closeModal() {
  $('modal-backdrop').classList.remove('visible');
  _editingId = null;
}

export async function saveModal() {
  const label = $('m_label').value.trim();
  const endpoint = $('m_endpoint').value.trim();
  const token = $('m_token').value.trim();
  const cert_pin = $('m_cert_pin').value.trim();
  const kc_auth = $('m_kc_auth').checked || null;
  if (!label) return showToast('Label is required.', 'error');
  if (!endpoint) return showToast('Endpoint is required.', 'error');
  if (!isValidEndpoint(endpoint))
    return showToast('Endpoint must look like host:port.', 'error');
  if (!kc_auth && !token)
    return showToast('Pre-shared key is required unless Keycloak is enabled.', 'error');
  if (!cert_pin) return showToast('Certificate PIN is required.', 'error');
  if (!isValidCertPin(cert_pin)) {
    return showToast(
      'Certificate PIN must be 64 hex characters (comma-separated for dual-pin rotation).',
      'error'
    );
  }

  const mtu = parseOptionalMtu($('m_vpn_mtu').value);
  if (!mtu.valid) {
    return showToast('VPN MTU must be between 1280 and 1360.', 'error');
  }

  const kc_url_input = kc_auth ? $('m_kc_url').value.trim() : '';
  if (kc_auth && !isValidKcUrl(kc_url_input)) {
    return showToast('Keycloak URL must be a valid http(s) URL.', 'error');
  }

  const http2_framing = $('m_h2_framing').checked;
  const split_tunnel_mode = _splitSupported ? $('m_split_mode').value : 'disabled';
  const split_tunnel_apps = _splitCatalog.filter((app) => _selectedAppIds.has(app.id));
  if (split_tunnel_mode !== 'disabled' && split_tunnel_apps.length === 0) {
    return showToast('Select at least one application for split tunneling.', 'error');
  }
  const conn = {
    id: _editingId || generateConnectionId(),
    label,
    endpoint,
    token: kc_auth ? null : token,
    cert_pin,
    ech_config: $('m_ech_config').value.trim() || null,
    censorship_resistant: http2_framing ? false : $('m_cr_mode').checked,
    http3_framing: http2_framing ? false : $('m_h3_framing').checked,
    http2_framing,
    kc_auth,
    kc_url: kc_auth ? $('m_kc_url').value.trim() || null : null,
    kc_realm: kc_auth ? $('m_kc_realm').value.trim() || null : null,
    kc_client_id: kc_auth ? $('m_kc_client_id').value.trim() || null : null,
    vpn_mtu: mtu.value,
    split_tunnel_mode,
    split_tunnel_apps,
  };

  if (_editingId) {
    const idx = state.prefs.connections.findIndex((c) => c.id === _editingId);
    if (idx >= 0) state.prefs.connections[idx] = conn;
  } else {
    state.prefs.connections.push(conn);
    state.prefs.active_id = conn.id;
  }
  await savePrefs();
  closeModal();
  renderConnectionList();
  if (_applyHero) _applyHero();
  showToast('Connection saved.', 'success');
}

export function updateSplitTunnelFields() {
  const enabled = _splitSupported && $('m_split_mode').value !== 'disabled';
  $('m-split-app-picker')?.classList.toggle('hidden', !enabled);
}

function renderSplitTunnelApps() {
  const list = $('m_split_apps');
  if (!list) return;
  const query = ($('m_split_search')?.value ?? '').trim().toLowerCase();
  const apps = _splitCatalog.filter((app) => !query || app.name.toLowerCase().includes(query));
  list.replaceChildren();
  if (apps.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'split-app-empty';
    empty.textContent = _splitCatalog.length ? 'No matching applications.' : 'No applications found.';
    list.appendChild(empty);
    return;
  }
  for (const app of apps) {
    const row = document.createElement('label');
    row.className = 'split-app-row';
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.checked = _selectedAppIds.has(app.id);
    checkbox.addEventListener('change', () => {
      if (checkbox.checked) _selectedAppIds.add(app.id);
      else _selectedAppIds.delete(app.id);
    });
    const name = document.createElement('span');
    name.textContent = app.name;
    row.append(checkbox, name);
    list.appendChild(row);
  }
}

export async function deleteModal() {
  if (!_editingId) return;
  state.prefs.connections = state.prefs.connections.filter((c) => c.id !== _editingId);
  if (state.prefs.active_id === _editingId) state.prefs.active_id = null;
  await savePrefs();
  closeModal();
  renderConnectionList();
  if (_applyHero) _applyHero();
}
