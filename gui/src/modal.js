import { state, $ } from './state.js';
import { savePrefs } from './theme.js';
import { renderConnectionList, generateConnectionId } from './connections.js';
import { showToast } from './toast.js';
import { parseOptionalMtu, parseSplitTunnelTargets } from './utils.js';

let _applyHero = null;
let _editingId = null;

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
  $('m_split_mode').value = existing?.split_tunnel_mode ?? 'disabled';
  $('m_split_targets').value = (existing?.split_tunnel_targets ?? []).join('\n');
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
  const split_tunnel_mode = $('m_split_mode').value;
  const split_tunnel_targets = parseSplitTunnelTargets($('m_split_targets').value);
  if (split_tunnel_mode !== 'disabled' && split_tunnel_targets.length === 0) {
    return showToast('Add at least one split-tunnel domain, IP, or CIDR.', 'error');
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
    split_tunnel_targets,
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

export async function deleteModal() {
  if (!_editingId) return;
  state.prefs.connections = state.prefs.connections.filter((c) => c.id !== _editingId);
  if (state.prefs.active_id === _editingId) state.prefs.active_id = null;
  await savePrefs();
  closeModal();
  renderConnectionList();
  if (_applyHero) _applyHero();
}
