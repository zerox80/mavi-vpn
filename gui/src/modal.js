import { state, $ } from './state.js';
import { savePrefs } from './theme.js';
import { renderConnectionList, generateConnectionId } from './connections.js';
import { showToast } from './toast.js';

let _applyHero = null;
let _editingId = null;

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
  $('m_kc_auth').checked = !!existing?.kc_auth;
  $('m_kc_url').value = existing?.kc_url ?? '';
  $('m_kc_realm').value = existing?.kc_realm ?? '';
  $('m_kc_client_id').value = existing?.kc_client_id ?? '';
  $('m_vpn_mtu').value = existing?.vpn_mtu ?? '';
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
  if (!kc_auth && !token)
    return showToast('Pre-shared key is required unless Keycloak is enabled.', 'error');
  if (!cert_pin) return showToast('Certificate PIN is required.', 'error');

  const mtuVal = parseInt($('m_vpn_mtu').value, 10);
  const conn = {
    id: _editingId || generateConnectionId(),
    label,
    endpoint,
    token: kc_auth ? null : token,
    cert_pin,
    ech_config: $('m_ech_config').value.trim() || null,
    censorship_resistant: $('m_cr_mode').checked,
    http3_framing: $('m_h3_framing').checked,
    kc_auth,
    kc_url: kc_auth ? $('m_kc_url').value.trim() || null : null,
    kc_realm: kc_auth ? $('m_kc_realm').value.trim() || null : null,
    kc_client_id: kc_auth ? $('m_kc_client_id').value.trim() || null : null,
    vpn_mtu: mtuVal >= 1280 && mtuVal <= 1360 ? mtuVal : null,
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
