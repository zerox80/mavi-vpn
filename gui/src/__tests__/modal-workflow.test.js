import { beforeEach, describe, expect, it, vi } from 'vitest';
import { state } from '../state.js';
import { deleteModal, openModal, saveModal, updateModalAuthFields, wireModal } from '../modal.js';
import { savePrefs } from '../theme.js';
import { renderConnectionList } from '../connections.js';

vi.mock('../theme.js', () => ({
  savePrefs: vi.fn(() => Promise.resolve()),
}));

vi.mock('../connections.js', () => ({
  generateConnectionId: vi.fn(() => 'generated-id'),
  renderConnectionList: vi.fn(),
}));

vi.mock('../toast.js', () => ({
  showToast: vi.fn(),
}));

function setupModalDom() {
  document.body.innerHTML = `
    <div id="modal-backdrop"></div>
    <div id="modal-title"></div>
    <input id="m_label" />
    <input id="m_endpoint" />
    <input id="m_token" />
    <input id="m_cert_pin" />
    <input id="m_ech_config" />
    <input id="m_cr_mode" type="checkbox" />
    <input id="m_h3_framing" type="checkbox" />
    <input id="m_kc_auth" type="checkbox" />
    <input id="m_kc_url" />
    <input id="m_kc_realm" />
    <input id="m_kc_client_id" />
    <input id="m_vpn_mtu" />
    <div id="m-kc-fields"></div>
    <div id="m-token-field"></div>
    <button id="modal-cancel"></button>
    <button id="modal-save"></button>
    <button id="modal-delete"></button>
  `;
}

describe('modal workflows', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setupModalDom();
    state.prefs.connections = [];
    state.prefs.active_id = null;
    wireModal({ applyHeroForSelection: vi.fn() });
  });

  it('toggles Keycloak fields against token field', () => {
    document.getElementById('m_kc_auth').checked = true;

    updateModalAuthFields();

    expect(document.getElementById('m-kc-fields').classList.contains('hidden')).toBe(false);
    expect(document.getElementById('m-token-field').classList.contains('hidden')).toBe(true);
  });

  it('saves a new connection and selects it', async () => {
    document.getElementById('m_label').value = 'Primary';
    document.getElementById('m_endpoint').value = 'vpn.example.com:443';
    document.getElementById('m_token').value = 'secret';
    document.getElementById('m_cert_pin').value = 'pin';
    document.getElementById('m_vpn_mtu').value = '1340';

    await saveModal();

    expect(state.prefs.connections).toHaveLength(1);
    expect(state.prefs.connections[0]).toMatchObject({
      id: 'generated-id',
      label: 'Primary',
      endpoint: 'vpn.example.com:443',
      token: 'secret',
      cert_pin: 'pin',
      vpn_mtu: 1340,
    });
    expect(state.prefs.active_id).toBe('generated-id');
    expect(savePrefs).toHaveBeenCalledOnce();
    expect(renderConnectionList).toHaveBeenCalledOnce();
  });

  it('deleting the active connection clears active_id', async () => {
    state.prefs.connections = [
      {
        id: 'conn-1',
        label: 'Primary',
        endpoint: 'vpn.example.com:443',
        token: 'secret',
        cert_pin: 'pin',
      },
    ];
    state.prefs.active_id = 'conn-1';

    openModal('conn-1');
    await deleteModal();

    expect(state.prefs.connections).toEqual([]);
    expect(state.prefs.active_id).toBeNull();
    expect(savePrefs).toHaveBeenCalledOnce();
  });
});
