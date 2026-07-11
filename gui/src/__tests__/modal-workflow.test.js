import { beforeEach, describe, expect, it, vi } from 'vitest';
import { state } from '../state.js';
import { deleteModal, openModal, saveModal, updateModalAuthFields, wireModal } from '../modal.js';
import { savePrefs } from '../theme.js';
import { renderConnectionList } from '../connections.js';
import { showToast } from '../toast.js';

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

// A syntactically valid 64-hex-char cert pin placeholder - saveModal() now
// validates the format, so tests exercising it need a value that passes.
const VALID_PIN = 'a'.repeat(64);

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
    <input id="m_h2_framing" type="checkbox" />
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

    document.getElementById('m_kc_auth').checked = false;
    updateModalAuthFields();
    expect(document.getElementById('m-kc-fields').classList.contains('hidden')).toBe(true);
    expect(document.getElementById('m-token-field').classList.contains('hidden')).toBe(false);
  });

  it('saves a new connection and selects it', async () => {
    document.getElementById('m_label').value = 'Primary';
    document.getElementById('m_endpoint').value = 'vpn.example.com:443';
    document.getElementById('m_token').value = 'secret';
    document.getElementById('m_cert_pin').value = VALID_PIN;
    document.getElementById('m_vpn_mtu').value = '1340';

    await saveModal();

    expect(state.prefs.connections).toHaveLength(1);
    expect(state.prefs.connections[0]).toMatchObject({
      id: 'generated-id',
      label: 'Primary',
      endpoint: 'vpn.example.com:443',
      token: 'secret',
      cert_pin: VALID_PIN,
      vpn_mtu: 1340,
    });
    expect(state.prefs.active_id).toBe('generated-id');
    expect(savePrefs).toHaveBeenCalledOnce();
    expect(renderConnectionList).toHaveBeenCalledOnce();
  });

  it('validates required modal fields and MTU range', async () => {
    await saveModal();
    expect(showToast).toHaveBeenLastCalledWith('Label is required.', 'error');

    document.getElementById('m_label').value = 'Primary';
    await saveModal();
    expect(showToast).toHaveBeenLastCalledWith('Endpoint is required.', 'error');

    document.getElementById('m_endpoint').value = 'vpn.example.com:443';
    await saveModal();
    expect(showToast).toHaveBeenLastCalledWith(
      'Pre-shared key is required unless Keycloak is enabled.',
      'error'
    );

    document.getElementById('m_token').value = 'secret';
    await saveModal();
    expect(showToast).toHaveBeenLastCalledWith('Certificate PIN is required.', 'error');

    document.getElementById('m_cert_pin').value = VALID_PIN;
    document.getElementById('m_vpn_mtu').value = '1500';
    await saveModal();
    expect(showToast).toHaveBeenLastCalledWith('VPN MTU must be between 1280 and 1360.', 'error');
    expect(savePrefs).not.toHaveBeenCalled();
  });

  it('saves a Keycloak connection with optional fields normalized', async () => {
    document.getElementById('m_label').value = 'SSO Node';
    document.getElementById('m_endpoint').value = 'vpn.example.com:443';
    document.getElementById('m_token').value = 'ignored';
    document.getElementById('m_cert_pin').value = VALID_PIN;
    document.getElementById('m_kc_auth').checked = true;
    document.getElementById('m_kc_url').value = ' https://auth.example.com ';

    await saveModal();

    expect(state.prefs.connections[0]).toMatchObject({
      token: null,
      kc_auth: true,
      kc_url: 'https://auth.example.com',
      kc_realm: null,
      kc_client_id: null,
    });
  });

  it('edits an existing Keycloak connection and applies hero refresh', async () => {
    const applyHeroForSelection = vi.fn();
    wireModal({ applyHeroForSelection });
    state.prefs.connections = [
      {
        id: 'conn-1',
        label: 'Primary',
        endpoint: 'old.example.com:443',
        token: 'old-secret',
        cert_pin: 'old-pin',
        ech_config: 'old-ech',
        censorship_resistant: false,
        http3_framing: false,
        kc_auth: false,
        vpn_mtu: null,
      },
    ];

    openModal('conn-1');
    document.getElementById('m_label').value = 'Updated';
    document.getElementById('m_endpoint').value = 'vpn.example.com:443';
    document.getElementById('m_token').value = 'stale';
    document.getElementById('m_cert_pin').value = VALID_PIN;
    document.getElementById('m_ech_config').value = 'ech';
    document.getElementById('m_cr_mode').checked = true;
    document.getElementById('m_h3_framing').checked = true;
    document.getElementById('m_kc_auth').checked = true;
    document.getElementById('m_kc_url').value = 'https://auth.example.com';
    document.getElementById('m_kc_realm').value = 'realm';
    document.getElementById('m_kc_client_id').value = 'client';
    document.getElementById('m_vpn_mtu').value = '';

    await saveModal();

    expect(state.prefs.connections).toEqual([
      {
        id: 'conn-1',
        label: 'Updated',
        endpoint: 'vpn.example.com:443',
        token: null,
        cert_pin: VALID_PIN,
        ech_config: 'ech',
        censorship_resistant: true,
        http3_framing: true,
        http2_framing: false,
        kc_auth: true,
        kc_url: 'https://auth.example.com',
        kc_realm: 'realm',
        kc_client_id: 'client',
        vpn_mtu: null,
      },
    ]);
    expect(applyHeroForSelection).toHaveBeenCalled();
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

  it('wires cancel, backdrop, auth change, save, and delete interactions', async () => {
    state.prefs.connections = [
      {
        id: 'conn-1',
        label: 'Primary',
        endpoint: 'vpn.example.com:443',
        token: 'secret',
        cert_pin: 'pin',
      },
    ];

    openModal('conn-1');
    expect(document.getElementById('modal-backdrop').classList.contains('visible')).toBe(true);

    document.getElementById('modal-cancel').click();
    expect(document.getElementById('modal-backdrop').classList.contains('visible')).toBe(false);

    openModal('conn-1');
    document
      .getElementById('modal-backdrop')
      .dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(document.getElementById('modal-backdrop').classList.contains('visible')).toBe(false);

    openModal('conn-1');
    document.getElementById('m_kc_auth').checked = true;
    document.getElementById('m_kc_auth').dispatchEvent(new Event('change'));
    expect(document.getElementById('m-token-field').classList.contains('hidden')).toBe(true);

    document.getElementById('modal-delete').click();
    await Promise.resolve();
    expect(state.prefs.connections).toEqual([]);

    await deleteModal();
    expect(savePrefs).toHaveBeenCalledOnce();
  });
});
