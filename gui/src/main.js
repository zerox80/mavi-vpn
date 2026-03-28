// =============================================================================
// Tauri API — resolved lazily inside DOMContentLoaded to avoid timing crashes
// =============================================================================

let _invoke = null;
let _listen = null;

function invoke(cmd, args) {
  if (!_invoke) throw new Error('Tauri invoke not ready');
  return _invoke(cmd, args);
}

function listen(event, handler) {
  if (!_listen) throw new Error('Tauri listen not ready');
  return _listen(event, handler);
}

// =============================================================================
// State
// =============================================================================

let isConnected = false;
let isConnecting = false;

// =============================================================================
// Initialization
// =============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  // Resolve Tauri API — withGlobalTauri:true injects window.__TAURI__ but
  // it may not be fully populated until after DOMContentLoaded fires on some
  // Tauri builds. Poll briefly to be safe.
  let attempts = 0;
  while ((!window.__TAURI__ || !window.__TAURI__.core) && attempts < 20) {
    await new Promise(r => setTimeout(r, 50));
    attempts++;
  }

  if (window.__TAURI__ && window.__TAURI__.core) {
    _invoke = window.__TAURI__.core.invoke;
    _listen = window.__TAURI__.event.listen;
  } else {
    console.error('Tauri API not available – running in browser preview mode');
  }

  // Wire up all buttons here — no onclick in HTML (avoids CSP issues)
  document.getElementById('connect-btn').addEventListener('click', () => toggleConnection());
  document.getElementById('settings-toggle').addEventListener('click', () => toggleSettings());
  document.getElementById('save-btn').addEventListener('click', () => saveSettings());
  document.getElementById('kc_auth').addEventListener('change', () => toggleKeycloak());
  document.getElementById('import-btn').addEventListener('click', () => importConfig());
  document.getElementById('export-btn').addEventListener('click', () => exportConfig());
  document.getElementById('copy-btn').addEventListener('click', () => copyConfigCode());

  // Load saved config into settings fields
  try {
    const config = await invoke('load_config');
    if (config) fillSettings(config);
  } catch (e) {
    console.log('No saved config:', e);
  }

  // Initial status check
  await refreshStatus();

  // Live status updates from Rust poller
  try {
    await listen('vpn-status-update', (event) => updateUI(event.payload));
    await listen('tray-toggle', async () => await toggleConnection());
  } catch (e) {
    console.warn('Could not register event listeners:', e);
  }
});

// =============================================================================
// Settings Panel
// =============================================================================

function toggleSettings() {
  const panel = document.getElementById('settings-panel');
  const arrow = document.getElementById('settings-arrow');
  const isOpen = !panel.classList.contains('hidden');
  panel.classList.toggle('hidden', isOpen);
  arrow.classList.toggle('open', !isOpen);
}

function toggleKeycloak() {
  const checked = document.getElementById('kc_auth').checked;
  document.getElementById('kc-fields').classList.toggle('hidden', !checked);
  document.getElementById('token-field').classList.toggle('hidden', checked);
}

// =============================================================================
// Connection Control
// =============================================================================

async function toggleConnection() {
  if (isConnecting) return;
  if (isConnected) await disconnect();
  else await connect();
}

async function connect() {
  const config = readSettings();
  if (!config.endpoint) { showError('Please enter a server endpoint in Settings.'); return; }
  if (!config.cert_pin) { showError('Please enter a certificate PIN in Settings.'); return; }
  if (!config.token && !config.kc_auth) { showError('Please provide an auth token or enable Keycloak.'); return; }

  hideError();
  isConnecting = true;
  setConnectingUI();

  try {
    await invoke('save_config', { config });
    await invoke('vpn_connect', { config });
  } catch (e) {
    showError(String(e));
    setDisconnectedUI();
  } finally {
    isConnecting = false;
  }
}

async function disconnect() {
  hideError();
  const btn = document.getElementById('connect-btn');
  btn.disabled = true;
  btn.textContent = 'Disconnecting…';
  try {
    await invoke('vpn_disconnect');
  } catch (e) {
    showError(String(e));
  } finally {
    btn.disabled = false;
    await refreshStatus();
  }
}

async function refreshStatus() {
  try {
    const status = await invoke('vpn_status');
    updateUI(status);
  } catch (_) {
    updateUI({ running: false, endpoint: null, service_available: false });
  }
}

// =============================================================================
// UI Updates
// =============================================================================

function updateUI(status) {
  isConnected = !!status.running;

  const badge = document.getElementById('service-badge');
  const btn = document.getElementById('connect-btn');

  if (status.service_available) {
    badge.className = 'badge badge-online';
    badge.textContent = 'Service Online';
    btn.disabled = false;
    btn.title = '';
  } else {
    badge.className = 'badge badge-offline';
    badge.textContent = 'Service Offline';
    if (!isConnected) {
      btn.disabled = true;
      btn.title = 'Start the VPN daemon first:\n  sudo systemctl start mavi-vpn\n  or: sudo mavi-vpn daemon &';
    }
    showServiceOfflineHint();
  }

  if (status.running) {
    setConnectedUI(status.endpoint);
  } else if (!isConnecting) {
    setDisconnectedUI();
  }
}

function showServiceOfflineHint() {
  const box = document.getElementById('error-box');
  // Don't overwrite an existing real error
  if (!box.classList.contains('hidden') && box.dataset.type === 'error') return;
  box.textContent = 'VPN daemon is not running. Run: sudo systemctl start mavi-vpn';
  box.style.color = 'var(--yellow)';
  box.style.background = 'rgba(234,179,8,0.12)';
  box.style.borderColor = 'rgba(234,179,8,0.3)';
  box.dataset.type = 'hint';
  box.classList.remove('hidden');
}

function setConnectedUI(endpoint) {
  document.getElementById('status-indicator').className = 'status-dot connected';
  document.getElementById('status-label').textContent = 'Connected';
  document.getElementById('status-detail').textContent = endpoint || 'VPN tunnel active';
  const btn = document.getElementById('connect-btn');
  btn.textContent = 'Disconnect';
  btn.className = 'btn btn-connect connected';
  btn.disabled = false;
}

function setDisconnectedUI() {
  document.getElementById('status-indicator').className = 'status-dot disconnected';
  document.getElementById('status-label').textContent = 'Disconnected';
  document.getElementById('status-detail').textContent = 'Not connected to any server';
  const btn = document.getElementById('connect-btn');
  btn.textContent = 'Connect';
  btn.className = 'btn btn-connect';
  btn.disabled = false;
}

function setConnectingUI() {
  document.getElementById('status-indicator').className = 'status-dot connecting';
  document.getElementById('status-label').textContent = 'Connecting…';
  document.getElementById('status-detail').textContent = 'Establishing VPN tunnel';
  const btn = document.getElementById('connect-btn');
  btn.textContent = 'Connecting…';
  btn.disabled = true;
}

// =============================================================================
// Settings Read / Write
// =============================================================================

function readSettings() {
  const kcAuth = document.getElementById('kc_auth').checked;
  return {
    endpoint:              document.getElementById('endpoint').value.trim(),
    token:                 document.getElementById('token').value.trim(),
    cert_pin:              document.getElementById('cert_pin').value.trim(),
    censorship_resistant:  document.getElementById('cr_mode').checked,
    prefer_tcp:            document.getElementById('prefer_tcp').checked,
    kc_auth:               kcAuth || null,
    kc_url:                kcAuth ? document.getElementById('kc_url').value.trim()       || null : null,
    kc_realm:              kcAuth ? document.getElementById('kc_realm').value.trim()     || null : null,
    kc_client_id:          kcAuth ? document.getElementById('kc_client_id').value.trim() || null : null,
  };
}

function fillSettings(config) {
  document.getElementById('endpoint').value    = config.endpoint  || '';
  document.getElementById('token').value       = config.token     || '';
  document.getElementById('cert_pin').value    = config.cert_pin  || '';
  document.getElementById('cr_mode').checked   = !!config.censorship_resistant;
  document.getElementById('prefer_tcp').checked= !!config.prefer_tcp;
  document.getElementById('kc_auth').checked   = !!config.kc_auth;
  document.getElementById('kc_url').value      = config.kc_url      || '';
  document.getElementById('kc_realm').value    = config.kc_realm    || '';
  document.getElementById('kc_client_id').value= config.kc_client_id|| '';
  document.getElementById('kc-fields').classList.toggle('hidden', !config.kc_auth);
  document.getElementById('token-field').classList.toggle('hidden', !!config.kc_auth);
}

async function saveSettings() {
  const config = readSettings();
  try {
    await invoke('save_config', { config });
    showSuccess('Settings saved.');
  } catch (e) {
    showError('Failed to save: ' + e);
  }
}

// =============================================================================
// Notifications
// =============================================================================

function showError(msg) {
  const box = document.getElementById('error-box');
  box.textContent = friendlyError(msg);
  box.style.color = 'var(--red)';
  box.style.background = 'var(--red-glow)';
  box.style.borderColor = 'rgba(239,68,68,0.3)';
  box.dataset.type = 'error';
  box.classList.remove('hidden');
  setTimeout(() => box.classList.add('hidden'), 8000);
}

function friendlyError(msg) {
  const s = String(msg);
  if (s.includes('10061') || s.includes('connection refused') || s.includes('Verbindung verweigerte'))
    return 'VPN daemon is not running. Start it with: sudo systemctl start mavi-vpn';
  if (s.includes('10060') || s.includes('timed out'))
    return 'Connection timed out. Check the server endpoint and firewall.';
  if (s.includes('cert') || s.includes('certificate'))
    return 'Certificate error. Verify the certificate PIN in Settings.';
  return s;
}

function showSuccess(msg) {
  const box = document.getElementById('error-box');
  box.textContent = msg;
  box.style.color = 'var(--green)';
  box.style.background = 'var(--green-glow)';
  box.style.borderColor = 'rgba(34,197,94,0.3)';
  box.classList.remove('hidden');
  setTimeout(() => box.classList.add('hidden'), 3000);
}

function hideError() {
  document.getElementById('error-box').classList.add('hidden');
}

// =============================================================================
// Config Code Import / Export
// =============================================================================

async function importConfig() {
  const code = document.getElementById('config_code_input').value.trim();
  if (!code) { showError('Please paste a config code (mavi://...).'); return; }

  try {
    const config = await invoke('import_config_code', { code });
    fillSettings(config);
    await invoke('save_config', { config });
    document.getElementById('config_code_input').value = '';
    if (config.kc_auth) {
      showSuccess('Config imported! Click Connect to log in via Keycloak.');
    } else {
      showSuccess('Config imported! Enter your token, then click Connect.');
      document.getElementById('token').focus();
    }
  } catch (e) {
    showError('Import failed: ' + e);
  }
}

async function exportConfig() {
  const config = readSettings();
  try {
    const code = await invoke('export_config_code', { config });
    document.getElementById('config_code_output').value = code;
    document.getElementById('export-output').classList.remove('hidden');
  } catch (e) {
    showError('Export failed: ' + e);
  }
}

async function copyConfigCode() {
  const code = document.getElementById('config_code_output').value;
  try {
    await navigator.clipboard.writeText(code);
    showSuccess('Config code copied to clipboard!');
  } catch (_) {
    // Fallback: select text for manual copy
    document.getElementById('config_code_output').select();
  }
}
