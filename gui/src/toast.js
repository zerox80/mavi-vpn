import { $ } from './state.js';

export function showToast(msg, kind = 'error', ttl = 6000) {
  const box = $('toast');
  if (!box) return;
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

export function hideToast(kind) {
  const box = $('toast');
  if (!box) return;
  if (!kind || box.dataset.kind === kind) {
    box.className = '';
    box.textContent = '';
    box.dataset.kind = '';
  }
}

export function showServiceOfflineHint() {
  const box = $('toast');
  if (!box) return;
  // Don't stomp a hard error
  if (box.dataset.kind === 'error') return;
  const isWin = navigator.platform.toLowerCase().includes('win');
  box.className = 'visible hint';
  box.dataset.kind = 'hint';
  box.innerHTML = isWin
    ? 'VPN daemon offline. Run in Admin PowerShell: <code>net start MaviVPNService</code>'
    : 'VPN daemon offline. Run: <code>sudo systemctl start mavi-vpn</code>';
}

export function daemonHintText() {
  return navigator.platform.toLowerCase().includes('win')
    ? 'Daemon offline. Run: net start MaviVPNService'
    : 'Daemon offline. Run: sudo systemctl start mavi-vpn';
}
