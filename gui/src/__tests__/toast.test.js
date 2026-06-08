import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { daemonHintText, hideToast, showServiceOfflineHint, showToast } from '../toast.js';

function setPlatform(platform) {
  Object.defineProperty(navigator, 'platform', {
    configurable: true,
    value: platform,
  });
}

describe('toast helpers', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    document.body.innerHTML = '<div id="toast"></div>';
    setPlatform('Linux x86_64');
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('shows, auto-hides, and manually hides matching toast kinds', () => {
    showToast('Saved', 'success', 100);

    const toast = document.getElementById('toast');
    expect(toast.className).toBe('visible success');
    expect(toast.textContent).toBe('Saved');
    expect(toast.dataset.kind).toBe('success');

    vi.advanceTimersByTime(100);

    expect(toast.className).toBe('');
    expect(toast.textContent).toBe('');
    expect(toast.dataset.kind).toBe('');
  });

  it('does not hide a toast when the kind does not match', () => {
    showToast('Saved', 'success', 0);

    hideToast('error');

    expect(document.getElementById('toast').textContent).toBe('Saved');
  });

  it('leaves the DOM alone when the toast element is missing', () => {
    document.body.innerHTML = '';

    expect(() => showToast('Missing')).not.toThrow();
    expect(() => hideToast()).not.toThrow();
    expect(() => showServiceOfflineHint()).not.toThrow();
  });

  it('shows Linux and Windows service hints without replacing hard errors', () => {
    showServiceOfflineHint();
    expect(document.getElementById('toast').innerHTML).toContain('sudo systemctl start mavi-vpn');
    expect(daemonHintText()).toBe('Daemon offline. Run: sudo systemctl start mavi-vpn');

    setPlatform('Win32');
    showServiceOfflineHint();
    expect(document.getElementById('toast').innerHTML).toContain('net start MaviVPNService');
    expect(daemonHintText()).toBe('Daemon offline. Run: net start MaviVPNService');

    showToast('Hard failure', 'error', 0);
    showServiceOfflineHint();

    expect(document.getElementById('toast').textContent).toBe('Hard failure');
  });
});
