import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

describe('main startup workflow', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    document.body.innerHTML = `
      <button class="tab active" data-tab="connect"></button>
      <button class="tab" data-tab="activity"></button>
      <div class="tab-panel active" data-panel="connect"></div>
      <div class="tab-panel" data-panel="activity"></div>
      <input id="search" />
      <div id="modal-backdrop" class="visible"></div>
      <button id="modal-cancel"></button>
    `;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('loads prefs, migrates legacy config, and wires status listeners', async () => {
    const invoke = vi
      .fn()
      .mockResolvedValueOnce({
        theme: 'dark',
        accent: '#2B44FF',
        connections: [],
        active_id: null,
        legacy_config_migrated: false,
      })
      .mockResolvedValueOnce({ endpoint: 'vpn.example.com:443', token: 'secret', cert_pin: 'pin' })
      .mockResolvedValueOnce({ service_available: false, running: false, state: 'Stopped' });
    const listen = vi.fn(() => Promise.resolve());
    const migrateLegacyConfig = vi.fn(() => Promise.resolve());
    const applyTheme = vi.fn();
    const renderConnectionList = vi.fn();
    const refreshStatus = vi.fn(() => Promise.resolve());
    const applyStatus = vi.fn();
    const toggleConnection = vi.fn();
    const updateSparklineColors = vi.fn();

    vi.doMock('../api.js', () => ({
      bootstrapTauri: vi.fn(() => Promise.resolve(true)),
      invoke,
      listen,
    }));
    vi.doMock('../theme.js', () => ({
      wireThemeToggle: vi.fn(),
      applyTheme,
      normalizePrefs: vi.fn((prefs) => prefs),
    }));
    vi.doMock('../connections.js', () => ({
      wireSidebarSearch: vi.fn(),
      renderConnectionList,
      migrateLegacyConfig,
    }));
    vi.doMock('../modal.js', () => ({
      wireModal: vi.fn(),
      openModal: vi.fn(),
    }));
    vi.doMock('../vpn.js', () => ({
      wireHero: vi.fn(),
      refreshStatus,
      applyStatus,
      toggleConnection,
      applyHeroForSelection: vi.fn(),
    }));
    vi.doMock('../animations.js', () => ({
      startCoreAnimation: vi.fn(),
      renderSparkline: vi.fn(),
      startStatsAnimation: vi.fn(),
      startSessionClock: vi.fn(),
      updateSparklineColors,
    }));

    await import('../main.js');
    document.dispatchEvent(new Event('DOMContentLoaded'));
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(invoke).toHaveBeenNthCalledWith(1, 'load_prefs');
    expect(invoke).toHaveBeenNthCalledWith(2, 'load_config');
    expect(migrateLegacyConfig).toHaveBeenCalledWith({
      endpoint: 'vpn.example.com:443',
      token: 'secret',
      cert_pin: 'pin',
    });
    expect(applyTheme).toHaveBeenCalledWith('dark');
    expect(renderConnectionList).toHaveBeenCalledOnce();
    expect(refreshStatus).toHaveBeenCalledOnce();
    expect(listen).toHaveBeenCalledWith('vpn-status-update', expect.any(Function));
    expect(listen).toHaveBeenCalledWith('tray-toggle', expect.any(Function));

    listen.mock.calls[0][1]({ payload: { state: 'Connected' } });
    listen.mock.calls[1][1]();
    expect(applyStatus).toHaveBeenCalledWith({ state: 'Connected' });
    expect(toggleConnection).toHaveBeenCalledOnce();

    document.querySelector('.tab[data-tab="activity"]').click();
    expect(document.querySelector('.tab[data-tab="activity"]').classList.contains('active')).toBe(
      true
    );
    expect(
      document.querySelector('.tab-panel[data-panel="activity"]').classList.contains('active')
    ).toBe(true);

    const search = document.getElementById('search');
    const shortcut = new KeyboardEvent('keydown', {
      key: 'K',
      ctrlKey: true,
      bubbles: true,
      cancelable: true,
    });
    document.dispatchEvent(shortcut);
    expect(shortcut.defaultPrevented).toBe(true);
    expect(document.activeElement).toBe(search);

    const cancelClick = vi.spyOn(document.getElementById('modal-cancel'), 'click');
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    expect(cancelClick).toHaveBeenCalledOnce();

    document.documentElement.setAttribute('data-theme', 'dark');
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(updateSparklineColors).toHaveBeenCalled();
  });

  it('continues startup when prefs, migration, or event wiring fails', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const invoke = vi
      .fn()
      .mockRejectedValueOnce(new Error('prefs offline'))
      .mockRejectedValueOnce(new Error('config offline'));
    const listen = vi.fn(() => Promise.reject(new Error('events offline')));
    const applyTheme = vi.fn();
    const renderConnectionList = vi.fn();
    const refreshStatus = vi.fn(() => Promise.resolve());

    vi.doMock('../api.js', () => ({
      bootstrapTauri: vi.fn(() => Promise.resolve(false)),
      invoke,
      listen,
    }));
    vi.doMock('../theme.js', () => ({
      wireThemeToggle: vi.fn(),
      applyTheme,
      normalizePrefs: vi.fn((prefs) => prefs),
    }));
    vi.doMock('../connections.js', () => ({
      wireSidebarSearch: vi.fn(),
      renderConnectionList,
      migrateLegacyConfig: vi.fn(),
    }));
    vi.doMock('../modal.js', () => ({
      wireModal: vi.fn(),
      openModal: vi.fn(),
    }));
    vi.doMock('../vpn.js', () => ({
      wireHero: vi.fn(),
      refreshStatus,
      applyStatus: vi.fn(),
      toggleConnection: vi.fn(),
      applyHeroForSelection: vi.fn(),
    }));
    vi.doMock('../animations.js', () => ({
      startCoreAnimation: vi.fn(),
      renderSparkline: vi.fn(),
      startStatsAnimation: vi.fn(),
      startSessionClock: vi.fn(),
      updateSparklineColors: vi.fn(),
    }));

    await import('../main.js');
    document.dispatchEvent(new Event('DOMContentLoaded'));
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(applyTheme).toHaveBeenCalled();
    expect(renderConnectionList).toHaveBeenCalled();
    expect(refreshStatus).toHaveBeenCalled();
    expect(warn).toHaveBeenCalledWith('load_prefs failed:', expect.any(Error));
    expect(warn).toHaveBeenCalledWith('legacy config migration skipped:', expect.any(Error));
    expect(warn).toHaveBeenCalledWith('event wiring failed:', expect.any(Error));
  });
});
