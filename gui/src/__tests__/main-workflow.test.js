import { beforeEach, describe, expect, it, vi } from 'vitest';

describe('main startup workflow', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    document.body.innerHTML = `
      <button class="tab active" data-tab="connect"></button>
      <div class="tab-panel active" data-panel="connect"></div>
      <input id="search" />
      <div id="modal-backdrop"></div>
      <button id="modal-cancel"></button>
    `;
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
  });
});
