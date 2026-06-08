import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

describe('Tauri API bootstrap', () => {
  beforeEach(() => {
    vi.resetModules();
    delete window.__TAURI__;
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('throws before bootstrap installs invoke and listen', async () => {
    const { invoke, listen } = await import('../api.js');

    expect(() => invoke('vpn_status')).toThrow('Tauri invoke not ready');
    expect(() => listen('event', vi.fn())).toThrow('Tauri listen not ready');
  });

  it('wires invoke and listen from window.__TAURI__', async () => {
    const coreInvoke = vi.fn(() => Promise.resolve('ok'));
    const eventListen = vi.fn(() => Promise.resolve(() => {}));
    window.__TAURI__ = {
      core: { invoke: coreInvoke },
      event: { listen: eventListen },
    };

    const { bootstrapTauri, invoke, listen } = await import('../api.js');

    await expect(bootstrapTauri()).resolves.toBe(true);
    await invoke('vpn_status', { a: 1 });
    await listen('vpn-status-update', vi.fn());

    expect(coreInvoke).toHaveBeenCalledWith('vpn_status', { a: 1 });
    expect(eventListen).toHaveBeenCalledWith('vpn-status-update', expect.any(Function));
  });

  it('returns false when Tauri never becomes available', async () => {
    vi.useFakeTimers();
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const { bootstrapTauri } = await import('../api.js');

    const result = bootstrapTauri();
    await vi.runAllTimersAsync();

    await expect(result).resolves.toBe(false);
    expect(error.mock.calls[0][0]).toContain('Tauri API not available');
    expect(error.mock.calls[0][0]).toContain('running in browser preview');
  });
});
