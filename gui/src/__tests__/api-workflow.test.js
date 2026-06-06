import { beforeEach, describe, expect, it, vi } from 'vitest';

describe('Tauri API bootstrap', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it('wires invoke and listen from bundled Tauri API imports', async () => {
    const coreInvoke = vi.fn(() => Promise.resolve('ok'));
    const eventListen = vi.fn(() => Promise.resolve(() => {}));
    vi.doMock('@tauri-apps/api/core', () => ({ invoke: coreInvoke }));
    vi.doMock('@tauri-apps/api/event', () => ({ listen: eventListen }));

    const { bootstrapTauri, invoke, listen } = await import('../api.js');

    await expect(bootstrapTauri()).resolves.toBe(true);
    await invoke('vpn_status', { a: 1 });
    await listen('vpn-status-update', vi.fn());

    expect(coreInvoke).toHaveBeenCalledWith('vpn_status', { a: 1 });
    expect(eventListen).toHaveBeenCalledWith('vpn-status-update', expect.any(Function));
  });
});
