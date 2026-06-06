import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { state } from '../state.js';
import { invoke } from '../api.js';
import { applyTheme, normalizePrefs, savePrefs, wireThemeToggle } from '../theme.js';

vi.mock('../api.js', () => ({
  invoke: vi.fn(() => Promise.resolve()),
}));

describe('theme workflows', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    document.body.innerHTML = `
      <button id="theme-toggle"></button>
      <svg id="theme-icon"></svg>
    `;
    state.prefs.theme = 'light';
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('applies theme to the document and icon', () => {
    applyTheme('dark');

    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    expect(document.getElementById('theme-icon').innerHTML).toContain('path');
  });

  it('renders the light icon and tolerates a missing icon', () => {
    applyTheme('light');

    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    expect(document.getElementById('theme-icon').innerHTML).toContain('circle');

    document.getElementById('theme-icon').remove();
    expect(() => applyTheme('dark')).not.toThrow();

    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
  });

  it('persists prefs through Tauri invoke', async () => {
    await savePrefs();

    expect(invoke).toHaveBeenCalledWith('save_prefs', { prefs: state.prefs });
  });

  it('theme toggle flips and persists the theme', async () => {
    wireThemeToggle();

    document.getElementById('theme-toggle').click();
    await Promise.resolve();

    expect(state.prefs.theme).toBe('dark');
    expect(invoke).toHaveBeenCalledWith('save_prefs', { prefs: state.prefs });
  });

  it('logs failed preference saves without throwing', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    invoke.mockRejectedValueOnce(new Error('offline'));

    await expect(savePrefs()).resolves.toBeUndefined();

    expect(warn).toHaveBeenCalledWith('save_prefs failed:', expect.any(Error));
  });

  it('normalizes missing and malformed prefs', () => {
    expect(normalizePrefs()).toEqual({
      theme: 'light',
      accent: '#2B44FF',
      connections: [],
      active_id: null,
      legacy_config_migrated: false,
    });
    expect(
      normalizePrefs({
        theme: 'dark',
        accent: '#ff00aa',
        connections: 'nope',
        active_id: 0,
        legacy_config_migrated: 1,
      })
    ).toMatchObject({
      theme: 'dark',
      accent: '#ff00aa',
      connections: [],
      active_id: 0,
      legacy_config_migrated: true,
    });
  });
});
