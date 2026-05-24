import { beforeEach, describe, expect, it, vi } from 'vitest';
import { state } from '../state.js';
import { invoke } from '../api.js';
import { applyTheme, savePrefs, wireThemeToggle } from '../theme.js';

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

  it('applies theme to the document and icon', () => {
    applyTheme('dark');

    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    expect(document.getElementById('theme-icon').innerHTML).toContain('path');
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
});
