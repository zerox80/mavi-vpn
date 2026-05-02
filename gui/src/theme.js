import { state, $ } from './state.js';
import { invoke } from './api.js';

export function wireThemeToggle() {
  $('theme-toggle').addEventListener('click', async () => {
    const next = state.prefs.theme === 'light' ? 'dark' : 'light';
    state.prefs.theme = next;
    applyTheme(next);
    await savePrefs();
  });
}

export function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const icon = $('theme-icon');
  if (!icon) return;
  if (theme === 'dark') {
    icon.innerHTML = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />';
  } else {
    icon.innerHTML =
      '<circle cx="12" cy="12" r="4" />' +
      '<path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />';
  }
}

export async function savePrefs() {
  try {
    await invoke('save_prefs', { prefs: state.prefs });
  } catch (e) {
    console.warn('save_prefs failed:', e);
  }
}

export function normalizePrefs(prefs = {}) {
  return {
    theme: prefs.theme || 'light',
    accent: prefs.accent || '#2B44FF',
    connections: Array.isArray(prefs.connections) ? prefs.connections : [],
    active_id: prefs.active_id ?? null,
    legacy_config_migrated: !!prefs.legacy_config_migrated,
  };
}
