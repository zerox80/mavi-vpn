import { state, $ } from './state.js';
import { bootstrapTauri, invoke, listen } from './api.js';
import {
  wireThemeToggle,
  applyTheme,
  normalizePrefs,
} from './theme.js';
import {
  wireSidebarSearch,
  renderConnectionList,
  migrateLegacyConfig,
} from './connections.js';
import { wireModal, openModal } from './modal.js';
import {
  wireHero,
  refreshStatus,
  applyStatus,
  toggleConnection,
  applyHeroForSelection,
} from './vpn.js';
import {
  startCoreAnimation,
  renderSparkline,
  startStatsAnimation,
  startSessionClock,
  updateSparklineColors,
} from './animations.js';

// ============================================================================
// Init
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  await bootstrapTauri();

  wireTabs();
  wireSidebarSearch({ openModal, applyHeroForSelection });
  wireModal({ applyHeroForSelection });
  wireHero();
  wireThemeToggle();
  wireShortcuts();

  // Load UI prefs (connections, theme) — tolerate missing backend
  try {
    const prefs = await invoke('load_prefs');
    if (prefs) state.prefs = normalizePrefs(prefs);
  } catch (e) {
    console.warn('load_prefs failed:', e);
  }

  // One-time migration from the old editable runtime config into saved connections.
  try {
    const config = await invoke('load_config');
    await migrateLegacyConfig(config);
  } catch (e) {
    console.warn('legacy config migration skipped:', e);
  }

  applyTheme(state.prefs.theme);
  renderConnectionList();

  startCoreAnimation();
  renderSparkline();
  startStatsAnimation();
  startSessionClock();

  await refreshStatus();

  try {
    await listen('vpn-status-update', (e) => applyStatus(e.payload));
    await listen('tray-toggle', () => toggleConnection());
  } catch (e) {
    console.warn('event wiring failed:', e);
  }
});

// ============================================================================
// Tabs & Shortcuts (Kept in main for simplicity)
// ============================================================================

function wireTabs() {
  document.querySelectorAll('.tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      const name = btn.dataset.tab;
      document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t === btn));
      document
        .querySelectorAll('.tab-panel')
        .forEach((p) => p.classList.toggle('active', p.dataset.panel === name));
    });
  });
}

function wireShortcuts() {
  document.addEventListener('keydown', (e) => {
    const mod = e.metaKey || e.ctrlKey;
    if (mod && (e.key === 'k' || e.key === 'K')) {
      e.preventDefault();
      // Ensure CONNECT tab is active then focus search
      const connectTab = document.querySelector('.tab[data-tab="connect"]');
      if (connectTab) connectTab.click();
      const searchInput = $('search');
      if (searchInput) {
        searchInput.focus();
        searchInput.select();
      }
    }
    if (e.key === 'Escape') {
      const modal = $('modal-backdrop');
      if (modal && modal.classList.contains('visible')) {
        // We need to import closeModal or just click the cancel button
        const cancelBtn = $('modal-cancel');
        if (cancelBtn) cancelBtn.click();
      }
    }
  });
}

// Re-tint sparkline when state changes — hook into setHero via MutationObserver
new MutationObserver(updateSparklineColors).observe(document.documentElement, {
  attributes: true,
  attributeFilter: ['data-state', 'data-theme'],
});
