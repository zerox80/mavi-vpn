export const state = {
  // UI state machine: 'off' | 'connecting' | 'disconnecting' | 'on'
  hero: 'off',
  disconnecting: false,
  // From vpn_status
  serviceAvailable: false,
  running: false,
  activeEndpoint: null,
  vpnState: 'Stopped',
  lastError: null,
  // Session wall clock
  sessionStart: null,
  // Saved UI prefs
  prefs: {
    theme: 'light',
    accent: '#2B44FF',
    connections: [],
    active_id: null,
    legacy_config_migrated: false,
  },
  // Search filter
  search: '',
};

export const $ = (id) => document.getElementById(id);
