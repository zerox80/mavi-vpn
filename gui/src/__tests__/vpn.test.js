import { describe, it, expect, beforeEach, vi } from 'vitest';
import { applyStatus } from '../vpn.js';
import { state } from '../state.js';

// Mocking the $ function from state.js is tricky because it's exported.
// But vpn.js imports it.
// We can use vi.mock or just define the DOM elements.

describe('applyStatus', () => {
  beforeEach(() => {
    // Reset state
    state.serviceAvailable = false;
    state.running = false;
    state.hero = 'off';
    state.disconnecting = false;
    state.prefs.active_id = 'test-id';
    state.prefs.connections = [{ id: 'test-id', label: 'Test Node', endpoint: 'test:443' }];

    // Setup DOM
    document.body.innerHTML = `
      <button id="connect-btn"></button>
      <div id="ip-readout"></div>
      <div id="hero-title"></div>
      <div id="hero-subtitle"></div>
      <div id="hero-node-id"></div>
      <div id="hero-lat"></div>
      <div id="title-state-label"></div>
      <div id="hero-status"></div>
      <div id="core-label"></div>
      <div id="net-node"></div>
      <div id="net-endpoint"></div>
      <div id="net-ip"></div>
      <div id="net-service"></div>
      <div id="toast"></div>
    `;
  });

  it('disables button when service is offline', () => {
    applyStatus({ service_available: false });
    expect(state.serviceAvailable).toBe(false);
    expect(document.getElementById('connect-btn').disabled).toBe(true);
    expect(document.getElementById('net-service').textContent).toBe('OFFLINE');
  });

  it('enables button when service is online and stopped', () => {
    applyStatus({ service_available: true, running: false, state: 'Stopped' });
    expect(state.serviceAvailable).toBe(true);
    expect(document.getElementById('connect-btn').disabled).toBe(false);
    expect(document.getElementById('connect-btn').textContent).toBe('CONNECT');
  });

  it('sets hero to on when connected', () => {
    applyStatus({ service_available: true, running: true, state: 'Connected', assigned_ip: '10.8.0.2' });
    expect(state.hero).toBe('on');
    expect(document.getElementById('connect-btn').textContent).toBe('DISCONNECT');
    expect(document.getElementById('ip-readout').textContent).toBe('10.8.0.2');
  });

  it('clears session and shows error on Failed state', () => {
    state.sessionStart = 12345;
    applyStatus({ service_available: true, state: 'Failed', last_error: 'Auth failed' });
    expect(state.hero).toBe('off');
    expect(state.sessionStart).toBeNull();
    expect(document.getElementById('toast').textContent).toBe('Auth failed');
  });

  it('handles missing active connection by disabling connect', () => {
    state.prefs.active_id = 'missing';
    state.prefs.connections = [];

    applyStatus({ service_available: true, running: false, state: 'Stopped' });

    expect(document.getElementById('connect-btn').disabled).toBe(true);
    expect(document.getElementById('connect-btn').title).toBe('Select or add a saved connection first');
    expect(document.getElementById('hero-title').textContent).toBe('No node selected');
  });

  it('service offline clears disconnecting state', () => {
    state.disconnecting = true;
    state.hero = 'disconnecting';

    applyStatus({ service_available: false, running: false, state: 'Stopping' });

    expect(state.disconnecting).toBe(false);
    expect(state.hero).toBe('off');
    expect(document.getElementById('connect-btn').disabled).toBe(true);
  });

  it('failed state without last_error leaves toast untouched', () => {
    const toast = document.getElementById('toast');
    toast.textContent = '';

    applyStatus({ service_available: true, state: 'Failed' });

    expect(state.lastError).toBeNull();
    expect(toast.textContent).toBe('');
  });
});
