import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { state } from '../state.js';
import {
  startCoreAnimation,
  renderSparkline,
  updateSparklineColors,
  startStatsAnimation,
  startSessionClock,
} from '../animations.js';

describe('animations.js unit tests', () => {
  let rafCallback = null;
  let performanceNowValue = 0;

  beforeEach(() => {
    vi.useFakeTimers();

    // Stub requestAnimationFrame
    rafCallback = null;
    vi.spyOn(window, 'requestAnimationFrame').mockImplementation((cb) => {
      rafCallback = cb;
      return 1;
    });

    // Stub performance.now
    performanceNowValue = 0;
    vi.spyOn(performance, 'now').mockImplementation(() => performanceNowValue);

    // Stub getComputedStyle
    vi.spyOn(window, 'getComputedStyle').mockImplementation(() => {
      return {
        getPropertyValue: (prop) => {
          if (prop === '--core-off') return '#E8E3D3';
          if (prop === '--accent') return '#2B44FF';
          if (prop === '--line') return '#cccccc';
          return '';
        },
      };
    });

    // Reset default state
    state.hero = 'off';
    state.prefs.accent = '#2B44FF';
    state.prefs.theme = 'light';
    state.sessionStart = null;

    // Reset DOM
    document.body.innerHTML = '';
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('startCoreAnimation', () => {
    it('does nothing if core element is missing', () => {
      expect(() => startCoreAnimation()).not.toThrow();
      expect(rafCallback).toBeNull();
    });

    it('initializes SVG structure and attributes', () => {
      const core = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      core.id = 'core';
      document.body.appendChild(core);

      startCoreAnimation();

      expect(core.getAttribute('width')).toBe('280');
      expect(core.getAttribute('height')).toBe('280');
      expect(core.querySelector('defs')).not.toBeNull();
      expect(core.querySelector('radialGradient')).not.toBeNull();
      expect(core.querySelector('filter')).not.toBeNull();

      // Check circles
      const circles = core.querySelectorAll('circle');
      // halo (1), rings (4), coreGlow (1), coreSolid (1), coreHighlight (1), orbit dots (5) = 13 circles
      expect(circles).toHaveLength(13);

      // Check lines (48 ticks)
      const lines = core.querySelectorAll('line');
      expect(lines).toHaveLength(48);
    });

    it('animates elements through raf loop when state is off', () => {
      const core = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      core.id = 'core';
      document.body.appendChild(core);

      startCoreAnimation();
      expect(rafCallback).toBeTypeOf('function');

      // Run one loop tick with state = off
      state.hero = 'off';
      performanceNowValue = 1000;
      rafCallback(1000);

      // Verify that ticks and orbit dots are hidden (opacity = 0)
      const lines = core.querySelectorAll('line');
      lines.forEach((line) => {
        expect(line.getAttribute('opacity')).toBe('0');
      });

      const circles = core.querySelectorAll('circle');
      // Core highlight should also be hidden (opacity = 0)
      // Core highlight is the 8th circle in DOM creation order:
      // circles[0] = halo
      // circles[1-4] = rings
      // circles[5] = coreGlow
      // circles[6] = coreSolid
      // circles[7] = coreHighlight
      // circles[8-12] = orbit dots
      const coreHighlight = circles[7];
      expect(coreHighlight.getAttribute('opacity')).toBe('0');

      // Rings should have offRing styling
      const ring = circles[1];
      expect(ring.getAttribute('stroke')).toBe('rgba(0,0,0,0.08)'); // light theme offRing
    });

    it('uses dark theme offRing when state is off and theme is dark', () => {
      const core = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      core.id = 'core';
      document.body.appendChild(core);

      state.prefs.theme = 'dark';
      startCoreAnimation();

      performanceNowValue = 1000;
      rafCallback(1000);

      const circles = core.querySelectorAll('circle');
      const ring = circles[1];
      expect(ring.getAttribute('stroke')).toBe('rgba(255,255,255,0.07)'); // dark theme offRing
    });

    it('animates elements through raf loop when state is on', () => {
      const core = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      core.id = 'core';
      document.body.appendChild(core);

      startCoreAnimation();

      state.hero = 'on';
      performanceNowValue = 2000;
      rafCallback(2000);

      const lines = core.querySelectorAll('line');
      // Ticks should be visible (opacity > 0)
      expect(parseFloat(lines[0].getAttribute('opacity'))).toBeGreaterThan(0);
      expect(lines[0].getAttribute('x1')).not.toBeNull();

      const circles = core.querySelectorAll('circle');
      // Core highlight should be visible
      const coreHighlight = circles[7];
      expect(parseFloat(coreHighlight.getAttribute('opacity'))).toBeGreaterThan(0);

      // Rings should have accent color
      const ring = circles[1];
      expect(ring.getAttribute('stroke')).toBe('#2B44FF');

      // Orbit dots should be animated and positioned
      const dot = circles[8];
      expect(parseFloat(dot.getAttribute('opacity'))).toBeGreaterThan(0);
      expect(dot.getAttribute('cx')).not.toBeNull();
    });

    it('uses faster rotation when state is connecting', () => {
      const core = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      core.id = 'core';
      document.body.appendChild(core);

      startCoreAnimation();

      state.hero = 'connecting';
      performanceNowValue = 1000;
      rafCallback(1000);

      const circles = core.querySelectorAll('circle');
      // Just assert they are rendered and updated without crash
      const dot = circles[8];
      expect(dot.getAttribute('cx')).not.toBeNull();
    });
  });

  describe('renderSparkline and updateSparklineColors', () => {
    it('does nothing if sparkline element is missing', () => {
      expect(() => renderSparkline()).not.toThrow();
    });

    it('renders sparkline SVG contents and sets colors when state.hero is on', () => {
      const sparkline = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      sparkline.id = 'sparkline';
      document.body.appendChild(sparkline);

      state.hero = 'on';
      renderSparkline();

      const line = document.getElementById('spark-line');
      const fill = document.getElementById('spark-fill');

      expect(line).not.toBeNull();
      expect(fill).not.toBeNull();
      expect(line.getAttribute('points')).not.toBeNull();
      expect(line.getAttribute('stroke')).toBe('#2B44FF');
      expect(fill.getAttribute('fill')).toBe('#2B44FF');
      expect(fill.getAttribute('opacity')).toBe('0.08');
    });

    it('sets off colors when state.hero is off', () => {
      const sparkline = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      sparkline.id = 'sparkline';
      document.body.appendChild(sparkline);

      state.hero = 'off';
      renderSparkline();

      const line = document.getElementById('spark-line');
      const fill = document.getElementById('spark-fill');

      expect(line.getAttribute('stroke')).toBe('#cccccc'); // from mocked --line
      expect(fill.getAttribute('opacity')).toBe('0');
    });

    it('updateSparklineColors returns early if elements are missing', () => {
      expect(() => updateSparklineColors()).not.toThrow();
    });
  });

  describe('startStatsAnimation', () => {
    it('updates stats elements on interval when state.hero is on', () => {
      const down = document.createElement('div');
      down.id = 'stat-down';
      const up = document.createElement('div');
      up.id = 'stat-up';
      const ip = document.createElement('div');
      ip.id = 'ip-readout';
      const netIp = document.createElement('div');
      netIp.id = 'net-ip';

      document.body.appendChild(down);
      document.body.appendChild(up);
      document.body.appendChild(ip);
      document.body.appendChild(netIp);

      startStatsAnimation();

      state.hero = 'on';
      ip.textContent = '192.168.1.100';

      // Advance one interval (800ms)
      vi.advanceTimersByTime(800);

      expect(down.textContent).not.toBe('0.0');
      expect(up.textContent).not.toBe('0.0');
      expect(netIp.textContent).toBe('192.168.1.100');
    });

    it('resets stats elements on interval when state.hero is off', () => {
      const down = document.createElement('div');
      down.id = 'stat-down';
      const up = document.createElement('div');
      up.id = 'stat-up';
      const ip = document.createElement('div');
      ip.id = 'ip-readout';

      document.body.appendChild(down);
      document.body.appendChild(up);
      document.body.appendChild(ip);

      startStatsAnimation();

      state.hero = 'off';
      down.textContent = '12.3';
      up.textContent = '4.5';
      ip.textContent = '192.168.1.100';

      // Advance one interval (800ms)
      vi.advanceTimersByTime(800);

      expect(down.textContent).toBe('0.0');
      expect(up.textContent).toBe('0.0');
      expect(ip.textContent).toBe('—');
    });
  });

  describe('startSessionClock', () => {
    it('updates clock elements on interval when state.hero is on and sessionStart exists', () => {
      const heroSession = document.createElement('div');
      heroSession.id = 'hero-session';
      const netSession = document.createElement('div');
      netSession.id = 'net-session';

      document.body.appendChild(heroSession);
      document.body.appendChild(netSession);

      startSessionClock();

      state.hero = 'on';
      const now = Date.now();
      state.sessionStart = now - 5000; // 5 seconds ago

      // Advance one interval (1000ms)
      // Since Date.now() in fake timers will advance by 1000ms as well
      vi.advanceTimersByTime(1000);

      // 5 seconds + 1 second advanced = 6 seconds
      expect(heroSession.textContent).toBe('00:00:06');
      expect(netSession.textContent).toBe('00:00:06');
    });

    it('resets clock elements to 00:00:00 when state.hero is off', () => {
      const heroSession = document.createElement('div');
      heroSession.id = 'hero-session';
      const netSession = document.createElement('div');
      netSession.id = 'net-session';

      document.body.appendChild(heroSession);
      document.body.appendChild(netSession);

      startSessionClock();

      state.hero = 'off';
      heroSession.textContent = '12:34:56';
      netSession.textContent = '12:34:56';

      vi.advanceTimersByTime(1000);

      expect(heroSession.textContent).toBe('00:00:00');
      expect(netSession.textContent).toBe('00:00:00');
    });
  });
});
