import { state, $ } from './state.js';
import { bandwidthWalk } from './utils.js';

export function startCoreAnimation() {
  const svg = $('core');
  if (!svg) return;
  const size = 280;
  const R = size / 2;
  const accent = state.prefs.accent || '#2B44FF';
  const accentClean = accent.replace('#', '');

  const ns = 'http://www.w3.org/2000/svg';
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);

  // defs
  svg.innerHTML = `
    <defs>
      <radialGradient id="mcore-${accentClean}" cx="50%" cy="50%" r="50%">
        <stop offset="0%" stop-color="${accent}" stop-opacity="0.9" />
        <stop offset="60%" stop-color="${accent}" stop-opacity="0.35" />
        <stop offset="100%" stop-color="${accent}" stop-opacity="0" />
      </radialGradient>
      <radialGradient id="mhalo-${accentClean}" cx="50%" cy="50%" r="50%">
        <stop offset="0%" stop-color="${accent}" stop-opacity="0.25" />
        <stop offset="100%" stop-color="${accent}" stop-opacity="0" />
      </radialGradient>
      <filter id="mblur"><feGaussianBlur stdDeviation="8" /></filter>
    </defs>
  `;

  // Static-ish layers
  const halo = document.createElementNS(ns, 'circle');
  halo.setAttribute('cx', R);
  halo.setAttribute('cy', R);
  halo.setAttribute('fill', `url(#mhalo-${accentClean})`);
  svg.appendChild(halo);

  const ringFracs = [0.42, 0.56, 0.72, 0.88];
  const rings = ringFracs.map((f, i) => {
    const c = document.createElementNS(ns, 'circle');
    c.setAttribute('cx', R);
    c.setAttribute('cy', R);
    c.setAttribute('r', R * f);
    c.setAttribute('fill', 'none');
    c.setAttribute('stroke-width', i === 1 ? '1.5' : '1');
    if (i === 2) c.setAttribute('stroke-dasharray', '2 6');
    if (i === 3) c.setAttribute('stroke-dasharray', '1 5');
    svg.appendChild(c);
    return c;
  });

  // Radial ticks
  const tickGroup = document.createElementNS(ns, 'g');
  const ticks = [];
  for (let i = 0; i < 48; i++) {
    const ln = document.createElementNS(ns, 'line');
    ln.setAttribute('stroke', accent);
    ln.setAttribute('stroke-width', '1');
    tickGroup.appendChild(ln);
    ticks.push(ln);
  }
  svg.appendChild(tickGroup);

  // Core glow + solid + highlight
  const coreGlow = document.createElementNS(ns, 'circle');
  coreGlow.setAttribute('cx', R);
  coreGlow.setAttribute('cy', R);
  coreGlow.setAttribute('fill', `url(#mcore-${accentClean})`);
  coreGlow.setAttribute('filter', 'url(#mblur)');
  svg.appendChild(coreGlow);

  const coreSolid = document.createElementNS(ns, 'circle');
  coreSolid.setAttribute('cx', R);
  coreSolid.setAttribute('cy', R);
  svg.appendChild(coreSolid);

  const coreHighlight = document.createElementNS(ns, 'circle');
  coreHighlight.setAttribute('fill', 'white');
  svg.appendChild(coreHighlight);

  // Orbit dots
  const dots = [0, 1, 2, 3, 4].map((i) => {
    const c = document.createElementNS(ns, 'circle');
    c.setAttribute('r', i === 0 ? '4' : '2');
    c.setAttribute('fill', accent);
    svg.appendChild(c);
    return c;
  });

  const t0 = performance.now();
  function loop(now) {
    const t = (now - t0) / 1000;
    const breathe = 0.5 + 0.5 * Math.sin(t * 0.9);
    const pulse = 0.5 + 0.5 * Math.sin(t * 2.4);
    const off = state.hero === 'off';
    const connecting = state.hero === 'connecting';
    const rot = (t * (connecting ? 60 : 18)) % 360;

    const themeIsDark = state.prefs.theme === 'dark';
    const offRing = themeIsDark ? 'rgba(255,255,255,0.07)' : 'rgba(0,0,0,0.08)';
    const ringColor = off ? offRing : accent;

    rings.forEach((c, i) => {
      c.setAttribute('stroke', ringColor);
      const op = off ? 0.6 : 0.18 + 0.12 * (1 - i / rings.length) + 0.08 * pulse;
      c.setAttribute('opacity', op.toFixed(3));
    });

    // ticks — hidden when off
    for (let i = 0; i < ticks.length; i++) {
      if (off) {
        ticks[i].setAttribute('opacity', '0');
        continue;
      }
      const a = (((i * 360) / 48) * Math.PI) / 180;
      const r1 = R * 0.91;
      const r2 = R * (0.94 + 0.02 * Math.sin(t * 2 + i));
      ticks[i].setAttribute('x1', (R + Math.cos(a) * r1).toFixed(2));
      ticks[i].setAttribute('y1', (R + Math.sin(a) * r1).toFixed(2));
      ticks[i].setAttribute('x2', (R + Math.cos(a) * r2).toFixed(2));
      ticks[i].setAttribute('y2', (R + Math.sin(a) * r2).toFixed(2));
      const op = 0.15 + 0.35 * ((Math.sin(t * 1.5 + i * 0.4) + 1) / 2);
      ticks[i].setAttribute('opacity', op.toFixed(3));
    }

    // core
    const coreR = R * 0.28 + (off ? 0 : 6 * breathe);
    coreGlow.setAttribute('r', coreR + 20);
    coreGlow.setAttribute('opacity', off ? '0' : '1');
    const coreOffColor =
      getComputedStyle(document.documentElement).getPropertyValue('--core-off').trim() || '#E8E3D3';
    coreSolid.setAttribute('r', coreR);
    coreSolid.setAttribute('fill', off ? coreOffColor : accent);

    if (off) {
      coreHighlight.setAttribute('opacity', '0');
    } else {
      const hr = coreR * 0.5;
      coreHighlight.setAttribute('cx', R - coreR * 0.3);
      coreHighlight.setAttribute('cy', R - coreR * 0.3);
      coreHighlight.setAttribute('r', hr);
      coreHighlight.setAttribute('opacity', (0.18 + 0.1 * breathe).toFixed(3));
    }

    // orbit dots
    const orbitR = R * 0.56;
    dots.forEach((d, i) => {
      if (off) {
        d.setAttribute('opacity', '0');
        return;
      }
      const a = ((rot + i * 72) * Math.PI) / 180;
      d.setAttribute('cx', (R + Math.cos(a) * orbitR).toFixed(2));
      d.setAttribute('cy', (R + Math.sin(a) * orbitR).toFixed(2));
      const op = i === 0 ? 1 : 0.4 + 0.3 * Math.sin(t * 2 + i);
      d.setAttribute('opacity', op.toFixed(3));
    });

    requestAnimationFrame(loop);
  }
  requestAnimationFrame(loop);
}

export function renderSparkline() {
  const svg = $('sparkline');
  if (!svg) return;
  const W = 200,
    H = 28;
  const values = bandwidthWalk(60);
  const max = Math.max(...values);
  const points = values
    .map((v, i) => {
      const x = (i / (values.length - 1)) * W;
      const y = H - (v / max) * H * 0.9 - 2;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');
  svg.innerHTML = `
    <polyline id="spark-line" points="${points}" fill="none" stroke-width="1.2" />
    <polygon  id="spark-fill" points="0,${H} ${points} ${W},${H}" />
  `;
  updateSparklineColors();
}

export function updateSparklineColors() {
  const line = document.getElementById('spark-line');
  const fill = document.getElementById('spark-fill');
  if (!line || !fill) return;
  const style = getComputedStyle(document.documentElement);
  const off = state.hero !== 'on';
  const accent = state.prefs.accent || style.getPropertyValue('--accent').trim() || '#2B44FF';
  const lineColor = off ? style.getPropertyValue('--line').trim() : accent;
  line.setAttribute('stroke', lineColor);
  fill.setAttribute('fill', accent);
  fill.setAttribute('opacity', off ? '0' : '0.08');
}

export function startStatsAnimation() {
  let tick = 0;
  setInterval(() => {
    if (state.hero === 'on') {
      tick++;
      $('stat-down').textContent = (42 + (tick % 7) * 3.1).toFixed(1);
      $('stat-up').textContent = (11 + (tick % 5) * 1.4).toFixed(1);
    } else {
      $('stat-down').textContent = '0.0';
      $('stat-up').textContent = '0.0';
      $('ip-readout').textContent = '—';
    }
    const netIp = $('net-ip');
    if (netIp) netIp.textContent = $('ip-readout').textContent;
  }, 800);
}

export function startSessionClock() {
  setInterval(() => {
    let s = '00:00:00';
    if (state.sessionStart && state.hero === 'on') {
      const diff = Math.floor((Date.now() - state.sessionStart) / 1000);
      const h = String(Math.floor(diff / 3600)).padStart(2, '0');
      const m = String(Math.floor((diff % 3600) / 60)).padStart(2, '0');
      const sec = String(diff % 60).padStart(2, '0');
      s = `${h}:${m}:${sec}`;
    }
    const heroSession = $('hero-session');
    if (heroSession) heroSession.textContent = s;
    const netSession = $('net-session');
    if (netSession) netSession.textContent = s;
  }, 1000);
}
