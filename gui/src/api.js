// ============================================================================
// Tauri API bootstrap — the API is injected by withGlobalTauri, but can lag
// behind DOMContentLoaded on some builds.
// ============================================================================

let _invoke = null;
let _listen = null;

export const invoke = (cmd, args) => {
  if (!_invoke) throw new Error('Tauri invoke not ready');
  return _invoke(cmd, args);
};

export const listen = (event, handler) => {
  if (!_listen) throw new Error('Tauri listen not ready');
  return _listen(event, handler);
};

export async function bootstrapTauri() {
  let attempts = 0;
  while (
    (!window.__TAURI__ ||
      !window.__TAURI__.core?.invoke ||
      !window.__TAURI__.event?.listen) &&
    attempts < 20
  ) {
    await new Promise((r) => setTimeout(r, 50));
    attempts++;
  }

  if (window.__TAURI__?.core?.invoke && window.__TAURI__?.event?.listen) {
    _invoke = window.__TAURI__.core.invoke;
    _listen = window.__TAURI__.event.listen;
    return true;
  }

  console.error('Tauri API not available — running in browser preview');
  return false;
}
