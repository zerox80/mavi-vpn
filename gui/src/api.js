import { invoke as tauriInvoke } from '@tauri-apps/api/core';
import { listen as tauriListen } from '@tauri-apps/api/event';

export const invoke = (cmd, args) => {
  return tauriInvoke(cmd, args);
};

export const listen = (event, handler) => {
  return tauriListen(event, handler);
};

export async function bootstrapTauri() {
  return true;
}
