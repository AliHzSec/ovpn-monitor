// api/websocket.ts — reconnecting WebSocket client for /ws, adapted from
// 3x-ui's websocket.ts but much simpler: a single channel carrying raw
// SystemStats JSON (the Go handler writes the same payload it serves on
// /api/server-stats — there is no message envelope).

import type { SystemStats } from '@/models/types';

const BASE_RECONNECT_MS = 2000;
const MAX_RECONNECT_MS = 30_000;

export interface StatsSocketCallbacks {
  onopen?: () => void;
  onmessage?: (stats: SystemStats) => void;
  onclose?: () => void;
}

export class StatsWebSocket {
  private ws: WebSocket | null = null;
  private shouldReconnect = false;
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private callbacks: StatsSocketCallbacks = {};

  connect(callbacks: StatsSocketCallbacks): void {
    this.callbacks = callbacks;
    this.shouldReconnect = true;
    this.openSocket();
  }

  disconnect(): void {
    this.shouldReconnect = false;
    this.callbacks = {};
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      try {
        this.ws.close(1000, 'client disconnect');
      } catch {}
      this.ws = null;
    }
  }

  private openSocket(): void {
    if (
      this.ws &&
      (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)
    ) {
      return;
    }
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const socket = new WebSocket(`${protocol}//${window.location.host}/ws`);
    this.ws = socket;

    socket.addEventListener('open', () => {
      if (this.ws !== socket) return;
      this.reconnectAttempts = 0;
      this.callbacks.onopen?.();
    });

    socket.addEventListener('message', (event) => {
      if (this.ws !== socket) return;
      try {
        const stats = JSON.parse(String(event.data)) as SystemStats;
        this.callbacks.onmessage?.(stats);
      } catch (err) {
        console.error('WebSocket: invalid stats payload', err);
      }
    });

    socket.addEventListener('close', () => {
      if (this.ws !== socket) return;
      this.ws = null;
      this.callbacks.onclose?.();
      if (this.shouldReconnect) this.scheduleReconnect();
    });
  }

  private scheduleReconnect(): void {
    if (!this.shouldReconnect) return;
    if (this.reconnectTimer !== null) clearTimeout(this.reconnectTimer);
    this.reconnectAttempts += 1;
    const exp = BASE_RECONNECT_MS * 2 ** (this.reconnectAttempts - 1);
    const delay = Math.min(MAX_RECONNECT_MS, exp) * (0.75 + Math.random() * 0.5);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      if (!this.shouldReconnect) return;
      this.openSocket();
    }, delay);
  }
}

let sharedSocket: StatsWebSocket | null = null;

export function getSharedStatsSocket(): StatsWebSocket {
  if (!sharedSocket) sharedSocket = new StatsWebSocket();
  return sharedSocket;
}
